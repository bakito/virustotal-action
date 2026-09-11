package action

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bakito/virustotal-action/pkg/archive"
	"github.com/bakito/virustotal-action/pkg/badges"
	"github.com/bakito/virustotal-action/pkg/github"
	"github.com/bakito/virustotal-action/pkg/types"
	"github.com/bakito/virustotal-action/pkg/vt"
)

// Runner coordinates the VirusTotal Action workflow.
type Runner struct {
	GHClient github.Client
	VTClient vt.Client
}

// Run executes the complete action workflow.
func (r *Runner) Run(ctx context.Context, cfg *types.Config) error {
	if cfg.ReleaseName == "" {
		fmt.Fprintln(os.Stderr, "Error: 'release_name' input is required but not provided.")
		return errors.New("'release_name' input is required but not provided")
	}
	if cfg.VTApiKey == "" {
		fmt.Fprintln(os.Stderr, "Error: 'vt_api_key' input is required but not provided.")
		return errors.New("'vt_api_key' input is required but not provided")
	}

	owner, repo, found := strings.Cut(cfg.GitHubRepository, "/")
	if !found || owner == "" || repo == "" {
		return fmt.Errorf("invalid repository %q, expected 'owner/repo'", cfg.GitHubRepository)
	}

	ghClient := r.GHClient
	if ghClient == nil {
		ghClient = github.NewClient(cfg.GitHubToken)
	}

	vtClient := r.VTClient
	if vtClient == nil {
		vtClient = vt.NewClient(cfg.VTApiKey)
	}

	assetsDir := cfg.AssetsDir
	extractedDir := cfg.ExtractedDir

	if assetsDir == "" {
		tempAssets, err := os.MkdirTemp("", "vt-assets-*")
		if err != nil {
			return fmt.Errorf("failed to create assets temp dir: %w", err)
		}
		defer os.RemoveAll(tempAssets)
		assetsDir = tempAssets
	}

	if extractedDir == "" {
		tempExtracted, err := os.MkdirTemp("", "vt-extracted-*")
		if err != nil {
			return fmt.Errorf("failed to create extracted temp dir: %w", err)
		}
		defer os.RemoveAll(tempExtracted)
		extractedDir = tempExtracted
	}

	// 1. Fetch release info from GitHub
	release, err := ghClient.GetRelease(ctx, owner, repo, cfg.ReleaseName)
	if err != nil {
		return fmt.Errorf("failed to get release: %w", err)
	}

	// 2. Download release assets
	_, err = ghClient.DownloadReleaseAssets(ctx, owner, repo, release, cfg.DownloadReleaseArtifactPattern, assetsDir)
	if err != nil {
		return fmt.Errorf("failed to download release assets: %w", err)
	}

	// 3. Extract archives
	if err := archive.ExtractAll(assetsDir, extractedDir); err != nil {
		return fmt.Errorf("failed to extract archives: %w", err)
	}

	// 4. Find binary targets
	targets, err := archive.FindBinaryTargets(assetsDir, extractedDir, cfg.BinaryPattern)
	if err != nil {
		return fmt.Errorf("failed to find binary targets: %w", err)
	}

	// 5. Scan files on VirusTotal
	archiveScans := make(map[string]string)
	var scannedItems []types.ScannedItem

	for _, target := range targets {
		scanIDArchive, alreadyScanned := archiveScans[target.ArchiveName]
		if alreadyScanned {
			fmt.Fprintf(os.Stderr, "  archive %s already scanned: %s\n", target.ArchiveName, scanIDArchive)
		} else {
			id, err := vtClient.ScanFile(target.ArchiveFile)
			if err != nil {
				return err
			}
			scanIDArchive = id
			archiveScans[target.ArchiveName] = scanIDArchive
			time.Sleep(1 * time.Second)
		}

		scanIDExe, err := vtClient.ScanFile(target.ExeFile)
		if err != nil {
			return err
		}
		time.Sleep(1 * time.Second)

		scannedItems = append(scannedItems, types.ScannedItem{
			ArchiveName:   target.ArchiveName,
			ExeName:       target.ExeName,
			ScanIDArchive: scanIDArchive,
			ScanIDExe:     scanIDExe,
		})

		fmt.Fprintf(os.Stderr, "  archive : https://www.virustotal.com/gui/file-analysis/%s/detection\n", scanIDArchive)
		fmt.Fprintf(os.Stderr, "  exe     : https://www.virustotal.com/gui/file-analysis/%s/detection\n", scanIDExe)
	}

	// 6. Poll VirusTotal for completed results
	allChecksSuccessful := true
	checksCount := 0
	var rows []badges.ResultRow

	for _, item := range scannedItems {
		outArchive, err := vtClient.PollScan(ctx, item.ScanIDArchive, item.ArchiveName, cfg.PollMaxAttempts, cfg.PollInterval)
		if err != nil {
			return err
		}
		outExe, err := vtClient.PollScan(ctx, item.ScanIDExe, item.ExeName, cfg.PollMaxAttempts, cfg.PollInterval)
		if err != nil {
			return err
		}

		badgeArchive := badges.MakeBadge(item.ScanIDArchive, item.ArchiveName, outArchive)
		badgeExe := badges.MakeBadge(item.ScanIDExe, item.ExeName, outExe)

		checksCount += 2
		if !outArchive.IsSuccess() || !outExe.IsSuccess() {
			allChecksSuccessful = false
		}

		lastScan := "-"
		if outExe != nil && outExe.Date > 0 {
			lastScan = badges.MakeDateBadge(outExe.Date, item.ScanIDExe)
		} else if outArchive != nil && outArchive.Date > 0 {
			lastScan = badges.MakeDateBadge(outArchive.Date, item.ScanIDArchive)
		}

		rows = append(rows, badges.ResultRow{
			ArchiveName:  item.ArchiveName,
			BadgeArchive: badgeArchive,
			BadgeExe:     badgeExe,
			LastScan:     lastScan,
		})
	}

	if checksCount == 0 {
		allChecksSuccessful = false
	}

	// 7. Update GitHub Release Info
	reportTable := badges.GenerateReportTable(rows)
	updatedNotes := badges.CombineReleaseNotes(release.GetBody(), reportTable)

	isPrerelease := release.GetPrerelease()
	updateToLatest := cfg.UpdateToLatest && isPrerelease && allChecksSuccessful
	if updateToLatest {
		fmt.Fprintln(os.Stderr, "All checks successful on pre-release; updating release to latest.")
	}

	err = ghClient.UpdateReleaseNotes(ctx, owner, repo, release.GetID(), updatedNotes, updateToLatest)
	if err != nil {
		return fmt.Errorf("failed to update release notes: %w", err)
	}

	return nil
}
