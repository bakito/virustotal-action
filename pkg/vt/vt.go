package vt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	vt "github.com/VirusTotal/vt-go"

	"github.com/bakito/virustotal-action/pkg/types"
)

// Client defines the interface for interacting with VirusTotal.
type Client interface {
	ScanFile(filePath string) (string, error)
	PollScan(ctx context.Context, scanID, label string, maxAttempts int, pollInterval time.Duration) (*types.ScanResult, error)
}

type vtClient struct {
	cli *vt.Client
}

// NewClient creates a new VirusTotal client with the given API key and options.
func NewClient(apiKey string, opts ...vt.ClientOption) Client {
	return &vtClient{
		cli: vt.NewClient(apiKey, opts...),
	}
}

func fileSHA256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func isAlreadySubmittedError(err error) bool {
	if err == nil {
		return false
	}
	if vtErr, ok := errors.AsType[vt.Error](err); ok {
		if strings.EqualFold(vtErr.Code, "AlreadyExistsError") ||
			strings.Contains(strings.ToLower(vtErr.Message), "already being submitted") ||
			strings.Contains(strings.ToLower(vtErr.Message), "already exists") ||
			strings.Contains(strings.ToLower(vtErr.Message), "already being scanned") {
			return true
		}
	}
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "already being submitted") ||
		strings.Contains(errMsg, "alreadyexists") ||
		strings.Contains(errMsg, "already exists") ||
		strings.Contains(errMsg, "already being scanned")
}

func (c *vtClient) getPreviousScanID(hash string) (string, error) {
	var analyses []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	}

	if _, err := c.cli.GetData(vt.URL("files/%s/analyses", hash), &analyses); err == nil && len(analyses) > 0 {
		if analyses[0].ID != "" {
			return analyses[0].ID, nil
		}
	}

	obj, err := c.cli.GetObject(vt.URL("files/%s", hash))
	if err == nil && obj != nil && obj.ID() != "" {
		return obj.ID(), nil
	}

	return "", fmt.Errorf("no previous scan found for hash %s", hash)
}

// ScanFile uploads and scans a file on VirusTotal, returning its scan ID.
func (c *vtClient) ScanFile(filePath string) (string, error) {
	fmt.Fprintf(os.Stderr, "🔎 Scanning %s\n", filePath)
	f, err := os.Open(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error: Failed to open %s.\n", filePath)
		return "", fmt.Errorf("failed to open %s: %w", filePath, err)
	}
	defer f.Close()

	scanner := c.cli.NewFileScanner()
	obj, err := scanner.Scan(f, filepath.Base(filePath), nil)
	if err != nil {
		if isAlreadySubmittedError(err) {
			if hash, hashErr := fileSHA256(filePath); hashErr == nil && hash != "" {
				if prevScanID, prevErr := c.getPreviousScanID(hash); prevErr == nil && prevScanID != "" {
					fmt.Fprintf(
						os.Stderr,
						"  file %s is already submitted for scanning, using previous scan ID: %s\n",
						filePath,
						prevScanID,
					)
					return prevScanID, nil
				}
			}
		}
		fmt.Fprintf(os.Stderr, "❌ Error: Failed to get scan ID for %s.\n", filePath)
		return "", fmt.Errorf("failed to scan %s: %w", filePath, err)
	}

	scanID := obj.ID()
	if scanID == "" {
		fmt.Fprintf(os.Stderr, "❌ Error: Failed to get scan ID for %s.\n", filePath)
		return "", fmt.Errorf("empty scan ID for %s", filePath)
	}

	return scanID, nil
}

// PollScan polls VirusTotal for completed analysis results.
func (c *vtClient) PollScan(
	ctx context.Context,
	scanID, label string,
	maxAttempts int,
	pollInterval time.Duration,
) (*types.ScanResult, error) {
	if scanID == "" || scanID == "null" {
		fmt.Fprintf(os.Stderr, "❌ Error: scan_id is empty for %s\n", label)
		return &types.ScanResult{ScanID: scanID, TimedOut: true}, nil
	}

	fmt.Fprintf(os.Stderr, "⏳ Polling %s (%s)\n", label, scanID)

	for attempt := range maxAttempts {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		obj, err := c.cli.GetObject(vt.URL("analyses/%s", scanID))
		if err == nil {
			status, _ := obj.GetString("status")
			if status == "completed" {
				malicious, _ := obj.GetInt64("stats.malicious")
				suspicious, _ := obj.GetInt64("stats.suspicious")
				harmless, _ := obj.GetInt64("stats.harmless")
				undetected, _ := obj.GetInt64("stats.undetected")
				timeoutC, _ := obj.GetInt64("stats.timeout")
				typeUns, _ := obj.GetInt64("stats.type-unsupported")
				total := malicious + suspicious + harmless + undetected + timeoutC + typeUns
				date, _ := obj.GetInt64("date")

				return &types.ScanResult{
					ScanID:    scanID,
					Malicious: malicious,
					Total:     total,
					Date:      date,
				}, nil
			}

			fmt.Fprintf(
				os.Stderr,
				"  attempt %d/%d: status=%s, waiting %ds …\n",
				attempt+1,
				maxAttempts,
				status,
				int(pollInterval.Seconds()),
			)
		} else {
			// Fallback: if analyses lookup failed, check if scanID is a file hash on files endpoint
			fileObj, fileErr := c.cli.GetObject(vt.URL("files/%s", scanID))
			if fileErr == nil && fileObj != nil {
				malicious, mErr := fileObj.GetInt64("last_analysis_stats.malicious")
				if mErr == nil {
					suspicious, _ := fileObj.GetInt64("last_analysis_stats.suspicious")
					harmless, _ := fileObj.GetInt64("last_analysis_stats.harmless")
					undetected, _ := fileObj.GetInt64("last_analysis_stats.undetected")
					timeoutC, _ := fileObj.GetInt64("last_analysis_stats.timeout")
					typeUns, _ := fileObj.GetInt64("last_analysis_stats.type-unsupported")
					total := malicious + suspicious + harmless + undetected + timeoutC + typeUns
					date, _ := fileObj.GetInt64("last_analysis_date")

					if total > 0 || date > 0 {
						return &types.ScanResult{
							ScanID:    scanID,
							Malicious: malicious,
							Total:     total,
							Date:      date,
						}, nil
					}
				}
			}

			fmt.Fprintf(
				os.Stderr,
				"  attempt %d/%d: request error: %v, waiting %ds …\n",
				attempt+1,
				maxAttempts,
				err,
				int(pollInterval.Seconds()),
			)
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollInterval):
		}
	}

	return &types.ScanResult{
		ScanID:   scanID,
		TimedOut: true,
	}, nil
}
