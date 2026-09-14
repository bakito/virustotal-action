package github

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-github/v91/github"

	"github.com/bakito/virustotal-action/pkg/archive"
)

// Client defines the interface for GitHub operations.
type Client interface {
	GetRelease(ctx context.Context, owner, repo, releaseName string) (*github.RepositoryRelease, error)
	DownloadReleaseAssets(
		ctx context.Context,
		owner, repo string,
		release *github.RepositoryRelease,
		pattern, destDir string,
	) ([]string, error)
	UpdateReleaseNotes(ctx context.Context, owner, repo string, releaseID int64, notes string, updateToLatest bool) error
}

type ghClient struct {
	client     *github.Client
	httpClient *http.Client
}

// NewClient creates a new GitHub client using token authentication if provided.
func NewClient(token string, opts ...Option) Client {
	c := &ghClient{
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(c)
	}

	var clientOpts []github.ClientOptionsFunc
	if c.httpClient != nil {
		clientOpts = append(clientOpts, github.WithHTTPClient(c.httpClient))
	}
	if token != "" {
		clientOpts = append(clientOpts, github.WithAuthToken(token))
	}

	baseClient, _ := github.NewClient(clientOpts...)
	c.client = baseClient

	return c
}

// Option configures the GitHub client.
type Option func(*ghClient)

// WithHTTPClient sets a custom HTTP client for GitHub API calls.
func WithHTTPClient(client *http.Client) Option {
	return func(c *ghClient) {
		c.httpClient = client
	}
}

// GetRelease retrieves a release by tag or name.
func (c *ghClient) GetRelease(ctx context.Context, owner, repo, releaseName string) (*github.RepositoryRelease, error) {
	rel, _, err := c.client.Repositories.GetReleaseByTag(ctx, owner, repo, releaseName)
	if err == nil && rel != nil {
		return rel, nil
	}

	opt := &github.ListOptions{PerPage: 100}
	for {
		releases, resp, listErr := c.client.Repositories.ListReleases(ctx, owner, repo, opt)
		if listErr != nil {
			break
		}
		for _, r := range releases {
			if r.GetName() == releaseName || r.GetTagName() == releaseName {
				return r, nil
			}
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get release %q: %w", releaseName, err)
	}
	return nil, fmt.Errorf("release %q not found", releaseName)
}

// DownloadReleaseAssets downloads assets matching pattern into destDir.
func (c *ghClient) DownloadReleaseAssets(
	ctx context.Context,
	owner, repo string,
	release *github.RepositoryRelease,
	pattern, destDir string,
) ([]string, error) {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create destination dir: %w", err)
	}

	var downloaded []string
	for _, asset := range release.Assets {
		name := asset.GetName()
		matched, err := filepath.Match(pattern, name)
		if err != nil || !matched {
			continue
		}

		if !isSupportedAsset(name) {
			continue
		}

		destFile := filepath.Join(destDir, name)
		if err := c.downloadAsset(ctx, owner, repo, asset.GetID(), destFile); err != nil {
			return nil, fmt.Errorf("failed to download asset %s: %w", name, err)
		}
		downloaded = append(downloaded, destFile)
	}

	return downloaded, nil
}

func isSupportedAsset(name string) bool {
	if strings.EqualFold(filepath.Ext(name), ".exe") {
		return true
	}
	return archive.IsArchive(name)
}

func (c *ghClient) downloadAsset(ctx context.Context, owner, repo string, assetID int64, destFile string) error {
	rc, redirectURL, err := c.client.Repositories.DownloadReleaseAsset(ctx, owner, repo, assetID, c.httpClient)
	if err != nil {
		return err
	}

	var reader io.ReadCloser
	switch {
	case rc != nil:
		reader = rc
	case redirectURL != "":
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, redirectURL, http.NoBody)
		if err != nil {
			return err
		}
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return fmt.Errorf("download failed with status %d", resp.StatusCode)
		}
		reader = resp.Body
	default:
		return fmt.Errorf("no content or redirect URL returned for asset %d", assetID)
	}
	defer reader.Close()

	out, err := os.Create(destFile)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, reader)
	return err
}

// UpdateReleaseNotes updates the release body and optionally updates prerelease to latest.
func (c *ghClient) UpdateReleaseNotes(
	ctx context.Context,
	owner, repo string,
	releaseID int64,
	notes string,
	updateToLatest bool,
) error {
	editReq := github.UpdateReleaseRequest{
		Body: &notes,
	}
	if updateToLatest {
		editReq.Prerelease = new(false)
		editReq.MakeLatest = new("true")
	}

	_, _, err := c.client.Repositories.UpdateRelease(ctx, owner, repo, releaseID, editReq)
	return err
}
