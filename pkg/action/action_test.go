package action

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gh "github.com/google/go-github/v91/github"

	"github.com/bakito/virustotal-action/pkg/types"
)

type mockGHClient struct {
	release        *gh.RepositoryRelease
	updatedNotes   string
	updateToLatest bool
	downloadErr    error
}

func (m *mockGHClient) GetRelease(_ context.Context, _, _, _ string) (*gh.RepositoryRelease, error) {
	return m.release, nil
}

func (m *mockGHClient) DownloadReleaseAssets(
	_ context.Context,
	_, _ string,
	_ *gh.RepositoryRelease,
	_, destDir string,
) ([]string, error) {
	if m.downloadErr != nil {
		return nil, m.downloadErr
	}
	// Create a dummy zip asset in destDir
	zipPath := filepath.Join(destDir, "app-windows.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	w, _ := zw.Create("app.exe")
	_, _ = w.Write([]byte("mock-exe-data"))
	_ = zw.Close()

	return []string{zipPath}, nil
}

func (m *mockGHClient) UpdateReleaseNotes(
	_ context.Context,
	_, _ string,
	_ int64,
	notes string,
	updateToLatest bool,
) error {
	m.updatedNotes = notes
	m.updateToLatest = updateToLatest
	return nil
}

type mockVTClient struct {
	scannedFiles []string
	pollResults  map[string]*types.ScanResult
}

func (m *mockVTClient) ScanFile(filePath string) (string, error) {
	m.scannedFiles = append(m.scannedFiles, filePath)
	return "scan-" + filepath.Base(filePath), nil
}

func (m *mockVTClient) PollScan(
	_ context.Context,
	scanID, _ string,
	_ int,
	_ time.Duration,
) (*types.ScanResult, error) {
	if res, ok := m.pollResults[scanID]; ok {
		return res, nil
	}
	return &types.ScanResult{
		ScanID:    scanID,
		Malicious: 0,
		Total:     70,
		Date:      1710513000,
	}, nil
}

func TestRunnerAllChecksSuccessfulPromotesPrerelease(t *testing.T) {
	mockGH := &mockGHClient{
		release: &gh.RepositoryRelease{
			ID:         1001,
			TagName:    "v1.0.0-rc1",
			Body:       new("Initial release notes"),
			Prerelease: true,
		},
	}
	mockVT := &mockVTClient{
		pollResults: map[string]*types.ScanResult{
			"scan-app-windows.zip": {ScanID: "scan-app-windows.zip", Malicious: 0, Total: 70, Date: 1710513000},
			"scan-app.exe":         {ScanID: "scan-app.exe", Malicious: 0, Total: 70, Date: 1710513000},
		},
	}

	runner := &Runner{
		GHClient: mockGH,
		VTClient: mockVT,
	}

	cfg := &types.Config{
		ReleaseName:                    "v1.0.0-rc1",
		VTApiKey:                       "secret-vt-key",
		DownloadReleaseArtifactPattern: "*windows*",
		BinaryPattern:                  "*.exe",
		PollInterval:                   1 * time.Millisecond,
		PollMaxAttempts:                1,
		GitHubRepository:               "bakito/virustotal-action",
		UpdateToLatest:                 true,
	}

	err := runner.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify scanned files
	if len(mockVT.scannedFiles) != 2 {
		t.Errorf("expected 2 files scanned, got %d", len(mockVT.scannedFiles))
	}

	// Verify release notes
	if !strings.Contains(mockGH.updatedNotes, "Initial release notes") {
		t.Error("expected existing notes preserved")
	}
	if !strings.Contains(mockGH.updatedNotes, "## 🦠 VirusTotal Report 🔎") {
		t.Error("expected VT heading in updated notes")
	}
	if !strings.Contains(mockGH.updatedNotes, "app-windows.zip") {
		t.Error("expected app-windows.zip in table")
	}

	// Verify promotion to latest
	if !mockGH.updateToLatest {
		t.Error("expected updateToLatest to be true for clean prerelease when UpdateToLatest is true")
	}
}

func TestRunnerAllChecksSuccessfulDefaultDisabled(t *testing.T) {
	mockGH := &mockGHClient{
		release: &gh.RepositoryRelease{
			ID:         1001,
			TagName:    "v1.0.0-rc1",
			Body:       new("Initial release notes"),
			Prerelease: true,
		},
	}
	mockVT := &mockVTClient{
		pollResults: map[string]*types.ScanResult{
			"scan-app-windows.zip": {ScanID: "scan-app-windows.zip", Malicious: 0, Total: 70, Date: 1710513000},
			"scan-app.exe":         {ScanID: "scan-app.exe", Malicious: 0, Total: 70, Date: 1710513000},
		},
	}

	runner := &Runner{
		GHClient: mockGH,
		VTClient: mockVT,
	}

	cfg := &types.Config{
		ReleaseName:                    "v1.0.0-rc1",
		VTApiKey:                       "secret-vt-key",
		DownloadReleaseArtifactPattern: "*windows*",
		BinaryPattern:                  "*.exe",
		PollInterval:                   1 * time.Millisecond,
		PollMaxAttempts:                1,
		GitHubRepository:               "bakito/virustotal-action",
		UpdateToLatest:                 false,
	}

	err := runner.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify not promoted to latest when UpdateToLatest is false
	if mockGH.updateToLatest {
		t.Error("expected updateToLatest to be false when UpdateToLatest is false")
	}
}

func TestRunnerMaliciousDetectionsDoesNotPromote(t *testing.T) {
	mockGH := &mockGHClient{
		release: &gh.RepositoryRelease{
			ID:         1002,
			TagName:    "v1.0.0-rc2",
			Body:       new("Notes"),
			Prerelease: true,
		},
	}
	mockVT := &mockVTClient{
		pollResults: map[string]*types.ScanResult{
			"scan-app-windows.zip": {ScanID: "scan-app-windows.zip", Malicious: 0, Total: 70, Date: 1710513000},
			"scan-app.exe":         {ScanID: "scan-app.exe", Malicious: 1, Total: 70, Date: 1710513000},
		},
	}

	runner := &Runner{
		GHClient: mockGH,
		VTClient: mockVT,
	}

	cfg := &types.Config{
		ReleaseName:                    "v1.0.0-rc2",
		VTApiKey:                       "secret-vt-key",
		DownloadReleaseArtifactPattern: "*windows*",
		BinaryPattern:                  "*.exe",
		PollInterval:                   1 * time.Millisecond,
		PollMaxAttempts:                1,
		GitHubRepository:               "bakito/virustotal-action",
	}

	err := runner.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mockGH.updateToLatest {
		t.Error("expected updateToLatest to be false when detections exist")
	}
}

func TestRunnerMissingInputs(t *testing.T) {
	runner := &Runner{}
	err := runner.Run(context.Background(), &types.Config{
		VTApiKey: "key",
	})
	if err == nil {
		t.Error("expected error for missing release_name")
	}

	err = runner.Run(context.Background(), &types.Config{
		ReleaseName: "v1.0.0",
	})
	if err == nil {
		t.Error("expected error for missing vt_api_key")
	}
}
