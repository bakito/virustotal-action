package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	gh "github.com/google/go-github/v91/github"
)

func TestGHClientGetRelease(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/releases/tags/v1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		rel := &gh.RepositoryRelease{
			ID:      101,
			TagName: "v1.0.0",
			Name:    new("Release v1.0.0"),
		}
		_ = json.NewEncoder(w).Encode(rel)
	})

	mux.HandleFunc("/repos/owner/repo/releases", func(w http.ResponseWriter, _ *http.Request) {
		releases := []*gh.RepositoryRelease{
			{
				ID:      102,
				TagName: "v2.0.0-rc1",
				Name:    new("v2.0.0-ReleaseCandidate"),
			},
		}
		_ = json.NewEncoder(w).Encode(releases)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	client, _ := gh.NewClient(gh.WithHTTPClient(ts.Client()), gh.WithURLs(new(ts.URL+"/"), new(ts.URL+"/")))

	ghc := &ghClient{
		client:     client,
		httpClient: ts.Client(),
	}

	ctx := context.Background()

	// 1. Found by tag
	rel, err := ghc.GetRelease(ctx, "owner", "repo", "v1.0.0")
	if err != nil {
		t.Fatalf("expected release, got error: %v", err)
	}
	if rel.GetID() != 101 {
		t.Errorf("expected ID 101, got %d", rel.GetID())
	}

	// 2. Found by name in list
	rel2, err := ghc.GetRelease(ctx, "owner", "repo", "v2.0.0-ReleaseCandidate")
	if err != nil {
		t.Fatalf("expected release by name, got error: %v", err)
	}
	if rel2.GetID() != 102 {
		t.Errorf("expected ID 102, got %d", rel2.GetID())
	}
}

func TestGHClientDownloadAssets(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/releases/assets/555", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("asset-555-content"))
	})
	mux.HandleFunc("/repos/owner/repo/releases/assets/666", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("asset-666-content"))
	})
	mux.HandleFunc("/repos/owner/repo/releases/assets/777", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("asset-777-content"))
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	client, _ := gh.NewClient(gh.WithHTTPClient(ts.Client()), gh.WithURLs(new(ts.URL+"/"), new(ts.URL+"/")))

	ghc := &ghClient{
		client:     client,
		httpClient: ts.Client(),
	}

	destDir := t.TempDir()
	release := &gh.RepositoryRelease{
		Assets: []*gh.ReleaseAsset{
			{
				ID:   new(int64(555)),
				Name: new("app-windows.zip"),
			},
			{
				ID:   new(int64(666)),
				Name: new("app-linux.tar.gz"),
			},
			{
				ID:   new(int64(777)),
				Name: new("app-windows.exe"),
			},
			{
				ID:   new(int64(888)),
				Name: new("app-windows.sbom.json"),
			},
			{
				ID:   new(int64(999)),
				Name: new("app-windows.json"),
			},
			{
				ID:   new(int64(1001)),
				Name: new("gws_0.5.2_windows_amd64.zip.sbom.json"),
			},
			{
				ID:   new(int64(1002)),
				Name: new("gws_0.5.2_linux_amd64.tar.gz.sbom.json"),
			},
		},
	}

	// 1. Download matching *windows* assets (zip and exe, ignoring json and sbom.json)
	downloaded, err := ghc.DownloadReleaseAssets(context.Background(), "owner", "repo", release, "*windows*", destDir)
	if err != nil {
		t.Fatalf("DownloadReleaseAssets failed: %v", err)
	}

	if len(downloaded) != 2 {
		t.Fatalf("expected 2 downloaded assets (zip and exe), got %d: %v", len(downloaded), downloaded)
	}

	content1, err := os.ReadFile(downloaded[0])
	if err != nil {
		t.Fatalf("failed to read downloaded file: %v", err)
	}
	if string(content1) != "asset-555-content" {
		t.Errorf("unexpected content: %s", string(content1))
	}

	content2, err := os.ReadFile(downloaded[1])
	if err != nil {
		t.Fatalf("failed to read downloaded file: %v", err)
	}
	if string(content2) != "asset-777-content" {
		t.Errorf("unexpected content: %s", string(content2))
	}

	// 2. Download matching *linux* assets (tar.gz)
	destDirLinux := t.TempDir()
	downloadedLinux, err := ghc.DownloadReleaseAssets(context.Background(), "owner", "repo", release, "*linux*", destDirLinux)
	if err != nil {
		t.Fatalf("DownloadReleaseAssets for linux failed: %v", err)
	}
	if len(downloadedLinux) != 1 {
		t.Fatalf("expected 1 downloaded asset (tar.gz), got %d: %v", len(downloadedLinux), downloadedLinux)
	}
	contentLinux, err := os.ReadFile(downloadedLinux[0])
	if err != nil {
		t.Fatalf("failed to read downloaded file: %v", err)
	}
	if string(contentLinux) != "asset-666-content" {
		t.Errorf("unexpected content: %s", string(contentLinux))
	}

	// 3. Download matching all assets (*) -> should download zip, tar.gz, exe; ignoring sbom.json and json
	destDirAll := t.TempDir()
	downloadedAll, err := ghc.DownloadReleaseAssets(context.Background(), "owner", "repo", release, "*", destDirAll)
	if err != nil {
		t.Fatalf("DownloadReleaseAssets for all failed: %v", err)
	}
	if len(downloadedAll) != 3 {
		t.Fatalf("expected 3 downloaded assets (zip, tar.gz, exe), got %d: %v", len(downloadedAll), downloadedAll)
	}
}

func TestGHClientUpdateReleaseNotes(t *testing.T) {
	var receivedBody string
	var receivedPrerelease *bool
	var receivedMakeLatest *string

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/releases/101", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			var editReq gh.UpdateReleaseRequest
			_ = json.NewDecoder(r.Body).Decode(&editReq)
			receivedBody = editReq.GetBody()
			receivedPrerelease = editReq.Prerelease
			receivedMakeLatest = editReq.MakeLatest
			_ = json.NewEncoder(w).Encode(&editReq)
			return
		}
		http.NotFound(w, r)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	client, _ := gh.NewClient(gh.WithHTTPClient(ts.Client()), gh.WithURLs(new(ts.URL+"/"), new(ts.URL+"/")))

	ghc := &ghClient{
		client:     client,
		httpClient: ts.Client(),
	}

	ctx := context.Background()

	// 1. Normal update
	err := ghc.UpdateReleaseNotes(ctx, "owner", "repo", 101, "New Notes", false)
	if err != nil {
		t.Fatalf("UpdateReleaseNotes failed: %v", err)
	}
	if receivedBody != "New Notes" {
		t.Errorf("expected 'New Notes', got %q", receivedBody)
	}
	if receivedPrerelease != nil || receivedMakeLatest != nil {
		t.Error("expected nil prerelease and makeLatest")
	}

	// 2. Update with promote to latest
	err = ghc.UpdateReleaseNotes(ctx, "owner", "repo", 101, "Latest Notes", true)
	if err != nil {
		t.Fatalf("UpdateReleaseNotes with latest failed: %v", err)
	}
	if receivedBody != "Latest Notes" {
		t.Errorf("expected 'Latest Notes', got %q", receivedBody)
	}
	if receivedPrerelease == nil || *receivedPrerelease {
		t.Error("expected prerelease false")
	}
	if receivedMakeLatest == nil || *receivedMakeLatest != "true" {
		t.Error("expected makeLatest 'true'")
	}
}
