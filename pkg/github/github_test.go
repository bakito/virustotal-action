package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	gh "github.com/google/go-github/v91/github"
)

func TestGHClientGetRelease(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/releases/tags/v1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		rel := &gh.RepositoryRelease{
			ID:      gh.Ptr(int64(101)),
			TagName: gh.Ptr("v1.0.0"),
			Name:    gh.Ptr("Release v1.0.0"),
		}
		_ = json.NewEncoder(w).Encode(rel)
	})

	mux.HandleFunc("/repos/owner/repo/releases", func(w http.ResponseWriter, _ *http.Request) {
		releases := []*gh.RepositoryRelease{
			{
				ID:      gh.Ptr(int64(102)),
				TagName: gh.Ptr("v2.0.0-rc1"),
				Name:    gh.Ptr("v2.0.0-ReleaseCandidate"),
			},
		}
		_ = json.NewEncoder(w).Encode(releases)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	u, _ := url.Parse(ts.URL + "/")
	client := gh.NewClient(ts.Client())
	client.BaseURL = u

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

	ts := httptest.NewServer(mux)
	defer ts.Close()

	u, _ := url.Parse(ts.URL + "/")
	client := gh.NewClient(ts.Client())
	client.BaseURL = u

	ghc := &ghClient{
		client:     client,
		httpClient: ts.Client(),
	}

	destDir := t.TempDir()
	release := &gh.RepositoryRelease{
		Assets: []*gh.ReleaseAsset{
			{
				ID:   gh.Ptr(int64(555)),
				Name: gh.Ptr("app-windows.zip"),
			},
			{
				ID:   gh.Ptr(int64(666)),
				Name: gh.Ptr("app-linux.tar.gz"),
			},
		},
	}

	downloaded, err := ghc.DownloadReleaseAssets(context.Background(), "owner", "repo", release, "*windows*", destDir)
	if err != nil {
		t.Fatalf("DownloadReleaseAssets failed: %v", err)
	}

	if len(downloaded) != 1 {
		t.Fatalf("expected 1 downloaded asset, got %d", len(downloaded))
	}

	content, err := os.ReadFile(downloaded[0])
	if err != nil {
		t.Fatalf("failed to read downloaded file: %v", err)
	}
	if string(content) != "asset-555-content" {
		t.Errorf("unexpected content: %s", string(content))
	}
}

func TestGHClientUpdateReleaseNotes(t *testing.T) {
	var receivedBody string
	var receivedPrerelease *bool
	var receivedMakeLatest *string

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/releases/101", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			var editReq gh.RepositoryRelease
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

	u, _ := url.Parse(ts.URL + "/")
	client := gh.NewClient(ts.Client())
	client.BaseURL = u

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
