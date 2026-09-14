package vt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	vt "github.com/VirusTotal/vt-go"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestVTClientPollScanCompleted(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "analyses/scan-123") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"data": {
					"id": "scan-123",
					"type": "analysis",
					"attributes": {
						"status": "completed",
						"date": 1710513000,
						"stats": {
							"malicious": 0,
							"suspicious": 1,
							"harmless": 2,
							"undetected": 65,
							"timeout": 0,
							"type-unsupported": 1
						}
					}
				}
			}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	httpClient := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			req.URL.Scheme = u.Scheme
			req.URL.Host = u.Host
			return http.DefaultTransport.RoundTrip(req)
		}),
	}

	client := NewClient("dummy-key", vt.WithHTTPClient(httpClient))

	res, err := client.PollScan(context.Background(), "scan-123", "app.exe", 3, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.TimedOut {
		t.Error("expected completed, got timed out")
	}
	if res.Malicious != 0 {
		t.Errorf("expected 0 malicious, got %d", res.Malicious)
	}
	if res.Total != 69 {
		t.Errorf("expected 69 total, got %d", res.Total)
	}
	if res.Date != 1710513000 {
		t.Errorf("expected date 1710513000, got %d", res.Date)
	}
	if !res.IsSuccess() {
		t.Error("expected IsSuccess true")
	}
}

func TestVTClientPollScanTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"data": {
				"id": "scan-123",
				"type": "analysis",
				"attributes": {
					"status": "queued"
				}
			}
		}`))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	httpClient := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			req.URL.Scheme = u.Scheme
			req.URL.Host = u.Host
			return http.DefaultTransport.RoundTrip(req)
		}),
	}

	client := NewClient("dummy-key", vt.WithHTTPClient(httpClient))

	res, err := client.PollScan(context.Background(), "scan-123", "app.exe", 2, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !res.TimedOut {
		t.Error("expected timed out, got completed")
	}
	if res.IsSuccess() {
		t.Error("expected IsSuccess false for timed out scan")
	}
}

func TestVTClientScanFile(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "files") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"data": {
					"id": "analysis-id-999",
					"type": "analysis"
				}
			}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	httpClient := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			req.URL.Scheme = u.Scheme
			req.URL.Host = u.Host
			return http.DefaultTransport.RoundTrip(req)
		}),
	}

	client := NewClient("dummy-key", vt.WithHTTPClient(httpClient))

	tmpFile := filepath.Join(t.TempDir(), "test.exe")
	if err := os.WriteFile(tmpFile, []byte("fake-exe"), 0o644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	scanID, err := client.ScanFile(tmpFile)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if scanID != "analysis-id-999" {
		t.Errorf("expected analysis-id-999, got %s", scanID)
	}
}

func TestVTClientScanFileAlreadySubmittedAnalysesFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v3/files" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{
				"error": {
					"code": "AlreadyExistsError",
					"message": "Already being submitted for scanning"
				}
			}`))
			return
		}
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/analyses") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"data": [
					{
						"id": "prev-analysis-id-123",
						"type": "analysis"
					}
				]
			}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	httpClient := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			req.URL.Scheme = u.Scheme
			req.URL.Host = u.Host
			return http.DefaultTransport.RoundTrip(req)
		}),
	}

	client := NewClient("dummy-key", vt.WithHTTPClient(httpClient))

	tmpFile := filepath.Join(t.TempDir(), "test.exe")
	if err := os.WriteFile(tmpFile, []byte("fake-exe"), 0o644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	scanID, err := client.ScanFile(tmpFile)
	if err != nil {
		t.Fatalf("ScanFile failed on already submitted error: %v", err)
	}
	if scanID != "prev-analysis-id-123" {
		t.Errorf("expected prev-analysis-id-123, got %s", scanID)
	}
}

func TestVTClientScanFileAlreadySubmittedFileObjectFound(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.exe")
	if err := os.WriteFile(tmpFile, []byte("fake-exe"), 0o644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	expectedHash, err := fileSHA256(tmpFile)
	if err != nil {
		t.Fatalf("failed to compute hash: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v3/files" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{
				"error": {
					"code": "AlreadyExistsError",
					"message": "Already being submitted for scanning"
				}
			}`))
			return
		}
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/analyses") {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v3/files/") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"data": {
					"id": "` + expectedHash + `",
					"type": "file"
				}
			}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	httpClient := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			req.URL.Scheme = u.Scheme
			req.URL.Host = u.Host
			return http.DefaultTransport.RoundTrip(req)
		}),
	}

	client := NewClient("dummy-key", vt.WithHTTPClient(httpClient))

	scanID, err := client.ScanFile(tmpFile)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}
	if scanID != expectedHash {
		t.Errorf("expected %s, got %s", expectedHash, scanID)
	}
}

func TestVTClientScanFileAlreadySubmittedNotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v3/files" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{
				"error": {
					"code": "AlreadyExistsError",
					"message": "Already being submitted for scanning"
				}
			}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	httpClient := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			req.URL.Scheme = u.Scheme
			req.URL.Host = u.Host
			return http.DefaultTransport.RoundTrip(req)
		}),
	}

	client := NewClient("dummy-key", vt.WithHTTPClient(httpClient))

	tmpFile := filepath.Join(t.TempDir(), "test.exe")
	if err := os.WriteFile(tmpFile, []byte("fake-exe"), 0o644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	_, err := client.ScanFile(tmpFile)
	if err == nil {
		t.Fatal("expected error when no previous scan is found, got nil")
	}
}

func TestVTClientPollScanFilesFallback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "analyses/") {
			http.NotFound(w, r)
			return
		}
		if strings.Contains(r.URL.Path, "files/file-hash-456") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"data": {
					"id": "file-hash-456",
					"type": "file",
					"attributes": {
						"last_analysis_date": 1710513000,
						"last_analysis_stats": {
							"malicious": 0,
							"suspicious": 1,
							"harmless": 2,
							"undetected": 65,
							"timeout": 0,
							"type-unsupported": 1
						}
					}
				}
			}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	httpClient := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			req.URL.Scheme = u.Scheme
			req.URL.Host = u.Host
			return http.DefaultTransport.RoundTrip(req)
		}),
	}

	client := NewClient("dummy-key", vt.WithHTTPClient(httpClient))

	res, err := client.PollScan(context.Background(), "file-hash-456", "app.exe", 2, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.TimedOut {
		t.Error("expected completed via files fallback, got timed out")
	}
	if res.Malicious != 0 {
		t.Errorf("expected 0 malicious, got %d", res.Malicious)
	}
	if res.Total != 69 {
		t.Errorf("expected 69 total, got %d", res.Total)
	}
	if res.Date != 1710513000 {
		t.Errorf("expected date 1710513000, got %d", res.Date)
	}
	if !res.IsSuccess() {
		t.Error("expected IsSuccess true")
	}
}
