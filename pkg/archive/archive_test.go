package archive

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func createTestZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create zip file: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("failed to create zip entry %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write zip entry %s: %v", name, err)
		}
	}
}

func createTestTarGz(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create targz file: %v", err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0o755,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("failed to write tar header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write tar content %s: %v", name, err)
		}
	}
}

func TestExtractAllAndFindBinaryTargets(t *testing.T) {
	tmpDir := t.TempDir()
	assetsDir := filepath.Join(tmpDir, "assets")
	extractedDir := filepath.Join(tmpDir, "extracted")

	if err := os.MkdirAll(assetsDir, 0o755); err != nil {
		t.Fatalf("failed to create assets dir: %v", err)
	}

	// 1. Create a zip archive with an exe and a txt file
	zipPath := filepath.Join(assetsDir, "app-windows.zip")
	createTestZip(t, zipPath, map[string]string{
		"app.exe":    "binary content",
		"readme.txt": "documentation",
	})

	// 2. Create a tar.gz archive with a nested exe
	tarGzPath := filepath.Join(assetsDir, "tool-windows.tar.gz")
	createTestTarGz(t, tarGzPath, map[string]string{
		"bin/tool.exe": "tool binary",
		"config.json":  "{}",
	})

	// 3. Create a single gz file
	gzPath := filepath.Join(assetsDir, "single.exe.gz")
	gzFile, err := os.Create(gzPath)
	if err != nil {
		t.Fatalf("failed to create gz file: %v", err)
	}
	gw := gzip.NewWriter(gzFile)
	_, _ = gw.Write([]byte("single binary"))
	_ = gw.Close()
	_ = gzFile.Close()

	// 4. Create a plain text file that is not an archive
	if err := os.WriteFile(filepath.Join(assetsDir, "checksums.txt"), []byte("hash"), 0o644); err != nil {
		t.Fatalf("failed to create checksums.txt: %v", err)
	}

	// Extract
	if err := ExtractAll(assetsDir, extractedDir); err != nil {
		t.Fatalf("ExtractAll failed: %v", err)
	}

	// Verify extraction
	if _, err := os.Stat(filepath.Join(extractedDir, "app-windows.zip", "app.exe")); err != nil {
		t.Fatalf("expected extracted app.exe: %v", err)
	}
	if _, err := os.Stat(filepath.Join(extractedDir, "tool-windows.tar.gz", "bin", "tool.exe")); err != nil {
		t.Fatalf("expected extracted tool.exe: %v", err)
	}
	if _, err := os.Stat(filepath.Join(extractedDir, "single.exe.gz", "single.exe")); err != nil {
		t.Fatalf("expected extracted single.exe: %v", err)
	}

	// Find binaries
	targets, err := FindBinaryTargets(assetsDir, extractedDir, "*.exe")
	if err != nil {
		t.Fatalf("FindBinaryTargets failed: %v", err)
	}

	if len(targets) != 3 {
		t.Fatalf("expected 3 targets, got %d: %+v", len(targets), targets)
	}

	if targets[0].ArchiveName != "app-windows.zip" || targets[0].ExeName != "app.exe" {
		t.Errorf("unexpected target[0]: %+v", targets[0])
	}
	if targets[1].ArchiveName != "single.exe.gz" || targets[1].ExeName != "single.exe" {
		t.Errorf("unexpected target[1]: %+v", targets[1])
	}
	if targets[2].ArchiveName != "tool-windows.tar.gz" || targets[2].ExeName != "tool.exe" {
		t.Errorf("unexpected target[2]: %+v", targets[2])
	}
}

func TestNonExistentDirs(t *testing.T) {
	if err := ExtractAll("/non/existent/path", "/tmp/extracted"); err != nil {
		t.Errorf("expected nil error for non-existent assets dir, got %v", err)
	}

	targets, err := FindBinaryTargets("/non/existent/path", "/non/existent/extracted", "*.exe")
	if err != nil {
		t.Errorf("expected nil error for non-existent extracted dir, got %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("expected 0 targets, got %d", len(targets))
	}
}
