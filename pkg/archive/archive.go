package archive

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/mholt/archives"

	"github.com/bakito/virustotal-action/pkg/types"
)

var archiveExtensions = []string{
	// Compound tar extensions
	".tar.gz",
	".tar.bz2",
	".tar.xz",
	".tar.zst",
	".tar.lz4",
	".tar.sz",
	".tar.s2",
	".tar.lz",
	".tar.br",

	// Short tar extensions
	".tgz",
	".tbz",
	".tbz2",
	".txz",
	".tzst",
	".tlz4",
	".tsz",
	".ts2",
	".tlz",
	".tbr",

	// Archive formats
	".zip",
	".tar",
	".7z",
	".rar",

	// Single compressed file formats
	".gz",
	".bz2",
	".xz",
	".zst",
	".lz4",
	".sz",
	".s2",
	".lz",
	".br",
}

// IsArchive returns true if the filename represents a recognized archive or compressed format.
func IsArchive(filename string) bool {
	if archives.PathIsArchive(filename) {
		return true
	}
	lower := strings.ToLower(filename)
	for _, ext := range archiveExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// ExtractAll extracts all archive files in assetsDir to corresponding subdirectories in extractedDir.
func ExtractAll(assetsDir, extractedDir string) error {
	entries, err := os.ReadDir(assetsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read assets directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !IsArchive(entry.Name()) {
			continue
		}
		filePath := filepath.Join(assetsDir, entry.Name())
		targetDir := filepath.Join(extractedDir, entry.Name())

		if err := extractFile(filePath, targetDir, entry.Name()); err != nil {
			return err
		}
	}

	return nil
}

func extractFile(filePath, targetDir, entryName string) error {
	if !IsArchive(entryName) {
		return nil
	}

	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", filePath, err)
	}
	defer f.Close()

	ctx := context.Background()
	format, reader, err := archives.Identify(ctx, filePath, f)
	if err != nil {
		if errors.Is(err, archives.NoMatch) {
			// Not a recognized archive format; skip extraction
			return nil
		}
		return nil
	}

	if extractor, ok := format.(archives.Extractor); ok {
		if err := os.MkdirAll(targetDir, 0o755); err != nil {
			return fmt.Errorf("failed to create target dir %s: %w", targetDir, err)
		}

		err = extractor.Extract(ctx, reader, func(_ context.Context, info archives.FileInfo) error {
			name := filepath.Clean(info.NameInArchive)
			if name == "." || name == "/" {
				return nil
			}
			targetPath := filepath.Join(targetDir, name)
			rel, err := filepath.Rel(targetDir, targetPath)
			if err != nil || strings.HasPrefix(rel, "..") {
				return fmt.Errorf("illegal file path in archive: %s", info.NameInArchive)
			}

			if info.IsDir() {
				return os.MkdirAll(targetPath, 0o755)
			}

			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				return fmt.Errorf("failed to create directory for %s: %w", targetPath, err)
			}

			rc, err := info.Open()
			if err != nil {
				return fmt.Errorf("failed to open entry %s: %w", info.NameInArchive, err)
			}
			defer rc.Close()

			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", targetPath, err)
			}
			defer outFile.Close()

			if _, err := io.Copy(outFile, rc); err != nil {
				return fmt.Errorf("failed to write file %s: %w", targetPath, err)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("failed to extract %s: %w", filePath, err)
		}
		return nil
	}

	if decompressor, ok := format.(archives.Decompressor); ok {
		if err := os.MkdirAll(targetDir, 0o755); err != nil {
			return fmt.Errorf("failed to create target dir %s: %w", targetDir, err)
		}

		rc, err := decompressor.OpenReader(reader)
		if err != nil {
			return fmt.Errorf("failed to decompress %s: %w", filePath, err)
		}
		defer rc.Close()

		ext := filepath.Ext(entryName)
		uncompressedName := strings.TrimSuffix(entryName, ext)
		if uncompressedName == "" {
			uncompressedName = entryName
		}
		targetPath := filepath.Join(targetDir, uncompressedName)

		outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return fmt.Errorf("failed to create file %s: %w", targetPath, err)
		}
		defer outFile.Close()

		if _, err := io.Copy(outFile, rc); err != nil {
			return fmt.Errorf("failed to write file %s: %w", targetPath, err)
		}
		return nil
	}

	return nil
}

// FindBinaryTargets locates files matching binaryPattern within each extracted archive directory.
func FindBinaryTargets(assetsDir, extractedDir, binaryPattern string) ([]types.BinaryTarget, error) {
	entries, err := os.ReadDir(extractedDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read extracted directory: %w", err)
	}

	var targets []types.BinaryTarget

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		archiveName := entry.Name()
		archiveDir := filepath.Join(extractedDir, archiveName)
		archiveFile := filepath.Join(assetsDir, archiveName)

		err := filepath.WalkDir(archiveDir, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}

			fileName := d.Name()
			relPath, err := filepath.Rel(archiveDir, path)
			if err != nil {
				relPath = fileName
			}

			matchedName, _ := filepath.Match(binaryPattern, fileName)
			matchedPath, _ := filepath.Match(binaryPattern, relPath)

			if matchedName || matchedPath {
				targets = append(targets, types.BinaryTarget{
					ArchiveName: archiveName,
					ArchiveFile: archiveFile,
					ExeName:     fileName,
					ExeFile:     path,
				})
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed to walk extracted archive %s: %w", archiveName, err)
		}
	}

	slices.SortFunc(targets, func(a, b types.BinaryTarget) int {
		if n := cmp.Compare(a.ArchiveName, b.ArchiveName); n != 0 {
			return n
		}
		return cmp.Compare(a.ExeName, b.ExeName)
	})

	return targets, nil
}
