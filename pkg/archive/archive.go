package archive

import (
	"cmp"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/mholt/archiver/v3"

	"github.com/bakito/virustotal-action/pkg/types"
)

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
		filePath := filepath.Join(assetsDir, entry.Name())
		targetDir := filepath.Join(extractedDir, entry.Name())

		u, err := archiver.ByExtension(filePath)
		if err != nil {
			// Not a recognized archive extension; skip extraction
			continue
		}
		unarchiver, ok := u.(archiver.Unarchiver)
		if !ok {
			continue
		}

		if err := os.MkdirAll(targetDir, 0o755); err != nil {
			return fmt.Errorf("failed to create target dir %s: %w", targetDir, err)
		}

		if err := unarchiver.Unarchive(filePath, targetDir); err != nil {
			return fmt.Errorf("failed to extract %s: %w", filePath, err)
		}
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
