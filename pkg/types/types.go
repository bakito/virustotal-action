package types

import "time"

// Config contains all configuration options for the action.
type Config struct {
	ReleaseName                    string
	VTApiKey                       string
	DownloadReleaseArtifactPattern string
	BinaryPattern                  string
	PollInterval                   time.Duration
	PollMaxAttempts                int
	GitHubToken                    string
	GitHubRepository               string
	AssetsDir                      string
	ExtractedDir                   string
}

// ScanResult holds the polling results for a single scan.
type ScanResult struct {
	ScanID    string
	Malicious int64
	Total     int64
	Date      int64
	TimedOut  bool
}

// IsSuccess returns true if scan completed with 0 malicious detections.
func (r *ScanResult) IsSuccess() bool {
	return !r.TimedOut && r.Malicious == 0
}

// ScannedItem represents an archive and its contained executable.
type ScannedItem struct {
	ArchiveName   string
	ExeName       string
	ScanIDArchive string
	ScanIDExe     string
}

// BinaryTarget represents a discovered binary inside an extracted archive.
type BinaryTarget struct {
	ArchiveName string
	ArchiveFile string
	ExeName     string
	ExeFile     string
}
