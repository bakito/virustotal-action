package badges

import (
	"fmt"
	"strings"
	"time"

	"github.com/bakito/virustotal-action/pkg/types"
)

const (
	// VTHeading is the markdown section heading used for the VirusTotal report.
	VTHeading = "## 🦠 VirusTotal Report 🔎"
)

// MakeBadge returns a markdown badge for a scan result.
func MakeBadge(scanID, displayName string, result *types.ScanResult) string {
	vtURL := fmt.Sprintf("https://www.virustotal.com/gui/file-analysis/%s/detection", scanID)
	if result == nil || result.TimedOut {
		badgeURL := "https://img.shields.io/badge/VirusTotal-scan%20timed%20out-lightgrey?logo=virustotal&style=flat"
		return fmt.Sprintf("[![VirusTotal - %s](%s)](%s)", displayName, badgeURL, vtURL)
	}

	color := "red"
	if result.Malicious == 0 {
		color = "brightgreen"
	} else if result.Malicious <= 3 {
		color = "orange"
	}

	label := fmt.Sprintf("%d%%2F%d+detected", result.Malicious, result.Total)
	badgeURL := fmt.Sprintf("https://img.shields.io/badge/VirusTotal-%s-%s?logo=virustotal&style=flat", label, color)
	return fmt.Sprintf("[![VirusTotal - %s](%s)](%s)", displayName, badgeURL, vtURL)
}

// MakeDateBadge returns a markdown badge for a scan timestamp.
func MakeDateBadge(timestamp int64, scanID string) string {
	t := time.Unix(timestamp, 0).UTC()
	formattedDate := t.Format("2006-01-02 15:04 MST")

	encodedDate := strings.ReplaceAll(formattedDate, "-", "--")
	encodedDate = strings.ReplaceAll(encodedDate, " ", "%20")
	encodedDate = strings.ReplaceAll(encodedDate, ":", "%3A")

	vtURL := fmt.Sprintf("https://www.virustotal.com/gui/file-analysis/%s/detection", scanID)
	badgeURL := fmt.Sprintf("https://img.shields.io/badge/Last%%20Scan-%s-blue?logo=virustotal&style=flat", encodedDate)
	return fmt.Sprintf("[![Last Scan](%s)](%s)", badgeURL, vtURL)
}

// ResultRow represents a row in the VirusTotal report table.
type ResultRow struct {
	ArchiveName  string
	BadgeArchive string
	BadgeExe     string
	LastScan     string
}

// GenerateReportTable formats the report rows into markdown table.
func GenerateReportTable(rows []ResultRow) string {
	var sb strings.Builder
	sb.WriteString(VTHeading)
	sb.WriteString("\n\n")
	sb.WriteString("| File | Archive | Binary | Last Scan |\n")
	sb.WriteString("|------|---------|--------|-----------|\n")
	for _, row := range rows {
		fmt.Fprintf(&sb, "| %s | %s | %s | %s |\n", row.ArchiveName, row.BadgeArchive, row.BadgeExe, row.LastScan)
	}
	return sb.String()
}

// StripExistingReport removes any existing VirusTotal report section from release notes.
// On a rerun, strips everything from the last VT heading to end-of-file.
func StripExistingReport(existingNotes string) string {
	lines := strings.Split(existingNotes, "\n")
	lastHeadingLine := -1
	for i, line := range lines {
		if strings.Contains(line, VTHeading) {
			lastHeadingLine = i
		}
	}

	if lastHeadingLine >= 0 {
		lines = lines[:lastHeadingLine]
	}

	return strings.TrimRight(strings.Join(lines, "\n"), "\r\n")
}

// CombineReleaseNotes combines stripped existing notes with the new VirusTotal report table.
func CombineReleaseNotes(existingNotes, reportTable string) string {
	stripped := StripExistingReport(existingNotes)
	if stripped == "" {
		return reportTable
	}
	return stripped + "\n\n" + reportTable
}
