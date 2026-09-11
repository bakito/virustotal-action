package badges

import (
	"strings"
	"testing"

	"github.com/bakito/virustotal-action/pkg/types"
)

func TestMakeBadge(t *testing.T) {
	tests := []struct {
		name        string
		scanID      string
		displayName string
		result      *types.ScanResult
		wantBadge   string
	}{
		{
			name:        "timed out scan",
			scanID:      "scan-123",
			displayName: "my-app.zip",
			result:      &types.ScanResult{TimedOut: true},
			wantBadge:   "[![VirusTotal - my-app.zip](https://img.shields.io/badge/VirusTotal-scan%20timed%20out-lightgrey?logo=virustotal&style=flat)](https://www.virustotal.com/gui/file-analysis/scan-123/detection)",
		},
		{
			name:        "nil result treated as timed out",
			scanID:      "scan-123",
			displayName: "my-app.zip",
			result:      nil,
			wantBadge:   "[![VirusTotal - my-app.zip](https://img.shields.io/badge/VirusTotal-scan%20timed%20out-lightgrey?logo=virustotal&style=flat)](https://www.virustotal.com/gui/file-analysis/scan-123/detection)",
		},
		{
			name:        "zero malicious - brightgreen",
			scanID:      "scan-456",
			displayName: "my-app.exe",
			result:      &types.ScanResult{Malicious: 0, Total: 72},
			wantBadge:   "[![VirusTotal - my-app.exe](https://img.shields.io/badge/VirusTotal-0%2F72+detected-brightgreen?logo=virustotal&style=flat)](https://www.virustotal.com/gui/file-analysis/scan-456/detection)",
		},
		{
			name:        "1-3 malicious - orange",
			scanID:      "scan-789",
			displayName: "my-app.exe",
			result:      &types.ScanResult{Malicious: 2, Total: 72},
			wantBadge:   "[![VirusTotal - my-app.exe](https://img.shields.io/badge/VirusTotal-2%2F72+detected-orange?logo=virustotal&style=flat)](https://www.virustotal.com/gui/file-analysis/scan-789/detection)",
		},
		{
			name:        "more than 3 malicious - red",
			scanID:      "scan-999",
			displayName: "my-app.exe",
			result:      &types.ScanResult{Malicious: 5, Total: 72},
			wantBadge:   "[![VirusTotal - my-app.exe](https://img.shields.io/badge/VirusTotal-5%2F72+detected-red?logo=virustotal&style=flat)](https://www.virustotal.com/gui/file-analysis/scan-999/detection)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MakeBadge(tt.scanID, tt.displayName, tt.result)
			if got != tt.wantBadge {
				t.Errorf("MakeBadge() = %v, want %v", got, tt.wantBadge)
			}
		})
	}
}

func TestMakeDateBadge(t *testing.T) {
	// 1710513000 = 2024-03-15 14:30:00 UTC
	got := MakeDateBadge(1710513000, "scan-abc")
	want := "[![Last Scan](https://img.shields.io/badge/Last%20Scan-2024--03--15%2014%3A30%20UTC-blue?logo=virustotal&style=flat)](https://www.virustotal.com/gui/file-analysis/scan-abc/detection)"
	if got != want {
		t.Errorf("MakeDateBadge() = %v, want %v", got, want)
	}
}

func TestGenerateReportTable(t *testing.T) {
	rows := []ResultRow{
		{
			ArchiveName:  "app.zip",
			BadgeArchive: "[badge1]",
			BadgeExe:     "[badge2]",
			LastScan:     "[date_badge]",
		},
	}
	got := GenerateReportTable(rows)
	want := "## 🦠 VirusTotal Report 🔎\n\n| File | Archive | Binary | Last Scan |\n|------|---------|--------|-----------|\n| app.zip | [badge1] | [badge2] | [date_badge] |\n"
	if got != want {
		t.Errorf("GenerateReportTable() = %v, want %v", got, want)
	}
}

func TestStripExistingReport(t *testing.T) {
	tests := []struct {
		name          string
		existingNotes string
		want          string
	}{
		{
			name:          "no existing report",
			existingNotes: "# Release 1.0.0\n\n- Feature A\n- Feature B",
			want:          "# Release 1.0.0\n\n- Feature A\n- Feature B",
		},
		{
			name:          "existing report present",
			existingNotes: "# Release 1.0.0\n\n- Feature A\n\n## 🦠 VirusTotal Report 🔎\n\n| File | Archive |\n|---|---|",
			want:          "# Release 1.0.0\n\n- Feature A",
		},
		{
			name:          "multiple existing reports takes last",
			existingNotes: "Note 1\n## 🦠 VirusTotal Report 🔎\nOld report\nNote 2\n## 🦠 VirusTotal Report 🔎\nNew report",
			want:          "Note 1\n## 🦠 VirusTotal Report 🔎\nOld report\nNote 2",
		},
		{
			name:          "empty notes",
			existingNotes: "",
			want:          "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StripExistingReport(tt.existingNotes)
			if got != tt.want {
				t.Errorf("StripExistingReport() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCombineReleaseNotes(t *testing.T) {
	table := "## 🦠 VirusTotal Report 🔎\n\n| File | Archive |\n|---|---|\n| a | b |"

	t.Run("empty existing", func(t *testing.T) {
		got := CombineReleaseNotes("", table)
		if got != table {
			t.Errorf("got %q, want %q", got, table)
		}
	})

	t.Run("non-empty existing", func(t *testing.T) {
		got := CombineReleaseNotes("Existing notes", table)
		want := "Existing notes\n\n" + table
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("existing with old report replaced", func(t *testing.T) {
		existing := "Initial note\n\n## 🦠 VirusTotal Report 🔎\n\nOld table"
		got := CombineReleaseNotes(existing, table)
		want := "Initial note\n\n" + table
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
		if strings.Contains(got, "Old table") {
			t.Error("expected old table to be stripped")
		}
	})
}
