package tui

import (
	"strings"
	"testing"
	"time"
)

func TestViewFindingsEmptyState(t *testing.T) {
	m := Model{}
	out := m.viewFindings()
	if !strings.Contains(out, "No findings") {
		t.Fatalf("expected empty-state placeholder, got: %s", out)
	}
}

func TestViewFindingsRendersEntries(t *testing.T) {
	m := Model{
		findings: []FindingEntry{
			{Severity: "WARN", Service: "rdp", Target: "10.0.0.5:3389", Message: "NLA not enforced", Time: time.Now()},
			{Severity: "CRITICAL", Service: "rdp", Target: "10.0.0.5:3389", Message: "sticky-keys backdoor", CVE: "", Time: time.Now()},
		},
	}
	out := m.viewFindings()
	for _, want := range []string{"WARN", "rdp", "10.0.0.5:3389", "NLA not enforced", "CRITICAL", "sticky-keys backdoor"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q: %s", want, out)
		}
	}
}

func TestViewFindingsRendersCVE(t *testing.T) {
	m := Model{
		findings: []FindingEntry{
			{Severity: "INFO", Service: "ssh", Target: "10.0.0.5:22", Message: "F5 bad key", CVE: "CVE-2012-1493", Time: time.Now()},
		},
	}
	out := m.viewFindings()
	if !strings.Contains(out, "CVE-2012-1493") {
		t.Fatalf("output missing CVE: %s", out)
	}
}

func TestAddFindingThroughUpdate(t *testing.T) {
	m := Model{}
	updated, _ := m.Update(FindingMsg{Entry: FindingEntry{Severity: "INFO", Service: "ssh", Target: "10.0.0.5:22", Message: "test"}})
	final := updated.(Model)
	if len(final.findings) != 1 {
		t.Fatalf("findings len = %d, want 1", len(final.findings))
	}
	if final.findings[0].Severity != "INFO" {
		t.Fatalf("severity = %q", final.findings[0].Severity)
	}
}
