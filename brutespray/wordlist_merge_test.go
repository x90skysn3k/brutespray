package brutespray

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile writes content to path under dir, creating parent directories.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestCmdMergeQualityGate(t *testing.T) {
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	// Minimal manifest: ssh passwords compose a base list plus an override file.
	writeFile(t, "wordlist/manifest.yaml", `bases:
  common_passwords: "_base/passwords-common.txt"
services:
  ssh:
    users:
      - overrides/ssh/user.txt
    passwords:
      - common_passwords
      - overrides/ssh/password.txt
`)
	writeFile(t, "wordlist/_base/passwords-common.txt", "admin\nroot\n")
	writeFile(t, "wordlist/overrides/ssh/password.txt", "existing1\n")

	candidates := []researchCandidate{
		// Rejected: already present in the base list.
		{Service: "ssh", Type: "password", Value: "admin", Product: "Cisco IOS", Source: "https://cisco.com"},
		// Rejected: already present in the override file.
		{Service: "ssh", Type: "password", Value: "existing1", Product: "Acme 1", Source: "https://acme.com"},
		// Rejected: placeholder junk.
		{Service: "ssh", Type: "password", Value: "none", Product: "Acme 2", Source: "https://acme.com"},
		// Rejected: low score (vague product, non-url source, plain value).
		{Service: "ssh", Type: "password", Value: "weakpass", Product: "router", Source: "docs"},
		// Rejected: missing source attribution.
		{Service: "ssh", Type: "password", Value: "Lonely9!", Product: "Acme 3", Source: ""},
		// Accepted: url source + specific product + complex value (score 4).
		{Service: "ssh", Type: "password", Value: "Cisco123!", Product: "Cisco IOS 15", Source: "https://cisco.com/docs"},
		// Accepted, but lower score — duplicate value, keep the higher one.
		{Service: "ssh", Type: "password", Value: "Cisco123!", Product: "Cisco", Source: "manual"},
	}
	data, _ := json.MarshalIndent(candidates, "", "  ")
	writeFile(t, filepath.Join("wordlist", "_candidates.json"), string(data))

	if err := cmdMerge(); err != nil {
		t.Fatalf("cmdMerge: %v", err)
	}

	got, err := os.ReadFile(filepath.Join("wordlist", "overrides", "ssh", "password.txt"))
	if err != nil {
		t.Fatal(err)
	}
	lines := map[string]int{}
	for _, l := range strings.Split(strings.TrimSpace(string(got)), "\n") {
		lines[l]++
	}

	if lines["Cisco123!"] != 1 {
		t.Errorf("expected Cisco123! added exactly once, got %d (file: %q)", lines["Cisco123!"], string(got))
	}
	// Pre-existing seed stays put and is not duplicated by a matching candidate.
	if lines["existing1"] != 1 {
		t.Errorf("expected existing1 to remain exactly once, got %d", lines["existing1"])
	}
	for _, rejected := range []string{"admin", "none", "weakpass", "Lonely9!"} {
		if lines[rejected] > 0 {
			t.Errorf("rejected candidate %q was merged", rejected)
		}
	}

	// The merge report should justify the single accepted entry.
	report, err := os.ReadFile(filepath.Join("wordlist", "_candidates_report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(report), "Cisco123!") {
		t.Errorf("report missing accepted entry, got:\n%s", report)
	}
}

func TestCmdMergeAppendsAfterMissingNewline(t *testing.T) {
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	writeFile(t, "wordlist/manifest.yaml", `services:
  ssh:
    passwords:
      - overrides/ssh/password.txt
`)
	writeFile(t, "wordlist/overrides/ssh/password.txt", "existing1")
	candidates := []researchCandidate{
		{Service: "ssh", Type: "password", Value: "Cisco123!", Product: "Cisco IOS 15", Source: "https://cisco.com/docs"},
	}
	data, _ := json.MarshalIndent(candidates, "", "  ")
	writeFile(t, filepath.Join("wordlist", "_candidates.json"), string(data))

	if err := cmdMerge(); err != nil {
		t.Fatalf("cmdMerge: %v", err)
	}

	got, err := os.ReadFile(filepath.Join("wordlist", "overrides", "ssh", "password.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "existing1\nCisco123!\n" {
		t.Fatalf("append should preserve line boundary, got %q", string(got))
	}
}

func TestCmdMergeNewOverrideIsIncludedInBuild(t *testing.T) {
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	writeFile(t, "wordlist/manifest.yaml", `bases:
  common_passwords: "_base/passwords-common.txt"
  seasonal_passwords: "_base/passwords-seasonal.txt"
  sysadmin_users: "_base/users-sysadmin.txt"
layers:
  os_infra: "_layers/passwords-os-infra.txt"
services:
  ssh:
    users: [sysadmin_users]
    passwords: [common_passwords, seasonal_passwords, os_infra]
`)
	writeFile(t, "wordlist/_base/users-sysadmin.txt", "root\n")
	writeFile(t, "wordlist/_base/passwords-common.txt", "admin\n")
	writeFile(t, "wordlist/_base/passwords-seasonal.txt", "Winter2030!\n")
	writeFile(t, "wordlist/_layers/passwords-os-infra.txt", "toor\n")
	candidates := []researchCandidate{
		{Service: "ssh", Type: "password", Value: "Cisco123!", Product: "Cisco IOS 15", Source: "https://cisco.com/docs"},
	}
	data, _ := json.MarshalIndent(candidates, "", "  ")
	writeFile(t, filepath.Join("wordlist", "_candidates.json"), string(data))

	if err := cmdMerge(); err != nil {
		t.Fatalf("cmdMerge: %v", err)
	}
	if err := cmdBuild(); err != nil {
		t.Fatalf("cmdBuild: %v", err)
	}

	built, err := os.ReadFile(filepath.Join("wordlist", "ssh", "password"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(built), "Cisco123!") {
		t.Fatalf("built ssh password wordlist missing merged candidate: %s", built)
	}
	manifest, err := os.ReadFile(filepath.Join("wordlist", "manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifest), "overrides/ssh/password.txt") {
		t.Fatalf("manifest missing new override ref: %s", manifest)
	}
}

func TestCmdMergeAlreadyPresentDoesNotAddMissingOverrideRef(t *testing.T) {
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	writeFile(t, "wordlist/manifest.yaml", `bases:
  common_passwords: "_base/passwords-common.txt"
services:
  ssh:
    passwords: [common_passwords]
`)
	writeFile(t, "wordlist/_base/passwords-common.txt", "Cisco123!\n")
	candidates := []researchCandidate{
		{Service: "ssh", Type: "password", Value: "Cisco123!", Product: "Cisco IOS 15", Source: "https://cisco.com/docs"},
	}
	data, _ := json.MarshalIndent(candidates, "", "  ")
	writeFile(t, filepath.Join("wordlist", "_candidates.json"), string(data))

	if err := cmdMerge(); err != nil {
		t.Fatalf("cmdMerge: %v", err)
	}
	if err := cmdValidate(); err != nil {
		t.Fatalf("cmdValidate after no-op merge: %v", err)
	}

	manifest, err := os.ReadFile(filepath.Join("wordlist", "manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(manifest), "overrides/ssh/password.txt") {
		t.Fatalf("manifest gained missing override ref after no-op merge: %s", manifest)
	}
	if _, err := os.Stat(filepath.Join("wordlist", "overrides", "ssh", "password.txt")); !os.IsNotExist(err) {
		t.Fatalf("no-op merge should not require override file, stat err=%v", err)
	}
	report, err := os.ReadFile(filepath.Join("wordlist", "_candidates_report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(report), "already present") {
		t.Fatalf("report should mark candidate already present: %s", report)
	}
}
