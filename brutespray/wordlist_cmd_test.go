package brutespray

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsJunkValue(t *testing.T) {
	junk := []string{
		"", " ", "x", "<password>", "<USERNAME>", "username", "Password",
		"none", "N/A", "redacted", "***", "unknown", "default",
		"has space", "tab\tinside", strings.Repeat("a", 65), "your_password",
	}
	for _, v := range junk {
		if !isJunkValue(v) {
			t.Errorf("isJunkValue(%q) = false, want true", v)
		}
	}

	valid := []string{
		"admin", "root", "Cisco123", "P@ssw0rd!", "ubnt", "raspberry",
		"sap*", "default123", "Wg@2026", "manager",
	}
	for _, v := range valid {
		if isJunkValue(v) {
			t.Errorf("isJunkValue(%q) = true, want false", v)
		}
	}
}

func TestLooksComplex(t *testing.T) {
	complex := []string{"Cisco123", "P@ssw0rd", "Admin1", "ubnt2026", "sap*"}
	for _, v := range complex {
		if !looksComplex(v) {
			t.Errorf("looksComplex(%q) = false, want true", v)
		}
	}
	simple := []string{"admin", "root", "password", "ADMIN", "123456"}
	for _, v := range simple {
		if looksComplex(v) {
			t.Errorf("looksComplex(%q) = true, want false", v)
		}
	}
}

func TestScoreCandidate(t *testing.T) {
	tests := []struct {
		name string
		c    researchCandidate
		want int
	}{
		{
			name: "url source + specific product + complex value",
			c:    researchCandidate{Value: "Cisco123", Product: "Cisco IOS 15", Source: "https://cisco.com/docs"},
			want: 4, // +2 url, +1 product, +1 complex
		},
		{
			name: "url source + plain value + vague product",
			c:    researchCandidate{Value: "admin", Product: "router", Source: "https://example.com"},
			want: 2, // +2 url only
		},
		{
			name: "non-url source + specific product",
			c:    researchCandidate{Value: "admin", Product: "Dahua DVR", Source: "vendor manual"},
			want: 2, // +1 source, +1 product
		},
		{
			name: "breach source penalised below threshold",
			c:    researchCandidate{Value: "Hunter2!", Product: "Acme 9000", Source: "https://pastebin.com/leak dump"},
			want: 1, // +2 url +1 product +1 complex -3 disallowed = 1 (< threshold)
		},
		{
			name: "bare value no attribution",
			c:    researchCandidate{Value: "admin", Product: "", Source: ""},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scoreCandidate(tt.c); got != tt.want {
				t.Errorf("scoreCandidate(%+v) = %d, want %d", tt.c, got, tt.want)
			}
		})
	}
}

// TestScoreThresholdGate documents the effective admission rule: a candidate
// needs a real URL source plus one more signal, OR a non-URL source with both a
// specific product and a complex value, to reach mergeScoreThreshold.
func TestScoreThresholdGate(t *testing.T) {
	pass := researchCandidate{Value: "Cisco123", Product: "Cisco IOS", Source: "https://cisco.com/docs"}
	if scoreCandidate(pass) < mergeScoreThreshold {
		t.Errorf("well-sourced candidate scored %d, below threshold %d", scoreCandidate(pass), mergeScoreThreshold)
	}
	fail := researchCandidate{Value: "admin", Product: "router", Source: "vendor docs"}
	if scoreCandidate(fail) >= mergeScoreThreshold {
		t.Errorf("weak candidate scored %d, at/above threshold %d", scoreCandidate(fail), mergeScoreThreshold)
	}
}

func TestCmdSeasonalGuaranteesPatterns(t *testing.T) {
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	if err := cmdSeasonal(); err != nil {
		t.Fatalf("cmdSeasonal: %v", err)
	}

	data, err := os.ReadFile(filepath.Join("wordlist", "_base", "passwords-seasonal.txt"))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	got := make(map[string]struct{})
	for _, line := range strings.Split(string(data), "\n") {
		got[line] = struct{}{}
	}

	// Year-less corp-word variants are always present regardless of the year.
	for _, want := range []string{"Welcome1", "Welcome123", "Welcome123!", "Password123!", "Changeme123!"} {
		if _, ok := got[want]; !ok {
			t.Errorf("seasonal output missing guaranteed pattern %q", want)
		}
	}
}

func TestCmdSeasonalUsesManifestRange(t *testing.T) {
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	writeFile(t, filepath.Join("wordlist", "manifest.yaml"), `seasonal_range: [2030, 2030]
bases:
  seasonal_passwords: "_base/passwords-seasonal.txt"
services: {}
`)

	if err := cmdSeasonal(); err != nil {
		t.Fatalf("cmdSeasonal: %v", err)
	}

	data, err := os.ReadFile(filepath.Join("wordlist", "_base", "passwords-seasonal.txt"))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	if !strings.Contains(string(data), "Winter2030!") || !strings.Contains(string(data), "January2030!") {
		t.Fatalf("seasonal output did not use manifest range 2030: %s", data)
	}
}

func TestCmdSeasonalRejectsMalformedManifest(t *testing.T) {
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	writeFile(t, filepath.Join("wordlist", "manifest.yaml"), `seasonal_range: [`)

	if err := cmdSeasonal(); err == nil {
		t.Fatal("cmdSeasonal succeeded with malformed manifest, want error")
	}
}

func TestCmdValidateRejectsCircularAliases(t *testing.T) {
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	writeFile(t, filepath.Join("wordlist", "manifest.yaml"), `services:
  ssh:
    alias: telnet
  telnet:
    alias: ssh
`)

	if err := cmdValidate(); err == nil {
		t.Fatal("cmdValidate succeeded with circular aliases, want error")
	}
}
