package modules

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

func captureStdoutModules(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

func TestWriteFindingTextMode(t *testing.T) {
	OutputFormatMode = "text"
	NoColorMode = true
	defer func() { NoColorMode = false }()
	out := captureStdoutModules(func() {
		WriteFinding("WARN", "rdp-nla-missing", "rdp", "10.0.0.5", 3389, "NLA not enforced", "")
	})
	for _, want := range []string{"WARN", "rdp", "10.0.0.5:3389", "NLA not enforced"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q: %s", want, out)
		}
	}
}

func TestWriteFindingJSONMode(t *testing.T) {
	OutputFormatMode = "json"
	defer func() { OutputFormatMode = "text" }()
	out := captureStdoutModules(func() {
		WriteFinding("CRITICAL", "rdp-stickykeys", "rdp", "10.0.0.5", 3389, "backdoor", "")
	})
	var got struct {
		Type, Severity, Code, Service, Target string
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if got.Type != "finding" || got.Severity != "CRITICAL" || got.Code != "rdp-stickykeys" {
		t.Fatalf("wrong fields: %+v", got)
	}
	if got.Target != "10.0.0.5:3389" {
		t.Fatalf("target = %q", got.Target)
	}
}

func TestWriteFindingIncludesCVE(t *testing.T) {
	OutputFormatMode = "json"
	defer func() { OutputFormatMode = "text" }()
	out := captureStdoutModules(func() {
		WriteFinding("INFO", "ssh-badkey", "ssh", "10.0.0.5", 22, "F5 key", "CVE-2012-1493")
	})
	if !strings.Contains(out, "CVE-2012-1493") {
		t.Fatalf("CVE missing: %s", out)
	}
}

func TestPrintBadKeyResultJSON(t *testing.T) {
	OutputFormatMode = "json"
	defer func() { OutputFormatMode = "text" }()
	out := captureStdoutModules(func() {
		PrintBadKeyResult("ssh", "10.0.0.5", 22, "vagrant",
			"HashiCorp Vagrant", "", "Vagrant insecure default key")
	})
	var got struct {
		Type, Vendor string
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if got.Type != "badkey" || got.Vendor != "HashiCorp Vagrant" {
		t.Fatalf("wrong fields: %+v", got)
	}
}
