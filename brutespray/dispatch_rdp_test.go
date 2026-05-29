package brutespray

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/x90skysn3k/brutespray/v2/brute"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

func captureStdoutDispatch(fn func()) string {
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

func TestEmitFindingFormat(t *testing.T) {
	modules.NoColorMode = true
	defer func() { modules.NoColorMode = false }()

	h := modules.Host{Service: "rdp", Host: "10.0.0.5", Port: 3389}
	f := &brute.Finding{Severity: "WARN", Code: "rdp-nla-missing", Message: "NLA not enforced"}
	out := captureStdoutDispatch(func() { emitFinding(h, f) })
	for _, want := range []string{"WARN", "rdp", "10.0.0.5:3389", "NLA not enforced"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q: %s", want, out)
		}
	}
}

func TestEmitFindingIncludesCVE(t *testing.T) {
	modules.NoColorMode = true
	defer func() { modules.NoColorMode = false }()

	h := modules.Host{Service: "ssh", Host: "10.0.0.5", Port: 22}
	f := &brute.Finding{Severity: "HIGH", Code: "ssh-badkey", Message: "F5 default key", CVE: "CVE-2012-1493"}
	out := captureStdoutDispatch(func() { emitFinding(h, f) })
	if !strings.Contains(out, "CVE-2012-1493") {
		t.Fatalf("CVE missing from output: %s", out)
	}
}
