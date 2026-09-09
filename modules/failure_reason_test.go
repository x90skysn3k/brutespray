package modules

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

func TestAttemptFailureReason(t *testing.T) {
	tests := []struct {
		name       string
		statusCode string
		success    bool
		connected  bool
		want       string
	}{
		{name: "authentication failure", statusCode: "auth_failure", connected: true, want: "Authentication rejected by target"},
		{name: "connection failure", statusCode: "connection_failure", want: "Unable to establish connection"},
		{name: "unsupported service", statusCode: "unsupported_service", want: "Service is not supported by BruteSpray"},
		{name: "skipped service", statusCode: "skipped_service", want: "Attempt skipped"},
		{name: "module timeout", statusCode: "module_timeout", want: "Protocol module timed out"},
		{name: "recovered module panic", statusCode: "module_panic_recovered", want: "Protocol module encountered an internal error"},
		{name: "success", statusCode: "auth_success", success: true, connected: true, want: ""},
		{name: "legacy connected failure fallback", connected: true, want: "Authentication rejected by target"},
		{name: "legacy connection failure fallback", want: "Unable to establish connection"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := attemptFailureReason(tt.statusCode, tt.success, tt.connected); got != tt.want {
				t.Fatalf("attemptFailureReason(%q, %t, %t) = %q, want %q", tt.statusCode, tt.success, tt.connected, got, tt.want)
			}
		})
	}
}

func captureAttemptOutput(t *testing.T, format string, fn func()) string {
	t.Helper()

	origFormat := OutputFormatMode
	origSilent := Silent
	origTUI := TUIMode
	origNoColor := NoColorMode
	defer func() {
		OutputFormatMode = origFormat
		Silent = origSilent
		TUIMode = origTUI
		NoColorMode = origNoColor
	}()

	OutputFormatMode = format
	Silent = false
	TUIMode = false
	NoColorMode = true

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()

	fn()

	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return strings.TrimSpace(buf.String())
}

func TestPrintResultJSONIncludesFailureReason(t *testing.T) {
	output := captureAttemptOutput(t, "json", func() {
		PrintResultWithStatus("ssh", "10.0.0.1", 22, "root", "test-secret", false, true, false, t.TempDir(), 0, "auth_failure")
	})

	var attempt AttemptResult
	if err := json.Unmarshal([]byte(output), &attempt); err != nil {
		t.Fatalf("invalid JSON output: %v\nraw: %s", err, output)
	}
	if attempt.FailureReason != "Authentication rejected by target" {
		t.Fatalf("failure_reason = %q", attempt.FailureReason)
	}
	if attempt.StatusCode != "auth_failure" {
		t.Fatalf("status_code = %q, want auth_failure", attempt.StatusCode)
	}
}

func TestPrintResultJSONOmitsFailureReasonForSuccess(t *testing.T) {
	output := captureAttemptOutput(t, "json", func() {
		PrintResultWithStatusAndProof("ssh", "10.0.0.1", 22, "root", "test-secret", true, true, false, t.TempDir(), 0, "auth_success", "confirmed", "auth_protocol_success", "ssh module result")
	})

	if strings.Contains(output, `"failure_reason"`) {
		t.Fatalf("success JSON unexpectedly contains failure_reason: %s", output)
	}

	var attempt AttemptResult
	if err := json.Unmarshal([]byte(output), &attempt); err != nil {
		t.Fatalf("invalid JSON output: %v\nraw: %s", err, output)
	}
	if attempt.FailureReason != "" {
		t.Fatalf("success failure_reason = %q, want empty", attempt.FailureReason)
	}
	if attempt.Confidence != "confirmed" || attempt.ProofType != "auth_protocol_success" {
		t.Fatalf("proof metadata changed unexpectedly: %+v", attempt)
	}
}

func TestPrintResultTextIncludesFailureReason(t *testing.T) {
	output := captureAttemptOutput(t, "text", func() {
		PrintResultWithStatus("ssh", "10.0.0.1", 22, "root", "test-secret", false, true, false, t.TempDir(), 0, "auth_failure")
	})

	if !strings.Contains(output, "FAILED (Authentication rejected by target)") {
		t.Fatalf("readable failure reason missing from text output: %s", output)
	}
}

func TestFailureReasonNeverContainsCredentialMaterial(t *testing.T) {
	const user = "credential-user-7f4b"
	const password = "credential-password-a91e"

	reason := attemptFailureReason("module_panic_recovered", false, false)
	if strings.Contains(reason, user) || strings.Contains(reason, password) {
		t.Fatalf("failure reason leaked credential material: %q", reason)
	}
}
