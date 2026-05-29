package tui

import (
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/brute"
)

// TestAttemptResultMsgCarriesKeyMatch verifies that KeyMatch round-trips
// through AttemptResultMsg so the TUI success view can render [+] BADKEY lines.
func TestAttemptResultMsgCarriesKeyMatch(t *testing.T) {
	km := &brute.KeyMatch{
		Fingerprint: "SHA256:xyzzy",
		Vendor:      "Cisco",
		CVE:         "CVE-2015-1338",
		Description: "Cisco default key",
	}

	msg := AttemptResultMsg{
		Host:      "192.0.2.1",
		Port:      22,
		Service:   "ssh",
		User:      "admin",
		Password:  "cisco",
		Success:   true,
		Connected: true,
		Duration:  100 * time.Millisecond,
		Timestamp: time.Now(),
		KeyMatch:  km,
	}

	if msg.KeyMatch == nil {
		t.Fatal("KeyMatch is nil, expected non-nil")
	}
	if msg.KeyMatch.CVE != "CVE-2015-1338" {
		t.Fatalf("KeyMatch.CVE = %q, want CVE-2015-1338", msg.KeyMatch.CVE)
	}
	if msg.KeyMatch.Vendor != "Cisco" {
		t.Fatalf("KeyMatch.Vendor = %q, want Cisco", msg.KeyMatch.Vendor)
	}
	if msg.KeyMatch.Fingerprint != "SHA256:xyzzy" {
		t.Fatalf("KeyMatch.Fingerprint = %q, want SHA256:xyzzy", msg.KeyMatch.Fingerprint)
	}
}

// TestAttemptResultMsgKeyMatchNilByDefault confirms that a zero-value
// AttemptResultMsg has a nil KeyMatch (normal credential attempts).
func TestAttemptResultMsgKeyMatchNilByDefault(t *testing.T) {
	var msg AttemptResultMsg
	if msg.KeyMatch != nil {
		t.Fatal("KeyMatch should be nil for a zero-value AttemptResultMsg")
	}
}
