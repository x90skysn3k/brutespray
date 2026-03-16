package brute

import (
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// TestSMBPassHashParam verifies that when params["pass"]="HASH" and the
// password is a valid 32-character hex string, BruteSMB doesn't panic.
// The actual SMB connection will fail since there's no server, but the
// hex parsing logic should not crash.
func TestSMBPassHashParam(t *testing.T) {
	cm, _ := modules.NewConnectionManager("", 2*time.Second, "")

	// 32-char hex string = 16 bytes, valid NTLM hash
	hash := "aabbccdd11223344aabbccdd11223344"

	// This should not panic — the connection will fail because there is no
	// SMB server, but the pass-the-hash parsing should work correctly.
	result := BruteSMB("127.0.0.1", 1, "admin", hash, 2*time.Second, cm, ModuleParams{
		"pass":   "HASH",
		"domain": "TESTDOMAIN",
	})

	if result.AuthSuccess {
		t.Fatal("expected auth failure (no server)")
	}
	// Connection should fail since nothing is listening on port 1
	// (or it may return ConnectionSuccess=true with AuthSuccess=false
	// if the module treats it as a connection-level failure)
	_ = result.ConnectionSuccess
}

// TestSMBPassHashInvalidHex verifies that an invalid hex string doesn't crash.
func TestSMBPassHashInvalidHex(t *testing.T) {
	cm, _ := modules.NewConnectionManager("", 2*time.Second, "")

	// Not valid hex — should be treated as a regular password
	result := BruteSMB("127.0.0.1", 1, "admin", "not-a-valid-hex", 2*time.Second, cm, ModuleParams{
		"pass": "HASH",
	})

	if result.AuthSuccess {
		t.Fatal("expected auth failure (no server)")
	}
}

// TestSMBPassHashTooShort verifies that a short hex string doesn't crash.
func TestSMBPassHashTooShort(t *testing.T) {
	cm, _ := modules.NewConnectionManager("", 2*time.Second, "")

	// Valid hex but not 32 chars (16 bytes) — should be treated as regular password
	result := BruteSMB("127.0.0.1", 1, "admin", "aabb", 2*time.Second, cm, ModuleParams{
		"pass": "HASH",
	})

	if result.AuthSuccess {
		t.Fatal("expected auth failure (no server)")
	}
}
