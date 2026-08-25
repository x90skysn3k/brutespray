package modules

import (
	"strings"
	"testing"
)

func TestRedactSecret(t *testing.T) {
	if got := RedactSecret("P@ssw0rd!"); got != "[REDACTED]" {
		t.Fatalf("RedactSecret = %q, want [REDACTED]", got)
	}
	if got := RedactSecret(""); got != "" {
		t.Fatalf("empty secret redaction = %q, want empty", got)
	}
}

func TestCredentialHMACIsStableAndDoesNotLeakSecret(t *testing.T) {
	key := []byte("engagement-key")
	secret := "P@ssw0rd!"
	first := CredentialHMAC(key, secret)
	second := CredentialHMAC(key, secret)
	if first == "" {
		t.Fatal("empty HMAC")
	}
	if first != second {
		t.Fatalf("HMAC not stable: %q != %q", first, second)
	}
	if first == secret || strings.Contains(first, secret) {
		t.Fatalf("HMAC leaks secret: %q", first)
	}
}

func TestEvidenceModeValidate(t *testing.T) {
	for _, mode := range []EvidenceMode{EvidenceRedacted, EvidenceHash, EvidenceFull, EvidenceEncrypted} {
		if err := mode.Validate(); err != nil {
			t.Fatalf("%s should validate: %v", mode, err)
		}
	}
	if err := EvidenceMode("invalid").Validate(); err == nil {
		t.Fatal("invalid evidence mode should fail")
	}
}

func TestEvidenceConfigRenderSecret(t *testing.T) {
	cfg := EvidenceConfig{Mode: EvidenceHash, HMACKey: []byte("engagement-key")}
	display, digest, redacted := cfg.RenderSecret("secret")
	if display != "[REDACTED]" {
		t.Fatalf("display = %q, want redacted", display)
	}
	if digest == "" {
		t.Fatal("hash mode should return digest")
	}
	if !redacted {
		t.Fatal("hash mode should mark secret redacted")
	}

	cfg = EvidenceConfig{Mode: EvidenceFull}
	display, digest, redacted = cfg.RenderSecret("secret")
	if display != "secret" || digest != "" || redacted {
		t.Fatalf("full mode display=%q digest=%q redacted=%v", display, digest, redacted)
	}
}
