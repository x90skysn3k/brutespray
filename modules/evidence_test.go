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

	for _, mode := range []EvidenceMode{"invalid", "bogus"} {
		if err := mode.Validate(); err == nil {
			t.Fatalf("%s evidence mode should fail", mode)
		}
	}
}

func TestEvidenceConfigRenderSecret(t *testing.T) {
	tests := []struct {
		name         string
		cfg          EvidenceConfig
		wantDisplay  string
		wantDigest   bool
		wantRedacted bool
	}{
		{
			name:         "hash mode redacts display and returns digest",
			cfg:          EvidenceConfig{Mode: EvidenceHash, HMACKey: []byte("engagement-key")},
			wantDisplay:  "[REDACTED]",
			wantDigest:   true,
			wantRedacted: true,
		},
		{
			name:        "full mode keeps secret for compatibility",
			cfg:         EvidenceConfig{Mode: EvidenceFull},
			wantDisplay: "secret",
		},
		{
			name:        "empty mode defaults to full for compatibility",
			cfg:         EvidenceConfig{Mode: ""},
			wantDisplay: "secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			display, digest, redacted := tt.cfg.RenderSecret("secret")
			if display != tt.wantDisplay {
				t.Fatalf("display = %q, want %q", display, tt.wantDisplay)
			}
			if (digest != "") != tt.wantDigest {
				t.Fatalf("digest presence = %v, want %v (digest=%q)", digest != "", tt.wantDigest, digest)
			}
			if redacted != tt.wantRedacted {
				t.Fatalf("redacted = %v, want %v", redacted, tt.wantRedacted)
			}
		})
	}
}
