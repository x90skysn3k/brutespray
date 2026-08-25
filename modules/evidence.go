package modules

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
)

// EvidenceMode controls how credential material appears in outputs.
type EvidenceMode string

const (
	EvidenceRedacted  EvidenceMode = "redacted"
	EvidenceHash      EvidenceMode = "hash"
	EvidenceFull      EvidenceMode = "full"
	EvidenceEncrypted EvidenceMode = "encrypted"
)

// Validate rejects unknown evidence modes before execution starts.
func (m EvidenceMode) Validate() error {
	switch m {
	case EvidenceRedacted, EvidenceHash, EvidenceFull, EvidenceEncrypted:
		return nil
	default:
		return fmt.Errorf("invalid evidence mode %q", m)
	}
}

// EvidenceConfig controls secret rendering for output paths.
type EvidenceConfig struct {
	Mode    EvidenceMode
	HMACKey []byte
}

var evidenceState = struct {
	mu     sync.RWMutex
	config EvidenceConfig
}{
	config: EvidenceConfig{Mode: EvidenceFull},
}

// SetEvidenceConfig updates the package-wide output evidence settings.
func SetEvidenceConfig(cfg EvidenceConfig) {
	if cfg.Mode == "" {
		cfg.Mode = EvidenceFull
	}
	keyCopy := append([]byte(nil), cfg.HMACKey...)
	cfg.HMACKey = keyCopy
	evidenceState.mu.Lock()
	evidenceState.config = cfg
	evidenceState.mu.Unlock()
}

// GetEvidenceConfig returns a copy of the package-wide evidence settings.
func GetEvidenceConfig() EvidenceConfig {
	evidenceState.mu.RLock()
	cfg := evidenceState.config
	evidenceState.mu.RUnlock()
	cfg.HMACKey = append([]byte(nil), cfg.HMACKey...)
	return cfg
}

// RedactSecret replaces non-empty secrets with a stable redaction marker.
func RedactSecret(secret string) string {
	if secret == "" {
		return ""
	}
	return "[REDACTED]"
}

// CredentialHMAC returns a keyed digest suitable for correlation without disclosure.
func CredentialHMAC(key []byte, secret string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(secret))
	return hex.EncodeToString(mac.Sum(nil))
}

// RenderSecret returns the display value, optional digest, and whether the display value is redacted.
func (cfg EvidenceConfig) RenderSecret(secret string) (display string, digest string, redacted bool) {
	mode := cfg.Mode
	if mode == "" {
		mode = EvidenceFull
	}
	switch mode {
	case EvidenceFull:
		return secret, "", false
	case EvidenceHash:
		return RedactSecret(secret), CredentialHMAC(cfg.HMACKey, secret), secret != ""
	case EvidenceRedacted, EvidenceEncrypted:
		return RedactSecret(secret), "", secret != ""
	default:
		return RedactSecret(secret), "", secret != ""
	}
}
