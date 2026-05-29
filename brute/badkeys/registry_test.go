package badkeys

import (
	"encoding/hex"
	"testing"
)

func TestLoadReturnsNonEmptyBundle(t *testing.T) {
	bundle, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(bundle) != 9 {
		t.Fatalf("expected 9 keys, got %d", len(bundle))
	}
}

func TestLoadParsesVagrantEntry(t *testing.T) {
	bundle, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, e := range bundle {
		if e.Vendor == "HashiCorp Vagrant" {
			if e.Username != "vagrant" {
				t.Fatalf("vagrant entry username = %q, want vagrant", e.Username)
			}
			if len(e.PEM) < 100 {
				t.Fatalf("vagrant PEM too short: %d bytes", len(e.PEM))
			}
			return
		}
	}
	t.Fatal("no Vagrant entry found in bundle")
}

func TestPEMHashIsHexSHA256(t *testing.T) {
	bundle, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, e := range bundle {
		if e.PEMHash == "" {
			t.Errorf("entry %q has empty PEMHash", e.File)
			continue
		}
		if len(e.PEMHash) != 64 {
			t.Errorf("entry %q PEMHash length = %d, want 64", e.File, len(e.PEMHash))
			continue
		}
		b, err := hex.DecodeString(e.PEMHash)
		if err != nil || len(b) != 32 {
			t.Errorf("entry %q PEMHash %q is not valid lowercase hex SHA-256", e.File, e.PEMHash)
		}
	}
}

func TestLoadIsDeterministic(t *testing.T) {
	first, err := Load()
	if err != nil {
		t.Fatalf("Load (first): %v", err)
	}
	second, err := Load()
	if err != nil {
		t.Fatalf("Load (second): %v", err)
	}
	if len(first) != len(second) {
		t.Fatalf("non-deterministic length: first=%d second=%d", len(first), len(second))
	}
	for i := range first {
		if first[i].PEMHash != second[i].PEMHash {
			t.Errorf("entry %d (%s): PEMHash differs between calls: %q vs %q",
				i, first[i].File, first[i].PEMHash, second[i].PEMHash)
		}
		if first[i].File != second[i].File {
			t.Errorf("entry %d: File differs: %q vs %q", i, first[i].File, second[i].File)
		}
	}
}
