package brutespray

import (
	"fmt"
	"testing"

	"github.com/x90skysn3k/brutespray/v2/brute/badkeys"
)

func TestValidateRejectsContradictoryBadKeyFlags(t *testing.T) {
	cfg := &Config{NoBadKeys: true, BadKeysOnly: true, ServiceType: "all"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for --no-badkeys + --badkeys-only, got nil")
	}
}

func TestBuildBadKeyCredsProducesMarkers(t *testing.T) {
	bundle, err := badkeys.Load()
	if err != nil {
		t.Fatalf("badkeys.Load: %v", err)
	}
	pairs := BuildBadKeyCreds(bundle, "")
	if len(pairs) != len(bundle) {
		t.Fatalf("got %d pairs, want %d", len(pairs), len(bundle))
	}
	for i, p := range pairs {
		wantPass := fmt.Sprintf("::badkey::%d", i)
		if p.Password != wantPass {
			t.Fatalf("pair[%d].Password = %q, want %q", i, p.Password, wantPass)
		}
	}
}

func TestBuildBadKeyCredsRespectsExplicitUser(t *testing.T) {
	bundle, err := badkeys.Load()
	if err != nil {
		t.Fatalf("badkeys.Load: %v", err)
	}
	pairs := BuildBadKeyCreds(bundle, "admin")
	for _, p := range pairs {
		if p.User != "admin" {
			t.Fatalf("user override failed: %q", p.User)
		}
	}
}

func TestBuildBadKeyCredsUsesMetadataUserByDefault(t *testing.T) {
	bundle, err := badkeys.Load()
	if err != nil {
		t.Fatalf("badkeys.Load: %v", err)
	}
	pairs := BuildBadKeyCreds(bundle, "")
	// Find the Vagrant entry and confirm its pair uses "vagrant" as user
	for i, e := range bundle {
		if e.Vendor == "HashiCorp Vagrant" {
			if pairs[i].User != "vagrant" {
				t.Fatalf("vagrant default user not preserved: got %q", pairs[i].User)
			}
			return
		}
	}
	t.Fatal("no Vagrant entry in bundle")
}
