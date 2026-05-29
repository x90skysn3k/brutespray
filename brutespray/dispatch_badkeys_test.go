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

func TestParseInlineCredsBasic(t *testing.T) {
	pairs := ParseInlineCreds("admin:admin,root:toor")
	if len(pairs) != 2 {
		t.Fatalf("got %d pairs, want 2: %+v", len(pairs), pairs)
	}
	if pairs[0].User != "admin" || pairs[0].Password != "admin" {
		t.Fatalf("pair[0]: %+v", pairs[0])
	}
	if pairs[1].User != "root" || pairs[1].Password != "toor" {
		t.Fatalf("pair[1]: %+v", pairs[1])
	}
}

func TestParseInlineCredsPasswordWithColon(t *testing.T) {
	pairs := ParseInlineCreds("user::pass:word")
	if len(pairs) != 1 {
		t.Fatalf("got %d, want 1", len(pairs))
	}
	if pairs[0].User != "user" || pairs[0].Password != ":pass:word" {
		t.Fatalf("colon-in-password not preserved: %+v", pairs[0])
	}
}

func TestParseInlineCredsEmpty(t *testing.T) {
	if got := ParseInlineCreds(""); got != nil {
		t.Fatalf("empty input should be nil, got %+v", got)
	}
}

func TestParseInlineCredsSkipsInvalidPair(t *testing.T) {
	pairs := ParseInlineCreds("admin:admin,notapair,root:toor")
	if len(pairs) != 2 {
		t.Fatalf("invalid middle pair should be skipped: got %d", len(pairs))
	}
}
