package brute

import (
	"testing"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func TestSNMPCommunitiesTiersIncreasing(t *testing.T) {
	def, err := modules.SNMPCommunities("default")
	if err != nil {
		t.Fatalf("default: %v", err)
	}
	ext, err := modules.SNMPCommunities("extended")
	if err != nil {
		t.Fatalf("extended: %v", err)
	}
	full, err := modules.SNMPCommunities("full")
	if err != nil {
		t.Fatalf("full: %v", err)
	}
	if !(len(def) > 0 && len(def) < len(ext) && len(ext) < len(full)) {
		t.Fatalf("tier sizes should strictly increase: default=%d extended=%d full=%d",
			len(def), len(ext), len(full))
	}
}

func TestSNMPCommunitiesUnknownTierFallback(t *testing.T) {
	got, err := modules.SNMPCommunities("nonsense")
	if err != nil {
		t.Fatalf("unknown tier should not error: %v", err)
	}
	def, _ := modules.SNMPCommunities("default")
	if len(got) != len(def) {
		t.Fatalf("unknown tier should match default size: got %d, default %d", len(got), len(def))
	}
}

func TestSNMPCommunitiesIncludesPublic(t *testing.T) {
	got, _ := modules.SNMPCommunities("default")
	for _, c := range got {
		if c == "public" {
			return
		}
	}
	t.Fatal("'public' should be in the default community list")
}
