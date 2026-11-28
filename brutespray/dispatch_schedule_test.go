package brutespray

import (
	"slices"
	"testing"
)

func TestCredentialPairsHostMajor(t *testing.T) {
	pairs := slices.Collect(credentialPairs([]string{"alice", "bob"}, []string{"p1", "p2"}, credentialOrderOptions{mode: "host-major"}))
	want := []credentialPair{{"alice", "p1"}, {"alice", "p2"}, {"bob", "p1"}, {"bob", "p2"}}
	assertCredentialPairs(t, pairs, want)
}

func TestCredentialPairsSpray(t *testing.T) {
	pairs := slices.Collect(credentialPairs([]string{"alice", "bob"}, []string{"p1", "p2"}, credentialOrderOptions{mode: "spray"}))
	want := []credentialPair{{"alice", "p1"}, {"bob", "p1"}, {"alice", "p2"}, {"bob", "p2"}}
	assertCredentialPairs(t, pairs, want)
}

func TestCredentialPairsPairwise(t *testing.T) {
	pairs := slices.Collect(credentialPairs([]string{"alice", "bob", "carol"}, []string{"p1", "p2"}, credentialOrderOptions{mode: "pairwise"}))
	want := []credentialPair{{"alice", "p1"}, {"bob", "p2"}}
	assertCredentialPairs(t, pairs, want)
}

func assertCredentialPairs(t *testing.T, got, want []credentialPair) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("pair[%d] = %#v, want %#v (all: %#v)", i, got[i], want[i], got)
		}
	}
}
