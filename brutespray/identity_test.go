package brutespray

import "testing"

func TestAttemptIdentityNormalizesDomainUser(t *testing.T) {
	id := NewAttemptIdentity("smbnt", "CORP", `CORP\Alice`)
	if id.Key() != "smbnt|corp|alice" {
		t.Fatalf("key = %q", id.Key())
	}
}

func TestAttemptIdentityUsesConfigDomain(t *testing.T) {
	id := NewAttemptIdentity("rdp", "CORP", "Alice")
	if id.Key() != "rdp|corp|alice" {
		t.Fatalf("key = %q", id.Key())
	}
}

func TestAttemptIdentityTrimsCase(t *testing.T) {
	id := NewAttemptIdentity(" SSH ", "", " Root ")
	if id.Key() != "ssh||root" {
		t.Fatalf("key = %q", id.Key())
	}
}
