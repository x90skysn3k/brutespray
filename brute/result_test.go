package brute

import "testing"

func TestBruteResultCarriesFinding(t *testing.T) {
	// shows Finding can coexist with non-auth result
	r := &BruteResult{
		ConnectionSuccess: true,
		Finding: &Finding{
			Severity: "CRITICAL",
			Code:     "rdp-stickykeys",
			Message:  "sticky-keys backdoor detected",
		},
	}
	if r.Finding == nil || r.Finding.Code != "rdp-stickykeys" {
		t.Fatalf("Finding not carried on BruteResult")
	}
}

func TestBruteResultCarriesKeyMatch(t *testing.T) {
	// success path: KeyMatch + AuthSuccess together
	r := &BruteResult{
		AuthSuccess:       true,
		ConnectionSuccess: true,
		KeyMatch: &KeyMatch{
			Fingerprint: "SHA256:abc",
			Vendor:      "Vagrant",
			CVE:         "CVE-2015-1338",
		},
	}
	if r.KeyMatch == nil || r.KeyMatch.Vendor != "Vagrant" {
		t.Fatalf("KeyMatch not carried on BruteResult")
	}
	if r.KeyMatch.CVE != "CVE-2015-1338" {
		t.Fatalf("KeyMatch.CVE = %q, want CVE-2015-1338", r.KeyMatch.CVE)
	}
}
