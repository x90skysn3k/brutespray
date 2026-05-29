package brute

import "testing"

func TestBruteResultCarriesFinding(t *testing.T) {
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
}
