package brute

import "testing"

func TestBruteResultDefaultProof(t *testing.T) {
	result := &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
	result.EnsureProof("ssh")
	if result.Confidence != ConfidenceConfirmed {
		t.Fatalf("confidence = %s", result.Confidence)
	}
	if result.ProofType != ProofAuthProtocolSuccess {
		t.Fatalf("proof type = %s", result.ProofType)
	}
}

func TestFindingDefaultProof(t *testing.T) {
	finding := Finding{Code: "redis-no-auth"}
	finding.EnsureProof()
	if finding.Confidence != ConfidenceProbable {
		t.Fatalf("confidence = %s", finding.Confidence)
	}
	if finding.ProofType != ProofPreAuthProbe {
		t.Fatalf("proof type = %s", finding.ProofType)
	}
}
