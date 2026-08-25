package brutespray

import "testing"

func TestCIExitCodeForCredentialsFound(t *testing.T) {
	result := CIResult{CredentialsFound: 1}
	if got := result.ExitCode(); got != CIExitCredentialsFound {
		t.Fatalf("exit = %d", got)
	}
}

func TestCIExitCodePolicyViolationWins(t *testing.T) {
	result := CIResult{CredentialsFound: 1, PolicyViolations: 1}
	if got := result.ExitCode(); got != CIExitPolicyViolation {
		t.Fatalf("exit = %d", got)
	}
}

func TestCIExitCodeSuccess(t *testing.T) {
	if got := (CIResult{}).ExitCode(); got != CIExitNoFindings {
		t.Fatalf("exit = %d", got)
	}
}
