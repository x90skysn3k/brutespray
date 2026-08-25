package brutespray

const (
	CIExitNoFindings       = 0
	CIExitCredentialsFound = 1
	CIExitPolicyViolation  = 2
	CIExitRuntimeError     = 3
)

// CIResult summarizes machine-readable CI outcomes.
type CIResult struct {
	CredentialsFound int
	Findings         int
	PolicyViolations int
	RuntimeErrors    int
}

// ExitCode returns deterministic CI exit semantics.
func (r CIResult) ExitCode() int {
	if r.RuntimeErrors > 0 {
		return CIExitRuntimeError
	}
	if r.PolicyViolations > 0 {
		return CIExitPolicyViolation
	}
	if r.CredentialsFound > 0 || r.Findings > 0 {
		return CIExitCredentialsFound
	}
	return CIExitNoFindings
}
