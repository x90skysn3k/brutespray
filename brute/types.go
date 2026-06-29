package brute

// Confidence describes how strongly BruteSpray can prove an auth or exposure result.
type Confidence string

const (
	ConfidenceConfirmed    Confidence = "confirmed"
	ConfidenceProbable     Confidence = "probable"
	ConfidenceInconclusive Confidence = "inconclusive"
)

// ProofType describes the evidence source for a result.
type ProofType string

const (
	ProofAuthProtocolSuccess ProofType = "auth_protocol_success"
	ProofPreAuthProbe        ProofType = "preauth_probe"
	ProofBadKey              ProofType = "badkey_match"
	ProofHTTPMatcher         ProofType = "http_matcher"
	ProofWrapperExit         ProofType = "wrapper_exit"
)

// Proof captures confidence metadata shared by auth results and findings.
type Proof struct {
	Confidence Confidence `json:"confidence,omitempty"`
	ProofType  ProofType  `json:"proof_type,omitempty"`
	Detail     string     `json:"proof_detail,omitempty"`
}

// Finding represents a pre-auth recon result (e.g. SSH bad-key match,
// RDP NLA missing, RDP sticky-keys backdoor). Modules can return findings
// without a successful authentication attempt.
type Finding struct {
	Severity string // INFO, WARN, HIGH, CRITICAL
	Code     string // e.g. "rdp-nla-missing", "rdp-stickykeys", "ssh-badkey"
	Message  string
	CVE      string // optional, e.g. "CVE-2012-1493"
	Proof
}

// KeyMatch records a successful SSH key authentication originating from
// the embedded bad-keys bundle.
type KeyMatch struct {
	Fingerprint string
	Vendor      string
	CVE         string
	Description string
}

// EnsureProof fills default proof metadata for pre-auth findings.
func (f *Finding) EnsureProof() {
	if f.Confidence == "" {
		f.Confidence = ConfidenceProbable
	}
	if f.ProofType == "" {
		f.ProofType = ProofPreAuthProbe
	}
}
