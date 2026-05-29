package brute

// Finding represents a pre-auth recon result (e.g. SSH bad-key match,
// RDP NLA missing, RDP sticky-keys backdoor). Modules can return findings
// without a successful authentication attempt.
type Finding struct {
	Severity string // INFO, WARN, HIGH, CRITICAL
	Code     string // e.g. "rdp-nla-missing", "rdp-stickykeys", "ssh-badkey"
	Message  string
	CVE      string // optional, e.g. "CVE-2012-1493"
}

// KeyMatch records a successful SSH key authentication originating from
// the embedded bad-keys bundle.
type KeyMatch struct {
	Fingerprint string
	Vendor      string
	CVE         string
	Description string
}
