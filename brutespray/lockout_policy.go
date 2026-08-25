package brutespray

import (
	"fmt"
	"time"
)

// LockoutPolicy defines account-attempt limits for scheduler decisions.
type LockoutPolicy struct {
	LockoutThreshold int           `yaml:"lockout_threshold" json:"lockout_threshold"`
	LockoutWindow    time.Duration `yaml:"lockout_window" json:"lockout_window"`
	SafeMargin       int           `yaml:"safe_margin" json:"safe_margin"`
	JitterPercent    int           `yaml:"jitter_percent" json:"jitter_percent"`
}

// EffectiveBudget returns usable attempts inside the lockout window.
func (p LockoutPolicy) EffectiveBudget() int {
	budget := p.LockoutThreshold - p.SafeMargin
	if budget < 0 {
		return 0
	}
	return budget
}

// Validate rejects policies that cannot safely budget attempts.
func (p LockoutPolicy) Validate() error {
	if p.LockoutThreshold < 0 {
		return fmt.Errorf("lockout threshold must be >= 0")
	}
	if p.LockoutWindow < 0 {
		return fmt.Errorf("lockout window must be >= 0")
	}
	if p.SafeMargin < 0 {
		return fmt.Errorf("safe margin must be >= 0")
	}
	if p.LockoutThreshold > 0 && p.SafeMargin >= p.LockoutThreshold {
		return fmt.Errorf("safe margin must be less than lockout threshold")
	}
	if p.JitterPercent < 0 || p.JitterPercent > 100 {
		return fmt.Errorf("jitter percent must be between 0 and 100")
	}
	return nil
}

// LockoutPolicyFromManifest converts YAML string durations into runtime policy.
func LockoutPolicyFromManifest(manifest ManifestPolicy) (LockoutPolicy, error) {
	policy := LockoutPolicy{
		LockoutThreshold: manifest.LockoutThreshold,
		SafeMargin:       manifest.SafeMargin,
		JitterPercent:    manifest.JitterPercent,
	}
	if manifest.LockoutWindow != "" {
		window, err := time.ParseDuration(manifest.LockoutWindow)
		if err != nil {
			return LockoutPolicy{}, fmt.Errorf("invalid lockout window: %w", err)
		}
		policy.LockoutWindow = window
	}
	return policy, policy.Validate()
}
