package brutespray

import (
	"fmt"
	"net/netip"
	"strings"
)

// ScopeMatcher checks resolved targets against engagement allow/deny scope.
type ScopeMatcher struct {
	allowPrefixes []netip.Prefix
	denyPrefixes  []netip.Prefix
	allowHosts    map[string]struct{}
	denyHosts     map[string]struct{}
	hasAllow      bool
}

// NewScopeMatcher compiles manifest scope selectors.
func NewScopeMatcher(cfg ScopeConfig) (*ScopeMatcher, error) {
	matcher := &ScopeMatcher{
		allowHosts: make(map[string]struct{}),
		denyHosts:  make(map[string]struct{}),
	}
	for _, cidr := range cfg.Allow.CIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("invalid allow cidr %q: %w", cidr, err)
		}
		matcher.allowPrefixes = append(matcher.allowPrefixes, prefix)
		matcher.hasAllow = true
	}
	for _, cidr := range cfg.Deny.CIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("invalid deny cidr %q: %w", cidr, err)
		}
		matcher.denyPrefixes = append(matcher.denyPrefixes, prefix)
	}
	for _, host := range cfg.Allow.Hosts {
		normalized := normalizeScopeHost(host)
		if normalized != "" {
			matcher.allowHosts[normalized] = struct{}{}
			matcher.hasAllow = true
		}
	}
	for _, host := range cfg.Deny.Hosts {
		normalized := normalizeScopeHost(host)
		if normalized != "" {
			matcher.denyHosts[normalized] = struct{}{}
		}
	}
	return matcher, nil
}

// Allowed reports whether host is in scope plus a stable reason string.
func (m *ScopeMatcher) Allowed(host string) (bool, string) {
	normalized := normalizeScopeHost(host)
	if _, ok := m.denyHosts[normalized]; ok {
		return false, "denied by host"
	}
	addr, hasAddr := netip.ParseAddr(normalized)
	if hasAddr == nil {
		for _, prefix := range m.denyPrefixes {
			if prefix.Contains(addr) {
				return false, "denied by cidr"
			}
		}
	}
	if !m.hasAllow {
		return true, "allowed"
	}
	if _, ok := m.allowHosts[normalized]; ok {
		return true, "allowed"
	}
	if hasAddr == nil {
		for _, prefix := range m.allowPrefixes {
			if prefix.Contains(addr) {
				return true, "allowed"
			}
		}
	}
	return false, "outside allow scope"
}

func normalizeScopeHost(host string) string {
	return strings.ToLower(strings.TrimSpace(strings.Trim(host, "[]")))
}
