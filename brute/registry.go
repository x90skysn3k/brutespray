package brute

import (
	"sort"
	"time"

	"github.com/x90skysn3k/brutespray/modules"
)

// BruteFunc is the standard signature for a brute-force module.
type BruteFunc func(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (authSuccess bool, connSuccess bool)

// BruteFuncWithDomain is for modules that require a domain parameter (SMB, RDP).
type BruteFuncWithDomain func(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, domain string) (authSuccess bool, connSuccess bool)

// BruteFuncHTTP is for the HTTP module that needs the useHTTPS flag.
type BruteFuncHTTP func(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, useHTTPS bool) (authSuccess bool, connSuccess bool)

type moduleEntry struct {
	standard   BruteFunc
	withDomain BruteFuncWithDomain
	http       BruteFuncHTTP
}

var registry = map[string]moduleEntry{}

// Register adds a standard brute-force module to the registry.
func Register(service string, fn BruteFunc) {
	registry[service] = moduleEntry{standard: fn}
}

// RegisterWithDomain adds a domain-aware module (SMB, RDP).
func RegisterWithDomain(service string, fn BruteFuncWithDomain) {
	registry[service] = moduleEntry{withDomain: fn}
}

// RegisterHTTP adds the HTTP module with HTTPS flag support.
func RegisterHTTP(service string, fn BruteFuncHTTP) {
	registry[service] = moduleEntry{http: fn}
}

// Lookup returns the module entry for a service, if registered.
func Lookup(service string) (moduleEntry, bool) {
	entry, ok := registry[service]
	return entry, ok
}

// Services returns a sorted list of all registered service names.
func Services() []string {
	services := make([]string, 0, len(registry))
	for s := range registry {
		services = append(services, s)
	}
	sort.Strings(services)
	return services
}

// IsRegistered returns true if a service has a registered module.
func IsRegistered(service string) bool {
	_, ok := registry[service]
	return ok
}
