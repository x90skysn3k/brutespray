package brute

import (
	"sort"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// ModuleParams carries per-module configuration such as auth method, domain,
// HTTPS flag, target path, etc. Modules read what they need and ignore the rest.
type ModuleParams map[string]string

// BruteFunc is the unified signature for all brute-force modules.
type BruteFunc func(host string, port int, user, password string,
	timeout time.Duration, cm *modules.ConnectionManager,
	params ModuleParams) *BruteResult

var registry = map[string]BruteFunc{}

// Register adds a brute-force module to the registry.
func Register(service string, fn BruteFunc) {
	registry[service] = fn
}

// Lookup returns the module function for a service, if registered.
func Lookup(service string) (BruteFunc, bool) {
	fn, ok := registry[service]
	return fn, ok
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
