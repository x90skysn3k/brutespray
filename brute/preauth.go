package brute

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// PreAuthTarget describes a target for bounded checks that do not require credentials.
type PreAuthTarget struct {
	Service string
	Host    string
	Port    int
	Timeout time.Duration
	CM      *modules.ConnectionManager
	Params  ModuleParams
}

// Address returns host:port for network dials and finding targets.
func (t PreAuthTarget) Address() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// PreAuthProbe performs a bounded non-credential check before brute-force attempts.
type PreAuthProbe struct {
	Code        string
	Description string
	Default     bool
	Run         func(context.Context, PreAuthTarget) ([]Finding, error)
}

var preAuthRegistry = struct {
	mu     sync.RWMutex
	probes map[string][]PreAuthProbe
}{probes: make(map[string][]PreAuthProbe)}

// RegisterPreAuthProbe registers a pre-auth probe for service.
func RegisterPreAuthProbe(service string, probe PreAuthProbe) {
	preAuthRegistry.mu.Lock()
	defer preAuthRegistry.mu.Unlock()
	preAuthRegistry.probes[service] = append(preAuthRegistry.probes[service], probe)
}

// PreAuthProbes returns registered probes for service.
func PreAuthProbes(service string) []PreAuthProbe {
	preAuthRegistry.mu.RLock()
	defer preAuthRegistry.mu.RUnlock()
	return append([]PreAuthProbe(nil), preAuthRegistry.probes[service]...)
}
