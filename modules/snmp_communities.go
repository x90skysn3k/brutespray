package modules

import (
	"fmt"
	"strings"
	"sync"

	"github.com/x90skysn3k/brutespray/v2/wordlist"
)

var (
	snmpCacheMu sync.Mutex
	snmpCache   = map[string][]string{}
)

// SNMPCommunities returns the embedded community-string list for a tier:
// "default" (~20), "extended" (~50), or "full" (~100+). The returned slice
// is cached after first load. Unknown tier names fall back to "default".
func SNMPCommunities(tier string) ([]string, error) {
	snmpCacheMu.Lock()
	defer snmpCacheMu.Unlock()

	if cached, ok := snmpCache[tier]; ok {
		return cached, nil
	}

	var fname string
	switch tier {
	case "extended":
		fname = "snmp/snmp_extended.txt"
	case "full":
		fname = "snmp/snmp_full.txt"
	default:
		fname = "snmp/snmp_default.txt"
	}

	data, err := wordlist.FS.ReadFile(fname)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", fname, err)
	}

	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		s := strings.TrimSpace(line)
		if s != "" && !strings.HasPrefix(s, "#") {
			out = append(out, s)
		}
	}

	snmpCache[tier] = out
	return out, nil
}
