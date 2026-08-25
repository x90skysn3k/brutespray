package brutespray

import (
	"context"
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/brute"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

func TestCollectPreAuthFindingsRunsDefaultProbes(t *testing.T) {
	brute.RegisterPreAuthProbe("dispatch-fake", brute.PreAuthProbe{
		Code:    "dispatch-fake",
		Default: true,
		Run: func(context.Context, brute.PreAuthTarget) ([]brute.Finding, error) {
			return []brute.Finding{{Severity: "INFO", Code: "dispatch-fake"}}, nil
		},
	})
	findings := collectPreAuthFindings(context.Background(), modules.Host{Service: "dispatch-fake", Host: "127.0.0.1", Port: 1}, time.Second, nil, nil)
	if len(findings) != 1 || findings[0].Code != "dispatch-fake" {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestRDPPreAuthProbeRegistered(t *testing.T) {
	probes := brute.PreAuthProbes("rdp")
	if len(probes) == 0 {
		t.Fatal("rdp pre-auth probe missing")
	}
}
