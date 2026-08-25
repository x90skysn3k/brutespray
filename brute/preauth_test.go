package brute

import (
	"context"
	"testing"
	"time"
)

func TestPreAuthProbeRegistry(t *testing.T) {
	RegisterPreAuthProbe("fake", PreAuthProbe{
		Code:        "fake-probe",
		Description: "fake probe",
		Default:     true,
		Run: func(context.Context, PreAuthTarget) ([]Finding, error) {
			return []Finding{{Severity: "INFO", Code: "fake-probe"}}, nil
		},
	})
	probes := PreAuthProbes("fake")
	if len(probes) != 1 {
		t.Fatalf("probes = %d, want 1", len(probes))
	}
	findings, err := probes[0].Run(context.Background(), PreAuthTarget{Service: "fake", Host: "127.0.0.1", Port: 1, Timeout: time.Second})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 || findings[0].Code != "fake-probe" {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestPreAuthTargetAddress(t *testing.T) {
	target := PreAuthTarget{Host: "127.0.0.1", Port: 22}
	if target.Address() != "127.0.0.1:22" {
		t.Fatalf("address = %q", target.Address())
	}
}
