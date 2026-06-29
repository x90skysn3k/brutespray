package brutespray

import (
	"testing"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func TestBuildExecutionPlanCountsAttempts(t *testing.T) {
	cfg := &Config{
		Hosts: []modules.Host{
			{Service: "ssh", Host: "10.0.0.1", Port: 22},
			{Service: "ssh", Host: "10.0.0.2", Port: 22},
		},
		User:     "root",
		Password: "toor",
	}
	plan, err := BuildExecutionPlan(cfg, EngagementManifest{})
	if err != nil {
		t.Fatalf("BuildExecutionPlan: %v", err)
	}
	if plan.TotalTargets != 2 {
		t.Fatalf("targets = %d, want 2", plan.TotalTargets)
	}
	if plan.TotalAttempts != 2 {
		t.Fatalf("attempts = %d, want 2", plan.TotalAttempts)
	}
	if plan.Hash == "" {
		t.Fatal("plan hash missing")
	}
}

func TestBuildExecutionPlanWarnsOnWrapper(t *testing.T) {
	cfg := &Config{
		Hosts:        []modules.Host{{Service: "wrapper", Host: "10.0.0.1", Port: 0}},
		User:         "root",
		Password:     "toor",
		AllowWrapper: true,
	}
	plan, err := BuildExecutionPlan(cfg, EngagementManifest{})
	if err != nil {
		t.Fatalf("BuildExecutionPlan: %v", err)
	}
	if !planHasWarning(plan, "wrapper-exec") {
		t.Fatalf("wrapper warning missing: %+v", plan.Warnings)
	}
}

func TestBuildExecutionPlanAppliesScope(t *testing.T) {
	cfg := &Config{
		Hosts: []modules.Host{
			{Service: "ssh", Host: "10.0.0.1", Port: 22},
			{Service: "ssh", Host: "10.0.0.13", Port: 22},
		},
		User:     "root",
		Password: "toor",
	}
	manifest := EngagementManifest{Scope: ScopeConfig{
		Allow: ScopeSet{CIDRs: []string{"10.0.0.0/24"}},
		Deny:  ScopeSet{Hosts: []string{"10.0.0.13"}},
	}}
	plan, err := BuildExecutionPlan(cfg, manifest)
	if err != nil {
		t.Fatalf("BuildExecutionPlan: %v", err)
	}
	if plan.TotalTargets != 1 {
		t.Fatalf("targets = %d, want 1", plan.TotalTargets)
	}
	if len(plan.ScopeRejects) != 1 || plan.ScopeRejects[0].Host != "10.0.0.13" {
		t.Fatalf("scope rejects = %+v", plan.ScopeRejects)
	}
}

func planHasWarning(plan ExecutionPlan, code string) bool {
	for _, warning := range plan.Warnings {
		if warning.Code == code {
			return true
		}
	}
	return false
}
