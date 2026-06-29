package brutespray

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func TestBuildExecutionPlanCountsAttempts(t *testing.T) {
	cfg := &Config{
		Hosts: []modules.Host{
			{Service: "ssh", Host: "10.0.0.1", Port: 22},
			{Service: "ssh", Host: "10.0.0.2", Port: 22},
		},
		User:      "root",
		Password:  "toor",
		NoBadKeys: true,
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
		User:      "root",
		Password:  "toor",
		NoBadKeys: true,
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

func TestBuildExecutionPlanHashIgnoresHostInputOrder(t *testing.T) {
	first := &Config{
		Hosts: []modules.Host{
			{Service: "ssh", Host: "10.0.0.2", Port: 22},
			{Service: "ssh", Host: "10.0.0.1", Port: 22},
		},
		User:      "root",
		Password:  "toor",
		NoBadKeys: true,
	}
	second := &Config{
		Hosts: []modules.Host{
			{Service: "ssh", Host: "10.0.0.1", Port: 22},
			{Service: "ssh", Host: "10.0.0.2", Port: 22},
		},
		User:      "root",
		Password:  "toor",
		NoBadKeys: true,
	}
	firstPlan, err := BuildExecutionPlan(first, EngagementManifest{})
	if err != nil {
		t.Fatalf("BuildExecutionPlan(first): %v", err)
	}
	secondPlan, err := BuildExecutionPlan(second, EngagementManifest{})
	if err != nil {
		t.Fatalf("BuildExecutionPlan(second): %v", err)
	}
	if firstPlan.Hash != secondPlan.Hash {
		t.Fatalf("hashes differ for same targets: %s != %s", firstPlan.Hash, secondPlan.Hash)
	}
}

func TestBuildExecutionPlanCountsFilesInlineAndExtras(t *testing.T) {
	dir := t.TempDir()
	users := filepath.Join(dir, "users.txt")
	passwords := filepath.Join(dir, "passwords.txt")
	if err := os.WriteFile(users, []byte("root\nadmin\n"), 0o600); err != nil {
		t.Fatalf("write users: %v", err)
	}
	if err := os.WriteFile(passwords, []byte("toor\nsecret\n"), 0o600); err != nil {
		t.Fatalf("write passwords: %v", err)
	}
	cfg := &Config{
		Hosts:             []modules.Host{{Service: "ftp", Host: "10.0.0.1", Port: 21}},
		User:              users,
		Password:          passwords,
		Creds:             "inline:cred,second:pair",
		UseUsernameAsPass: true,
		UseReversedPass:   true,
	}
	plan, err := BuildExecutionPlan(cfg, EngagementManifest{})
	if err != nil {
		t.Fatalf("BuildExecutionPlan: %v", err)
	}
	// 2 inline creds + 2 username-as-password + 2 reversed users + 2x2 file credentials.
	if plan.TotalAttempts != 10 {
		t.Fatalf("attempts = %d, want 10", plan.TotalAttempts)
	}
}

func TestBuildExecutionPlanCountsComboFile(t *testing.T) {
	combo := filepath.Join(t.TempDir(), "combo.txt")
	if err := os.WriteFile(combo, []byte("root:toor\nadmin:secret\n"), 0o600); err != nil {
		t.Fatalf("write combo: %v", err)
	}
	cfg := &Config{
		Hosts: []modules.Host{{Service: "ssh", Host: "10.0.0.1", Port: 22}},
		Combo: combo,
	}
	plan, err := BuildExecutionPlan(cfg, EngagementManifest{})
	if err != nil {
		t.Fatalf("BuildExecutionPlan: %v", err)
	}
	if plan.TotalAttempts != 2 {
		t.Fatalf("attempts = %d, want 2", plan.TotalAttempts)
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
