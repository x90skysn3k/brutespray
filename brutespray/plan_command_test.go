package brutespray

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func TestRunPlanCommandWritesPlanFile(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "plan.json")
	cfg := &Config{
		Hosts:     []modules.Host{{Service: "ssh", Host: "127.0.0.1", Port: 22}},
		User:      "root",
		Password:  "toor",
		PlanOut:   outPath,
		NoBadKeys: true,
	}
	plan, err := RunPlanCommand(cfg)
	if err != nil {
		t.Fatalf("RunPlanCommand: %v", err)
	}
	var fromFile ExecutionPlan
	if err := readJSONFile(outPath, &fromFile); err != nil {
		t.Fatalf("read plan file: %v", err)
	}
	if fromFile.Hash != plan.Hash || fromFile.TotalTargets != 1 || fromFile.TotalAttempts != 1 {
		t.Fatalf("plan file mismatch: file=%+v returned=%+v", fromFile, plan)
	}
}

func TestRunPlanCommandLoadsEngagementManifest(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "engagement.yaml")
	if err := os.WriteFile(manifestPath, []byte("engagement:\n  id: acme-q3\nscope:\n  deny:\n    hosts: [127.0.0.2]\n"), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	cfg := &Config{
		Hosts:          []modules.Host{{Service: "ssh", Host: "127.0.0.1", Port: 22}, {Service: "ssh", Host: "127.0.0.2", Port: 22}},
		User:           "root",
		Password:       "toor",
		EngagementFile: manifestPath,
		NoBadKeys:      true,
		PlanOut:        filepath.Join(dir, "plan.json"),
	}
	plan, err := RunPlanCommand(cfg)
	if err != nil {
		t.Fatalf("RunPlanCommand: %v", err)
	}
	if plan.EngagementID != "acme-q3" {
		t.Fatalf("engagement id = %q", plan.EngagementID)
	}
	if plan.TotalTargets != 1 || len(plan.ScopeRejects) != 1 {
		t.Fatalf("scope not applied: %+v", plan)
	}
}

func readJSONFile(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}
