package modules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigReadsSkipPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := []byte("skip_policy: aggressive\nmax_conn_fails: 7\nschedule: pairwise\ndebug_audit: true\ndebug_file: audit.jsonl\nroute_diagnostics: true\nmodule_help: ssh\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.SkipPolicy != "aggressive" {
		t.Fatalf("SkipPolicy = %q, want aggressive", cfg.SkipPolicy)
	}
	if cfg.MaxConnFails != 7 {
		t.Fatalf("MaxConnFails = %d, want 7", cfg.MaxConnFails)
	}
	if cfg.Schedule != "pairwise" {
		t.Fatalf("Schedule = %q, want pairwise", cfg.Schedule)
	}
	if !cfg.DebugAudit {
		t.Fatal("DebugAudit = false, want true")
	}
	if cfg.DebugFile != "audit.jsonl" {
		t.Fatalf("DebugFile = %q, want audit.jsonl", cfg.DebugFile)
	}
	if !cfg.RouteDiagnostics {
		t.Fatal("RouteDiagnostics = false, want true")
	}
	if cfg.ModuleHelp != "ssh" {
		t.Fatalf("ModuleHelp = %q, want ssh", cfg.ModuleHelp)
	}
}
