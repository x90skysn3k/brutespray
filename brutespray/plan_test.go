package brutespray

import (
	"flag"
	"os"
	"os/exec"
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

func TestBuildExecutionPlanHashBindsCredentialContents(t *testing.T) {
	passwords := filepath.Join(t.TempDir(), "passwords.txt")
	if err := os.WriteFile(passwords, []byte("first-secret\n"), 0o600); err != nil {
		t.Fatalf("write first password list: %v", err)
	}
	cfg := &Config{
		Hosts:     []modules.Host{{Service: "ftp", Host: "10.0.0.1", Port: 21}},
		User:      "root",
		Password:  passwords,
		NoBadKeys: true,
	}
	manifest := EngagementManifest{Evidence: ManifestEvidence{HMACKey: "plan-key"}}

	first, err := BuildExecutionPlan(cfg, manifest)
	if err != nil {
		t.Fatalf("BuildExecutionPlan(first): %v", err)
	}
	if err := os.WriteFile(passwords, []byte("other-secret\n"), 0o600); err != nil {
		t.Fatalf("replace password list: %v", err)
	}
	second, err := BuildExecutionPlan(cfg, manifest)
	if err != nil {
		t.Fatalf("BuildExecutionPlan(second): %v", err)
	}
	if first.TotalAttempts != second.TotalAttempts {
		t.Fatalf("attempt counts differ: %d != %d", first.TotalAttempts, second.TotalAttempts)
	}
	if first.Hash == second.Hash {
		t.Fatalf("plan hash did not bind credential contents: %s", first.Hash)
	}
}

func TestBuildExecutionPlanAcknowledgementRequiresHMACKey(t *testing.T) {
	cfg := &Config{
		Hosts:          []modules.Host{{Service: "ftp", Host: "10.0.0.1", Port: 21}},
		User:           "root",
		Password:       "secret",
		RequirePlanAck: "acknowledged-hash",
	}

	if _, err := BuildExecutionPlan(cfg, EngagementManifest{}); err == nil {
		t.Fatal("expected plan acknowledgment without evidence.hmac_key to fail")
	}
}

func TestBuildExecutionPlanCredentialHMACBindsSSHBadKeys(t *testing.T) {
	cfg := &Config{
		Hosts:     []modules.Host{{Service: "ssh", Host: "10.0.0.1", Port: 22}},
		User:      "root",
		Password:  "secret",
		NoBadKeys: true,
	}
	manifest := EngagementManifest{Evidence: ManifestEvidence{HMACKey: "plan-key"}}
	withoutBadKeys, err := BuildExecutionPlan(cfg, manifest)
	if err != nil {
		t.Fatalf("BuildExecutionPlan(without bad keys): %v", err)
	}
	cfg.NoBadKeys = false
	withBadKeys, err := BuildExecutionPlan(cfg, manifest)
	if err != nil {
		t.Fatalf("BuildExecutionPlan(with bad keys): %v", err)
	}
	if withoutBadKeys.Targets[0].CredentialHMAC == withBadKeys.Targets[0].CredentialHMAC {
		t.Fatal("credential HMAC did not bind SSH bad-key identities")
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
		Creds: "ignored:inline-secret",
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

func TestEstimateAttemptsForRedisCountsInlineCredentialAndExplicitPassword(t *testing.T) {
	cfg := &Config{
		Creds:    "ignored:redis-inline-secret",
		Password: "base-secret",
	}
	got, _, err := estimateAttemptsForTarget(cfg, modules.Host{Service: "redis", Host: "10.0.0.1", Port: 6379}, nil)
	if err != nil {
		t.Fatalf("estimateAttemptsForTarget: %v", err)
	}
	if got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}
}

func TestEstimateAttemptsForInfluxDBTokenModeIgnoresUsers(t *testing.T) {
	users := filepath.Join(t.TempDir(), "users.txt")
	if err := os.WriteFile(users, []byte("admin\noperator\n"), 0o600); err != nil {
		t.Fatalf("write users: %v", err)
	}
	cfg := &Config{
		User:         users,
		Password:     "influx-token",
		ModuleParams: map[string]string{"mode": "v2"},
	}
	got, _, err := estimateAttemptsForTarget(cfg, modules.Host{Service: "influxdb", Host: "10.0.0.1", Port: 8086}, nil)
	if err != nil {
		t.Fatalf("estimateAttemptsForTarget: %v", err)
	}
	if got != 1 {
		t.Fatalf("attempts = %d, want one token attempt", got)
	}
}

func TestEstimateAttemptsForInfluxDBV1KeepsUserPasswordPairs(t *testing.T) {
	users := filepath.Join(t.TempDir(), "users.txt")
	if err := os.WriteFile(users, []byte("admin\noperator\n"), 0o600); err != nil {
		t.Fatalf("write users: %v", err)
	}
	cfg := &Config{
		User:         users,
		Password:     "influx-password",
		ModuleParams: map[string]string{"mode": "v1"},
	}
	got, _, err := estimateAttemptsForTarget(cfg, modules.Host{Service: "influxdb", Host: "10.0.0.1", Port: 8086}, nil)
	if err != nil {
		t.Fatalf("estimateAttemptsForTarget: %v", err)
	}
	if got != 2 {
		t.Fatalf("attempts = %d, want two user/password attempts", got)
	}
}

func TestParseConfigTotalCombinationsCountsInlineCredsWithoutCombo(t *testing.T) {
	if mode := os.Getenv("BRUTESPRAY_PARSECONFIG_TOTALS_HELPER"); mode != "" {
		originalArgs := os.Args
		originalCommandLine := flag.CommandLine
		defer func() {
			os.Args = originalArgs
			flag.CommandLine = originalCommandLine
		}()

		os.Args = []string{os.Args[0], "-q", "-nc", "-c", "ignored:inline-secret"}
		switch mode {
		case "redis":
			os.Args = append(os.Args, "-s", "redis", "-H", "redis://127.0.0.1:6379", "-p", "base-secret")
		case "ftp":
			os.Args = append(os.Args, "-s", "ftp", "-H", "ftp://127.0.0.1:21", "-u", "admin", "-p", "base-secret")
		case "influx-v2":
			users := filepath.Join(t.TempDir(), "influx-users.txt")
			if err := os.WriteFile(users, []byte("admin\noperator\n"), 0o600); err != nil {
				t.Fatalf("write influx users: %v", err)
			}
			os.Args = append(os.Args, "-s", "influxdb", "-H", "influxdb://127.0.0.1:8086", "-u", users, "-p", "base-secret", "-m", "mode:v2")
		case "combo":
			os.Args = append(os.Args, "-s", "ftp", "-H", "ftp://127.0.0.1:21", "-C", "admin:base-secret")
		default:
			t.Fatalf("unknown helper mode %q", mode)
		}
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

		cfg := ParseConfig()
		want := 2
		if mode == "combo" {
			want = 1
		}
		if cfg.TotalCombinations != want {
			t.Fatalf("%s TotalCombinations = %d, want %d", mode, cfg.TotalCombinations, want)
		}
		return
	}

	for _, mode := range []string{"redis", "ftp", "influx-v2", "combo"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestParseConfigTotalCombinationsCountsInlineCredsWithoutCombo$", "-test.v")
			cmd.Env = append(os.Environ(), "BRUTESPRAY_PARSECONFIG_TOTALS_HELPER="+mode)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("ParseConfig totals helper failed for %s: %v\n%s", mode, err, out)
			}
		})
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
