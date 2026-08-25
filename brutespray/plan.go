package brutespray

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/x90skysn3k/brutespray/v2/brute/badkeys"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

// ExecutionPlan is a dry-run summary of what a run would attempt.
type ExecutionPlan struct {
	Version       string           `json:"version"`
	GeneratedAt   time.Time        `json:"generated_at"`
	EngagementID  string           `json:"engagement_id,omitempty"`
	Hash          string           `json:"hash"`
	TotalTargets  int              `json:"total_targets"`
	TotalAttempts int              `json:"total_attempts"`
	Targets       []PlannedTarget  `json:"targets"`
	Warnings      []PlanWarning    `json:"warnings,omitempty"`
	ScopeRejects  []ScopeRejection `json:"scope_rejects,omitempty"`
}

// PlannedTarget describes a target that remains in scope.
type PlannedTarget struct {
	Service        string `json:"service"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Attempts       int    `json:"attempts"`
	CredentialHMAC string `json:"credential_hmac,omitempty"`
}

// PlanWarning is a stable warning emitted before execution.
type PlanWarning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ScopeRejection records a target excluded by scope policy.
type ScopeRejection struct {
	Service string `json:"service"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Reason  string `json:"reason"`
}

// BuildExecutionPlan resolves targets, scope, and credential cardinality without performing attempts.
func BuildExecutionPlan(cfg *Config, manifest EngagementManifest) (ExecutionPlan, error) {
	if cfg == nil {
		return ExecutionPlan{}, fmt.Errorf("config is required")
	}
	if err := manifest.Validate(); err != nil {
		return ExecutionPlan{}, err
	}
	credentialKey := []byte(manifest.Evidence.HMACKey)
	if cfg.RequirePlanAck != "" && len(credentialKey) == 0 {
		return ExecutionPlan{}, fmt.Errorf("plan acknowledgment requires evidence.hmac_key to bind credential inputs")
	}
	matcher, err := NewScopeMatcher(manifest.Scope)
	if err != nil {
		return ExecutionPlan{}, err
	}
	plan := ExecutionPlan{
		Version:      "brutespray.plan.v1",
		GeneratedAt:  time.Now().UTC(),
		EngagementID: manifest.Engagement.ID,
	}
	for _, host := range cfg.Hosts {
		allowed, reason := matcher.Allowed(host.Host)
		if !allowed {
			plan.ScopeRejects = append(plan.ScopeRejects, ScopeRejection{Service: host.Service, Host: host.Host, Port: host.Port, Reason: reason})
			continue
		}
		attempts, credentialHMAC, err := estimateAttemptsForTarget(cfg, host, credentialKey)
		if err != nil {
			return ExecutionPlan{}, err
		}
		plan.Targets = append(plan.Targets, PlannedTarget{
			Service:        host.Service,
			Host:           host.Host,
			Port:           host.Port,
			Attempts:       attempts,
			CredentialHMAC: credentialHMAC,
		})
		plan.TotalTargets++
		plan.TotalAttempts += attempts
		if host.Service == "wrapper" {
			plan.Warnings = append(plan.Warnings, PlanWarning{Code: "wrapper-exec", Message: "wrapper executes external commands and requires explicit authorization"})
		}
	}
	sortPlan(&plan)
	plan.Hash = planHash(plan)
	return plan, nil
}

func estimateAttemptsForTarget(cfg *Config, host modules.Host, credentialKey []byte) (int, string, error) {
	mac := hmac.New(sha256.New, credentialKey)
	hashEnabled := len(credentialKey) > 0
	writeValue := func(value string) {
		if !hashEnabled {
			return
		}
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = mac.Write(size[:])
		_, _ = mac.Write([]byte(value))
	}
	writeValues := func(label string, values []string) {
		writeValue(label)
		for _, value := range values {
			writeValue(value)
		}
	}
	digest := func() string {
		if !hashEnabled {
			return ""
		}
		return hex.EncodeToString(mac.Sum(nil))
	}

	writeValue("brutespray.plan.credentials.v1")
	writeValue(host.Service)
	writeValue(host.Host)
	writeValue(strconv.Itoa(host.Port))

	if cfg.Combo != "" {
		users, passwords := modules.GetUsersAndPasswordsCombo(&host, cfg.Combo, version)
		count := min(len(users), len(passwords))
		writeValue("combo")
		for i := range count {
			writeValue(users[i])
			writeValue(passwords[i])
		}
		return count, digest(), nil
	}

	inline := ParseInlineCreds(cfg.Creds)
	attempts := len(inline)
	if modules.IsSingleSecretService(host.Service, cfg.ModuleParams) {
		writeValue("single-secret")
		for _, pair := range inline {
			writeValue(pair.Password)
		}
		if cfg.PasswordGen != nil {
			writeValue("generator")
			writeValue(strconv.Itoa(cfg.PasswordGen.MinLen))
			writeValue(strconv.Itoa(cfg.PasswordGen.MaxLen))
			writeValue(string(cfg.PasswordGen.Charset))
			return attempts + cfg.PasswordGen.Count(), digest(), nil
		}
		_, passwords, err := modules.GetUsersAndPasswords(&host, cfg.User, cfg.Password, version)
		if err != nil {
			return 0, "", err
		}
		writeValues("passwords", passwords)
		return attempts + len(passwords), digest(), nil
	}

	writeValue("user-password")
	for _, pair := range inline {
		writeValue(pair.User)
		writeValue(pair.Password)
	}
	users, passwords, err := modules.GetUsersAndPasswords(&host, cfg.User, cfg.Password, version)
	if err != nil {
		return 0, "", err
	}
	writeValues("users", users)
	passCount := len(passwords)
	if cfg.PasswordGen != nil {
		writeValue("generator")
		writeValue(strconv.Itoa(cfg.PasswordGen.MinLen))
		writeValue(strconv.Itoa(cfg.PasswordGen.MaxLen))
		writeValue(string(cfg.PasswordGen.Charset))
		passCount = cfg.PasswordGen.Count()
	} else {
		writeValues("passwords", passwords)
	}
	writeValue(normalizedScheduleMode(cfg))
	writeValue(strconv.FormatBool(cfg.UseUsernameAsPass))
	writeValue(strconv.FormatBool(cfg.UseReversedPass))

	if host.Service == "ssh" && !cfg.NoBadKeys {
		bundle, err := badkeys.Load()
		if err != nil {
			return 0, "", fmt.Errorf("loading bad-keys bundle: %w", err)
		}
		writeValue("ssh-badkeys")
		for _, entry := range bundle {
			writeValue(entry.Username)
			writeValue(entry.PEMHash)
		}
		attempts += len(bundle)
	}
	if host.Service == "ssh" && cfg.BadKeysOnly {
		return attempts, digest(), nil
	}
	attempts += countCredentialPairs(users, passCount, normalizedScheduleMode(cfg), cfg.UseUsernameAsPass, cfg.UseReversedPass)
	return attempts, digest(), nil
}

func countCredentialPairs(users []string, passwordCount int, mode string, useUsernameAsPass bool, useReversedPass bool) int {
	extra := 0
	if useUsernameAsPass {
		extra += len(users)
	}
	if useReversedPass {
		for _, user := range users {
			if reverseString(user) != user {
				extra++
			}
		}
	}
	if mode == "pairwise" {
		pairs := len(users)
		if passwordCount < pairs {
			pairs = passwordCount
		}
		return extra + pairs
	}
	return extra + len(users)*passwordCount
}

func normalizedScheduleMode(cfg *Config) string {
	if cfg.ScheduleMode != "" && cfg.ScheduleMode != "auto" {
		return cfg.ScheduleMode
	}
	if cfg.SprayMode {
		return "spray"
	}
	return "host-major"
}

func hostsFromPlanTargets(targets []PlannedTarget) []modules.Host {
	hosts := make([]modules.Host, 0, len(targets))
	for _, target := range targets {
		hosts = append(hosts, modules.Host{Service: target.Service, Host: target.Host, Port: target.Port})
	}
	return hosts
}

func sortPlan(plan *ExecutionPlan) {
	sort.Slice(plan.Targets, func(i, j int) bool {
		return comparePlanTarget(plan.Targets[i].Service, plan.Targets[i].Host, plan.Targets[i].Port, plan.Targets[j].Service, plan.Targets[j].Host, plan.Targets[j].Port)
	})
	sort.Slice(plan.ScopeRejects, func(i, j int) bool {
		return comparePlanTarget(plan.ScopeRejects[i].Service, plan.ScopeRejects[i].Host, plan.ScopeRejects[i].Port, plan.ScopeRejects[j].Service, plan.ScopeRejects[j].Host, plan.ScopeRejects[j].Port)
	})
	sort.Slice(plan.Warnings, func(i, j int) bool {
		if plan.Warnings[i].Code != plan.Warnings[j].Code {
			return plan.Warnings[i].Code < plan.Warnings[j].Code
		}
		return plan.Warnings[i].Message < plan.Warnings[j].Message
	})
}

func comparePlanTarget(aService, aHost string, aPort int, bService, bHost string, bPort int) bool {
	if aService != bService {
		return aService < bService
	}
	if aHost != bHost {
		return aHost < bHost
	}
	return aPort < bPort
}

func planHash(plan ExecutionPlan) string {
	stable := plan
	stable.GeneratedAt = time.Time{}
	stable.Hash = ""
	data, _ := json.Marshal(stable)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
