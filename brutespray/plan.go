package brutespray

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

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
	Service  string `json:"service"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Attempts int    `json:"attempts"`
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
	matcher, err := NewScopeMatcher(manifest.Scope)
	if err != nil {
		return ExecutionPlan{}, err
	}
	plan := ExecutionPlan{
		Version:      "brutespray.plan.v1",
		GeneratedAt:  time.Now().UTC(),
		EngagementID: manifest.Engagement.ID,
	}
	attemptsPerTarget := estimateAttemptsPerTarget(cfg)
	for _, host := range cfg.Hosts {
		allowed, reason := matcher.Allowed(host.Host)
		if !allowed {
			plan.ScopeRejects = append(plan.ScopeRejects, ScopeRejection{Service: host.Service, Host: host.Host, Port: host.Port, Reason: reason})
			continue
		}
		attempts := attemptsPerTarget
		if modules.IsPasswordOnlyService(host.Service) && attempts == 0 {
			attempts = estimatePasswordCount(cfg)
		}
		plan.Targets = append(plan.Targets, PlannedTarget{Service: host.Service, Host: host.Host, Port: host.Port, Attempts: attempts})
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

func estimateAttemptsPerTarget(cfg *Config) int {
	if cfg.Combo != "" || cfg.Creds != "" {
		return 1
	}
	users := estimateUserCount(cfg)
	passwords := estimatePasswordCount(cfg)
	if users == 0 || passwords == 0 {
		return 0
	}
	return users * passwords
}

func estimateUserCount(cfg *Config) int {
	if cfg.User != "" {
		return 1
	}
	return 0
}

func estimatePasswordCount(cfg *Config) int {
	if cfg.Password != "" || cfg.PasswordGenSpec != "" {
		return 1
	}
	return 0
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
