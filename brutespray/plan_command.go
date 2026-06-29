package brutespray

import (
	"encoding/json"
	"fmt"
	"os"
)

// RunPlanCommand builds and emits a dry-run execution plan.
func RunPlanCommand(cfg *Config) (ExecutionPlan, error) {
	manifest, err := LoadEngagementManifest(cfg.EngagementFile)
	if err != nil {
		return ExecutionPlan{}, err
	}
	plan, err := BuildExecutionPlan(cfg, manifest)
	if err != nil {
		return ExecutionPlan{}, err
	}
	if err := EmitExecutionPlan(cfg, plan); err != nil {
		return ExecutionPlan{}, err
	}
	return plan, nil
}

// EmitExecutionPlan writes a plan to stdout or the configured plan output file.
func EmitExecutionPlan(cfg *Config, plan ExecutionPlan) error {
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling plan: %w", err)
	}
	data = append(data, '\n')
	if cfg.PlanOut != "" {
		if err := os.WriteFile(cfg.PlanOut, data, 0o600); err != nil {
			return fmt.Errorf("writing plan: %w", err)
		}
		return nil
	}
	_, err = os.Stdout.Write(data)
	if err != nil {
		return fmt.Errorf("writing plan: %w", err)
	}
	return nil
}

// ValidatePlanAcknowledgement aborts execution unless the current plan hash was acknowledged.
func ValidatePlanAcknowledgement(cfg *Config, plan ExecutionPlan) error {
	if cfg.RequirePlanAck == "" {
		return nil
	}
	if cfg.RequirePlanAck != plan.Hash {
		return fmt.Errorf("plan hash %s does not match required acknowledgment %s", plan.Hash, cfg.RequirePlanAck)
	}
	return nil
}
