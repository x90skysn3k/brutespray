package brutespray

import (
	"fmt"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// AuditCommand handles audit log utilities.
func AuditCommand(args []string) error {
	if len(args) != 2 || args[0] != "verify" {
		return fmt.Errorf("usage: brutespray audit verify <audit.jsonl>")
	}
	if err := modules.VerifyAuditLog(args[1]); err != nil {
		return fmt.Errorf("audit log verification failed: %w", err)
	}
	fmt.Printf("audit log verified: %s\n", args[1])
	return nil
}
