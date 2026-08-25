package brutespray

import (
	"fmt"
	"os"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// AuditCommand handles audit log utilities.
func AuditCommand(args []string) error {
	if len(args) != 2 || args[0] != "verify" {
		return fmt.Errorf("usage: brutespray audit verify <audit.jsonl>")
	}
	key := os.Getenv("BRUTESPRAY_AUDIT_HMAC_KEY")
	if key == "" {
		return fmt.Errorf("BRUTESPRAY_AUDIT_HMAC_KEY is required to verify an audit log")
	}
	if err := modules.VerifyAuditLog(args[1], []byte(key)); err != nil {
		return fmt.Errorf("audit log verification failed: %w", err)
	}
	fmt.Printf("audit log verified: %s\n", args[1])
	return nil
}
