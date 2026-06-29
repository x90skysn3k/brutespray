package brutespray

import (
	"os"
	"path/filepath"
)

// WorkspaceStoreKind records the v2.3.0 storage decision: JSONL directories, no SQLite dependency.
const WorkspaceStoreKind = "json"

// DefaultWorkspaceRoot returns the default local workspace store root.
func DefaultWorkspaceRoot() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "brutespray", "workspaces")
	}
	return filepath.Join(".brutespray", "workspaces")
}
