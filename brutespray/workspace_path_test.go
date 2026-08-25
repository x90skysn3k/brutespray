package brutespray

import (
	"strings"
	"testing"
)

func TestWorkspaceStoreKindIsJSON(t *testing.T) {
	if WorkspaceStoreKind != "json" {
		t.Fatalf("WorkspaceStoreKind = %q, want json", WorkspaceStoreKind)
	}
}

func TestDefaultWorkspaceRootUsesBrutesprayDirectory(t *testing.T) {
	root := DefaultWorkspaceRoot()
	if !strings.Contains(root, "brutespray") || !strings.Contains(root, "workspaces") {
		t.Fatalf("workspace root = %q", root)
	}
}
