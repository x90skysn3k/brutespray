package brutespray

import "testing"

func TestWorkspaceCreateListUse(t *testing.T) {
	manager := NewWorkspaceManager(t.TempDir())
	if err := manager.Create("acme-q3"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := manager.Use("acme-q3"); err != nil {
		t.Fatalf("Use: %v", err)
	}
	current, err := manager.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if current != "acme-q3" {
		t.Fatalf("current = %q", current)
	}
	list, err := manager.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0] != "acme-q3" {
		t.Fatalf("list = %+v", list)
	}
}

func TestWorkspaceCommandCreate(t *testing.T) {
	manager := NewWorkspaceManager(t.TempDir())
	if err := WorkspaceCommand(manager, []string{"create", "acme-q3"}); err != nil {
		t.Fatalf("WorkspaceCommand: %v", err)
	}
	list, err := manager.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0] != "acme-q3" {
		t.Fatalf("list = %+v", list)
	}
}
