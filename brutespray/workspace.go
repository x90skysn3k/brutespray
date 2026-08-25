package brutespray

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// WorkspaceManager manages local workspace directories.
type WorkspaceManager struct {
	root string
}

// NewWorkspaceManager creates a manager rooted at root.
func NewWorkspaceManager(root string) *WorkspaceManager {
	return &WorkspaceManager{root: root}
}

// Create creates a workspace directory.
func (m *WorkspaceManager) Create(name string) error {
	if !safeWorkspaceName(name) {
		return fmt.Errorf("invalid workspace name %q", name)
	}
	return os.MkdirAll(filepath.Join(m.root, name), 0o700)
}

// Use marks a workspace as current.
func (m *WorkspaceManager) Use(name string) error {
	if !safeWorkspaceName(name) {
		return fmt.Errorf("invalid workspace name %q", name)
	}
	if _, err := os.Stat(filepath.Join(m.root, name)); err != nil {
		return err
	}
	if err := os.MkdirAll(m.root, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(m.root, ".current"), []byte(name+"\n"), 0o600)
}

// Current returns the selected workspace.
func (m *WorkspaceManager) Current() (string, error) {
	data, err := os.ReadFile(filepath.Join(m.root, ".current"))
	if err != nil {
		return "", err
	}
	name := string(bytesTrimSpace(data))
	if !safeWorkspaceName(name) {
		return "", fmt.Errorf("invalid current workspace %q", name)
	}
	return name, nil
}

// List lists workspace directories.
func (m *WorkspaceManager) List() ([]string, error) {
	entries, err := os.ReadDir(m.root)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	workspaces := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() && safeWorkspaceName(entry.Name()) {
			workspaces = append(workspaces, entry.Name())
		}
	}
	sort.Strings(workspaces)
	return workspaces, nil
}

// WorkspaceCommand handles workspace subcommands.
func WorkspaceCommand(manager *WorkspaceManager, args []string) error {
	if manager == nil {
		manager = NewWorkspaceManager(DefaultWorkspaceRoot())
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: brutespray workspace <create|list|use|current> [name]")
	}
	switch args[0] {
	case "create":
		if len(args) != 2 {
			return fmt.Errorf("usage: brutespray workspace create <name>")
		}
		return manager.Create(args[1])
	case "use":
		if len(args) != 2 {
			return fmt.Errorf("usage: brutespray workspace use <name>")
		}
		return manager.Use(args[1])
	case "list":
		if len(args) != 1 {
			return fmt.Errorf("usage: brutespray workspace list")
		}
		list, err := manager.List()
		if err != nil {
			return err
		}
		for _, name := range list {
			fmt.Println(name)
		}
		return nil
	case "current":
		if len(args) != 1 {
			return fmt.Errorf("usage: brutespray workspace current")
		}
		current, err := manager.Current()
		if err != nil {
			return err
		}
		fmt.Println(current)
		return nil
	default:
		return fmt.Errorf("unknown workspace command %q", args[0])
	}
}

func safeWorkspaceName(name string) bool {
	if name == "" || filepath.Base(name) != name {
		return false
	}
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func bytesTrimSpace(data []byte) []byte {
	for len(data) > 0 && (data[0] == ' ' || data[0] == '\n' || data[0] == '\t' || data[0] == '\r') {
		data = data[1:]
	}
	for len(data) > 0 && (data[len(data)-1] == ' ' || data[len(data)-1] == '\n' || data[len(data)-1] == '\t' || data[len(data)-1] == '\r') {
		data = data[:len(data)-1]
	}
	return data
}
