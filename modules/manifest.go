package modules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// WordlistManifest defines the composable wordlist structure.
type WordlistManifest struct {
	Generated     string                     `yaml:"generated"`
	SeasonalRange [2]int                     `yaml:"seasonal_range"`
	Bases         map[string]string          `yaml:"bases"`
	Layers        map[string]string          `yaml:"layers"`
	Services      map[string]ServiceWordlist `yaml:"services"`
}

// ServiceWordlist defines how a service composes its wordlists.
type ServiceWordlist struct {
	Alias     string   `yaml:"alias,omitempty"`
	Users     []string `yaml:"users"`
	Passwords []string `yaml:"passwords"`
}

// LoadManifest reads and parses a manifest.yaml file.
func LoadManifest(path string) (*WordlistManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m WordlistManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}
	return &m, nil
}

// ResolveService follows aliases to find the actual service definition.
func (m *WordlistManifest) ResolveService(name string) (*ServiceWordlist, error) {
	seen := make(map[string]bool)
	current := name
	for {
		if seen[current] {
			return nil, fmt.Errorf("circular alias detected for service %q", name)
		}
		seen[current] = true
		sw, ok := m.Services[current]
		if !ok {
			return nil, fmt.Errorf("service %q not found in manifest", current)
		}
		if sw.Alias == "" {
			return &sw, nil
		}
		current = sw.Alias
	}
}

// resolvePath resolves a wordlist reference to a file path.
// If ref matches a key in bases or layers, use that path.
// Otherwise treat ref as a relative path under wordlistDir.
func (m *WordlistManifest) resolvePath(ref, wordlistDir string) string {
	if p, ok := m.Bases[ref]; ok {
		return filepath.Join(wordlistDir, p)
	}
	if p, ok := m.Layers[ref]; ok {
		return filepath.Join(wordlistDir, p)
	}
	return filepath.Join(wordlistDir, ref)
}

// LoadWordlist reads and merges multiple wordlist files, deduplicating in insertion order.
func (m *WordlistManifest) LoadWordlist(refs []string, wordlistDir string) ([]string, error) {
	seen := make(map[string]struct{})
	var result []string
	for _, ref := range refs {
		path := m.resolvePath(ref, wordlistDir)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading wordlist %q: %w", path, err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if _, exists := seen[line]; !exists {
				seen[line] = struct{}{}
				result = append(result, line)
			}
		}
	}
	return result, nil
}

// resolveRelPath resolves a wordlist reference to a relative path (no directory prefix).
func (m *WordlistManifest) resolveRelPath(ref string) string {
	if p, ok := m.Bases[ref]; ok {
		return p
	}
	if p, ok := m.Layers[ref]; ok {
		return p
	}
	return ref
}

// LoadWordlistFS reads and merges wordlists from an fs.FS, deduplicating in insertion order.
func (m *WordlistManifest) LoadWordlistFS(refs []string, fsys fs.FS) ([]string, error) {
	seen := make(map[string]struct{})
	var result []string
	for _, ref := range refs {
		path := m.resolveRelPath(ref)
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return nil, fmt.Errorf("reading wordlist %q: %w", path, err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if _, exists := seen[line]; !exists {
				seen[line] = struct{}{}
				result = append(result, line)
			}
		}
	}
	return result, nil
}

// LoadManifestFS reads and parses a manifest.yaml from an fs.FS.
func LoadManifestFS(fsys fs.FS, path string) (*WordlistManifest, error) {
	data, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, err
	}
	var m WordlistManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}
	return &m, nil
}
