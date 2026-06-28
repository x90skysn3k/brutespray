package modules

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/x90skysn3k/brutespray/v2/wordlist"
)

func TestEmbeddedManifestLoading(t *testing.T) {
	m, err := LoadManifestFS(wordlist.FS, "manifest.yaml")
	if err != nil {
		t.Fatalf("LoadManifestFS: %v", err)
	}
	if len(m.Services) == 0 {
		t.Fatal("no services in manifest")
	}

	tests := []struct {
		service string
		kind    string
		minLen  int
	}{
		{"ssh", "users", 5},
		{"ssh", "passwords", 100},
		{"ftp", "users", 3},
		{"http", "users", 10},
		{"mysql", "passwords", 2},
		{"redis", "passwords", 50},
	}

	for _, tt := range tests {
		t.Run(tt.service+"/"+tt.kind, func(t *testing.T) {
			resolved, err := m.ResolveService(tt.service)
			if err != nil {
				t.Fatalf("ResolveService(%q): %v", tt.service, err)
			}
			var refs []string
			if tt.kind == "users" {
				refs = resolved.Users
			} else {
				refs = resolved.Passwords
			}
			if len(refs) == 0 {
				if tt.minLen > 0 {
					t.Fatalf("expected refs for %s/%s", tt.service, tt.kind)
				}
				return
			}
			words, err := m.LoadWordlistFS(refs, wordlist.FS)
			if err != nil {
				t.Fatalf("LoadWordlistFS: %v", err)
			}
			if len(words) < tt.minLen {
				t.Errorf("got %d words, want >= %d", len(words), tt.minLen)
			}
			t.Logf("%s/%s: %d entries, first: %q", tt.service, tt.kind, len(words), words[0])
		})
	}
}

func TestEmbeddedManifestReferencesValidate(t *testing.T) {
	m, err := LoadManifestFS(wordlist.FS, "manifest.yaml")
	if err != nil {
		t.Fatalf("LoadManifestFS: %v", err)
	}
	if err := m.ValidateFS(wordlist.FS); err != nil {
		t.Fatalf("ValidateFS: %v", err)
	}
}

func TestEmbeddedAliases(t *testing.T) {
	m, err := LoadManifestFS(wordlist.FS, "manifest.yaml")
	if err != nil {
		t.Fatalf("LoadManifestFS: %v", err)
	}
	// https should alias to http
	resolved, err := m.ResolveService("https")
	if err != nil {
		t.Fatalf("ResolveService(https): %v", err)
	}
	if len(resolved.Users) == 0 {
		t.Error("https alias should resolve to http users")
	}
}

func TestTryManifestFromFS(t *testing.T) {
	users, err := tryManifestFromFS(wordlist.FS, "ssh", "users")
	if err != nil {
		t.Fatalf("tryManifestFromFS: %v", err)
	}
	if len(users) == 0 {
		t.Error("expected SSH users from embedded FS")
	}
	t.Logf("SSH users from embedded FS: %d", len(users))
}

func TestTryLocalManifestLoadsUnixUserConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-style ~/.config path is not used on Windows")
	}
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(dir, "home")
	t.Setenv("HOME", home)

	configWordlist := filepath.Join(home, ".config", "brutespray", "wordlist")
	if err := os.MkdirAll(filepath.Join(configWordlist, "overrides", "ssh"), 0755); err != nil {
		t.Fatal(err)
	}
	manifest := `services:
  ssh:
    users:
      - overrides/ssh/user.txt
`
	if err := os.WriteFile(filepath.Join(configWordlist, "manifest.yaml"), []byte(manifest), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configWordlist, "overrides", "ssh", "user.txt"), []byte("config-user\n"), 0644); err != nil {
		t.Fatal(err)
	}

	users, err := tryLocalManifest("ssh", "users")
	if err != nil {
		t.Fatalf("tryLocalManifest: %v", err)
	}
	if len(users) != 1 || users[0] != "config-user" {
		t.Fatalf("users = %q, want [config-user]", users)
	}
}
