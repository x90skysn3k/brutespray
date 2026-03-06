package modules

import (
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
