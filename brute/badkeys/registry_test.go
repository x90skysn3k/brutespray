package badkeys

import "testing"

func TestLoadReturnsNonEmptyBundle(t *testing.T) {
	bundle, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(bundle) < 5 {
		t.Fatalf("expected >=5 keys, got %d", len(bundle))
	}
}

func TestLoadParsesVagrantEntry(t *testing.T) {
	bundle, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, e := range bundle {
		if e.Vendor == "HashiCorp Vagrant" {
			if e.Username != "vagrant" {
				t.Fatalf("vagrant entry username = %q, want vagrant", e.Username)
			}
			if len(e.PEM) < 100 {
				t.Fatalf("vagrant PEM too short: %d bytes", len(e.PEM))
			}
			return
		}
	}
	t.Fatal("no Vagrant entry found in bundle")
}
