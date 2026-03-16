package brute

import (
	"strings"
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func TestBruteWrapperSuccess(t *testing.T) {
	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteWrapper("127.0.0.1", 9999, "user", "pass", 5*time.Second, cm, ModuleParams{
		"cmd":           "echo success && exit 0",
		"allow-wrapper": "true",
	})

	if !result.AuthSuccess {
		t.Fatalf("expected auth success (exit 0), got error: %v", result.Error)
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success")
	}
}

func TestBruteWrapperFailure(t *testing.T) {
	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteWrapper("127.0.0.1", 9999, "user", "pass", 5*time.Second, cm, ModuleParams{
		"cmd":           "exit 1",
		"allow-wrapper": "true",
	})

	if result.AuthSuccess {
		t.Fatal("expected auth failure (exit 1)")
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success (command ran, just failed)")
	}
}

func TestBruteWrapperPlaceholders(t *testing.T) {
	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteWrapper("10.0.0.1", 8080, "testuser", "testpass", 5*time.Second, cm, ModuleParams{
		"cmd":           "echo %H %P %U %W",
		"allow-wrapper": "true",
	})

	if !result.AuthSuccess {
		t.Fatalf("expected auth success, got error: %v", result.Error)
	}

	// Banner should contain the substituted values
	if !strings.Contains(result.Banner, "10.0.0.1") {
		t.Fatalf("expected banner to contain host, got %q", result.Banner)
	}
	if !strings.Contains(result.Banner, "8080") {
		t.Fatalf("expected banner to contain port, got %q", result.Banner)
	}
	if !strings.Contains(result.Banner, "testuser") {
		t.Fatalf("expected banner to contain username, got %q", result.Banner)
	}
	if !strings.Contains(result.Banner, "testpass") {
		t.Fatalf("expected banner to contain password, got %q", result.Banner)
	}
}

func TestBruteWrapperTimeout(t *testing.T) {
	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteWrapper("127.0.0.1", 9999, "user", "pass", 2*time.Second, cm, ModuleParams{
		"cmd":           "sleep 30",
		"allow-wrapper": "true",
	})

	if result.AuthSuccess {
		t.Fatal("expected auth failure on timeout")
	}
	if result.ConnectionSuccess {
		t.Fatal("expected connection failure on timeout")
	}
	if result.Error == nil {
		t.Fatal("expected timeout error")
	}
}

func TestBruteWrapperMissingCmd(t *testing.T) {
	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteWrapper("127.0.0.1", 9999, "user", "pass", 5*time.Second, cm, ModuleParams{
		"allow-wrapper": "true",
	})

	if result.AuthSuccess {
		t.Fatal("expected auth failure when cmd is missing")
	}
	if result.ConnectionSuccess {
		t.Fatal("expected connection failure when cmd is missing")
	}
	if result.Error == nil {
		t.Fatal("expected error about missing cmd parameter")
	}
	if !strings.Contains(result.Error.Error(), "cmd") {
		t.Fatalf("expected error to mention 'cmd', got: %v", result.Error)
	}
}

func TestBruteWrapperBanner(t *testing.T) {
	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteWrapper("127.0.0.1", 9999, "user", "pass", 5*time.Second, cm, ModuleParams{
		"cmd":           "echo 'banner output line'",
		"allow-wrapper": "true",
	})

	if !result.AuthSuccess {
		t.Fatalf("expected auth success, got error: %v", result.Error)
	}
	if !strings.Contains(result.Banner, "banner output line") {
		t.Fatalf("expected banner to capture stdout, got %q", result.Banner)
	}
}

func TestBruteWrapperBlockedWithoutFlag(t *testing.T) {
	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteWrapper("127.0.0.1", 9999, "user", "pass", 5*time.Second, cm, ModuleParams{
		"cmd": "echo hello",
	})

	if result.AuthSuccess {
		t.Fatal("expected auth failure without --allow-wrapper")
	}
	if result.ConnectionSuccess {
		t.Fatal("expected connection failure without --allow-wrapper")
	}
	if result.Error == nil || !strings.Contains(result.Error.Error(), "allow-wrapper") {
		t.Fatalf("expected error mentioning allow-wrapper, got: %v", result.Error)
	}
}
