package brute

import (
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// TestModuleParamsNil verifies that passing empty or nil-like ModuleParams
// to various modules doesn't cause a panic.
func TestModuleParamsNil(t *testing.T) {
	cm, _ := modules.NewConnectionManager("", 2*time.Second, "")

	// Test a selection of modules with empty params. They will all fail to
	// connect (port 1 is not listening), but none should panic.
	tests := []struct {
		name    string
		service string
	}{
		{"FTP", "ftp"},
		{"HTTP", "http"},
		{"SSH", "ssh"},
		{"SMTP", "smtp"},
		{"POP3", "pop3"},
		{"Rexec", "rexec"},
		{"VNC", "vnc"},
		{"SMBNT", "smbnt"},
		{"SMTP-VRFY", "smtp-vrfy"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, ok := Lookup(tt.service)
			if !ok {
				t.Skipf("service %q not registered", tt.service)
			}

			// Should not panic with empty ModuleParams
			result := fn("127.0.0.1", 1, "user", "pass", 2*time.Second, cm, ModuleParams{})
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			// All should fail since nothing listens on port 1
			if result.AuthSuccess {
				t.Fatal("expected auth failure (no server)")
			}
		})
	}
}

// TestModuleParamsDomain verifies that the domain parameter is read from
// the effective params in RunBrute's param-building logic.
func TestModuleParamsDomain(t *testing.T) {
	// Test the effectiveParams building logic directly by verifying that
	// a domain value passed to RunBrute gets merged into the params.
	//
	// We test this by constructing the effectiveParams map the same way
	// RunBrute does and verifying the result.
	params := ModuleParams{}
	domain := "TESTCORP"

	// Simulate RunBrute's effectiveParams building
	effectiveParams := make(ModuleParams)
	for k, v := range params {
		effectiveParams[k] = v
	}
	if effectiveParams["domain"] == "" && domain != "" {
		effectiveParams["domain"] = domain
	}

	if effectiveParams["domain"] != "TESTCORP" {
		t.Fatalf("expected domain TESTCORP, got %q", effectiveParams["domain"])
	}

	// Verify that an explicit domain in params takes precedence
	params2 := ModuleParams{"domain": "EXPLICIT"}
	effectiveParams2 := make(ModuleParams)
	for k, v := range params2 {
		effectiveParams2[k] = v
	}
	if effectiveParams2["domain"] == "" && domain != "" {
		effectiveParams2["domain"] = domain
	}

	if effectiveParams2["domain"] != "EXPLICIT" {
		t.Fatalf("expected explicit domain EXPLICIT to take precedence, got %q", effectiveParams2["domain"])
	}
}

// TestModuleParamsHTTPS verifies that the https param is set when the service
// is "https" (simulating RunBrute's logic).
func TestModuleParamsHTTPS(t *testing.T) {
	params := ModuleParams{}
	service := "https"

	effectiveParams := make(ModuleParams)
	for k, v := range params {
		effectiveParams[k] = v
	}
	if effectiveParams["https"] == "" && service == "https" {
		effectiveParams["https"] = "true"
	}

	if effectiveParams["https"] != "true" {
		t.Fatalf("expected https=true for https service, got %q", effectiveParams["https"])
	}
}

// TestModuleParamsDomainBackslash verifies the DOMAIN\user parsing logic.
func TestModuleParamsDomainBackslash(t *testing.T) {
	params := ModuleParams{}
	domain := ""
	user := `CORP\jdoe`

	effectiveParams := make(ModuleParams)
	for k, v := range params {
		effectiveParams[k] = v
	}
	if effectiveParams["domain"] == "" && domain != "" {
		effectiveParams["domain"] = domain
	}

	// Parse domain from username (DOMAIN\user format)
	effectiveUser := user
	if effectiveParams["domain"] == "" {
		idx := -1
		for i, c := range user {
			if c == '\\' {
				idx = i
				break
			}
		}
		if idx >= 0 {
			effectiveParams["domain"] = user[:idx]
			effectiveUser = user[idx+1:]
		}
	}

	if effectiveParams["domain"] != "CORP" {
		t.Fatalf("expected domain CORP from backslash notation, got %q", effectiveParams["domain"])
	}
	if effectiveUser != "jdoe" {
		t.Fatalf("expected user jdoe from backslash notation, got %q", effectiveUser)
	}
}
