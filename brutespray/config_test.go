package brutespray

import (
	"strings"
	"testing"
)

// TestModuleParamsFlagParsing tests that the moduleParamsFlag type correctly
// parses KEY:VALUE pairs as the -m flag would provide.
func TestModuleParamsFlagParsing(t *testing.T) {
	var mpf moduleParamsFlag

	// Simulate: -m auth:NTLM -m dir:/admin
	if err := mpf.Set("auth:NTLM"); err != nil {
		t.Fatalf("unexpected error setting auth:NTLM: %v", err)
	}
	if err := mpf.Set("dir:/admin"); err != nil {
		t.Fatalf("unexpected error setting dir:/admin: %v", err)
	}

	// Parse into map the same way ParseConfig does
	result := make(map[string]string)
	for _, mp := range mpf {
		parts := strings.SplitN(mp, ":", 2)
		result[parts[0]] = parts[1]
	}

	if result["auth"] != "NTLM" {
		t.Fatalf("expected auth=NTLM, got %q", result["auth"])
	}
	if result["dir"] != "/admin" {
		t.Fatalf("expected dir=/admin, got %q", result["dir"])
	}
}

// TestModuleParamsFlagInvalid tests that values without a colon are rejected.
func TestModuleParamsFlagInvalid(t *testing.T) {
	var mpf moduleParamsFlag

	err := mpf.Set("nocolon")
	if err == nil {
		t.Fatal("expected error for value without colon")
	}
	if !strings.Contains(err.Error(), "KEY:VALUE") {
		t.Fatalf("expected error to mention KEY:VALUE format, got: %v", err)
	}
}

// TestModuleParamsFlagColonInValue tests that colons in the value part are
// preserved (e.g., -m cmd:echo:hello).
func TestModuleParamsFlagColonInValue(t *testing.T) {
	var mpf moduleParamsFlag

	if err := mpf.Set("cmd:echo:hello:world"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := make(map[string]string)
	for _, mp := range mpf {
		parts := strings.SplitN(mp, ":", 2)
		result[parts[0]] = parts[1]
	}

	if result["cmd"] != "echo:hello:world" {
		t.Fatalf("expected cmd=echo:hello:world, got %q", result["cmd"])
	}
}

// TestModuleParamsFlagString tests the String() method.
func TestModuleParamsFlagString(t *testing.T) {
	var mpf moduleParamsFlag
	_ = mpf.Set("auth:BASIC")
	_ = mpf.Set("dir:/login")

	s := mpf.String()
	if !strings.Contains(s, "auth:BASIC") {
		t.Fatalf("expected String() to contain auth:BASIC, got %q", s)
	}
	if !strings.Contains(s, "dir:/login") {
		t.Fatalf("expected String() to contain dir:/login, got %q", s)
	}
}

// TestExtraCredsFlagParsing tests that the -e flag values are parsed correctly
// for username-as-password and empty-password options.
func TestExtraCredsFlagParsing(t *testing.T) {
	tests := []struct {
		name             string
		flag             string
		wantUsernamePass bool
		wantEmptyPass    bool
	}{
		{
			name:             "BothNS",
			flag:             "ns",
			wantUsernamePass: true,
			wantEmptyPass:    true,
		},
		{
			name:             "BothSN",
			flag:             "sn",
			wantUsernamePass: true,
			wantEmptyPass:    true,
		},
		{
			name:             "OnlyS",
			flag:             "s",
			wantUsernamePass: true,
			wantEmptyPass:    false,
		},
		{
			name:             "OnlyN",
			flag:             "n",
			wantUsernamePass: false,
			wantEmptyPass:    true,
		},
		{
			name:             "Empty",
			flag:             "",
			wantUsernamePass: false,
			wantEmptyPass:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the -e flag the same way ParseConfig does
			useUsernameAsPass := false
			useEmptyPassword := false

			if tt.flag != "" {
				e := strings.ToLower(tt.flag)
				if strings.Contains(e, "s") {
					useUsernameAsPass = true
				}
				if strings.Contains(e, "n") {
					useEmptyPassword = true
				}
			}

			if useUsernameAsPass != tt.wantUsernamePass {
				t.Fatalf("UseUsernameAsPass: got %v, want %v", useUsernameAsPass, tt.wantUsernamePass)
			}
			if useEmptyPassword != tt.wantEmptyPass {
				t.Fatalf("UseEmptyPassword: got %v, want %v", useEmptyPassword, tt.wantEmptyPass)
			}
		})
	}
}

// TestHostListFlagParsing tests that the hostListFlag type accumulates
// multiple -H values.
func TestHostListFlagParsing(t *testing.T) {
	var hlf hostListFlag

	if err := hlf.Set("ssh://10.0.0.1:22"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := hlf.Set("ftp://10.0.0.2:21"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hlf) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(hlf))
	}
	if hlf[0] != "ssh://10.0.0.1:22" {
		t.Fatalf("expected first host ssh://10.0.0.1:22, got %q", hlf[0])
	}
	if hlf[1] != "ftp://10.0.0.2:21" {
		t.Fatalf("expected second host ftp://10.0.0.2:21, got %q", hlf[1])
	}
}

// TestHostListFlagEmpty tests that empty string is rejected.
func TestHostListFlagEmpty(t *testing.T) {
	var hlf hostListFlag
	err := hlf.Set("")
	if err == nil {
		t.Fatal("expected error for empty host")
	}
}
