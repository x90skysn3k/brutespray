package brute

import (
	"fmt"
	"testing"
	"time"
)

// TestVNCAntibruteDetection verifies that vncHandleResult correctly detects
// anti-brute-force patterns in VNC error messages and sets RetryDelay.
func TestVNCAntibruteDetection(t *testing.T) {
	tests := []struct {
		name          string
		errMsg        string
		wantDelay     bool
		wantBanner    string
	}{
		{
			name:       "TooManyAttempts",
			errMsg:     "too many authentication attempts",
			wantDelay:  true,
			wantBanner: "VNC anti-brute-force detected",
		},
		{
			name:       "Blacklisted",
			errMsg:     "your IP has been blacklisted",
			wantDelay:  true,
			wantBanner: "VNC anti-brute-force detected",
		},
		{
			name:       "SecurityType",
			errMsg:     "no matching security type",
			wantDelay:  true,
			wantBanner: "VNC anti-brute-force detected",
		},
		{
			name:      "NormalError",
			errMsg:    "authentication failed",
			wantDelay: false,
		},
		{
			name:      "ConnectionRefused",
			errMsg:    "connection refused",
			wantDelay: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := vncHandleResult(false, false, fmt.Errorf("%s", tt.errMsg), ModuleParams{})

			if tt.wantDelay {
				if result.RetryDelay == 0 {
					t.Fatal("expected RetryDelay to be set for anti-brute-force detection")
				}
				if result.RetryDelay != 60*time.Second {
					t.Fatalf("expected default RetryDelay of 60s, got %v", result.RetryDelay)
				}
				if result.Banner != tt.wantBanner {
					t.Fatalf("expected banner %q, got %q", tt.wantBanner, result.Banner)
				}
			} else {
				if result.RetryDelay != 0 {
					t.Fatalf("expected no RetryDelay, got %v", result.RetryDelay)
				}
			}
		})
	}
}

// TestVNCMaxSleepParam verifies that params["maxsleep"] controls the retry
// delay duration when anti-brute-force is detected.
func TestVNCMaxSleepParam(t *testing.T) {
	tests := []struct {
		name       string
		maxSleep   string
		wantDelay  time.Duration
	}{
		{
			name:      "Default60s",
			maxSleep:  "",
			wantDelay: 60 * time.Second,
		},
		{
			name:      "Custom30s",
			maxSleep:  "30",
			wantDelay: 30 * time.Second,
		},
		{
			name:      "Custom120s",
			maxSleep:  "120",
			wantDelay: 120 * time.Second,
		},
		{
			name:      "InvalidValue",
			maxSleep:  "notanumber",
			wantDelay: 60 * time.Second, // falls back to default
		},
		{
			name:      "ZeroValue",
			maxSleep:  "0",
			wantDelay: 60 * time.Second, // zero is invalid, falls back to default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := ModuleParams{}
			if tt.maxSleep != "" {
				params["maxsleep"] = tt.maxSleep
			}

			// Trigger anti-brute detection with a "too many" error
			result := vncHandleResult(false, false, fmt.Errorf("%s", "too many attempts"), params)

			if result.RetryDelay != tt.wantDelay {
				t.Fatalf("expected RetryDelay %v, got %v", tt.wantDelay, result.RetryDelay)
			}
		})
	}
}
