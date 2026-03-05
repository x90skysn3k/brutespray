package brute

import (
	"context"
	"fmt"
	"time"

	"github.com/masterzen/winrm"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteWinRM(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) *BruteResult {
	endpoint := winrm.NewEndpoint(host, port, port == 5986, true, nil, nil, nil, timeout)

	params := winrm.DefaultParameters
	params.TransportDecorator = func() winrm.Transporter {
		return &winrm.ClientNTLM{}
	}

	client, err := winrm.NewClientWithParameters(endpoint, user, password, params)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Try to run a simple command to verify auth
	stdout, _, _, err := client.RunWithContextWithString(ctx, "hostname", "")
	if err != nil {
		errStr := fmt.Sprintf("%v", err)
		// WinRM returns HTTP 401 for bad creds
		if contains401(errStr) {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
		}
		if ctx.Err() != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: ctx.Err()}
		}
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
	}

	_ = stdout
	return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
}

func contains401(s string) bool {
	return len(s) > 0 && (containsSubstr(s, "401") || containsSubstr(s, "Unauthorized") || containsSubstr(s, "authorization"))
}

func containsSubstr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func init() { Register("winrm", BruteWinRM) }
