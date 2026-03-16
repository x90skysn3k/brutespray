package brute

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// BruteWrapper executes an external command with credential placeholders.
// Placeholders: %H (host), %P (port), %U (user), %W (password).
// Exit code 0 = success. Requires params["cmd"] to be set.
func BruteWrapper(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	cmdTemplate := params["cmd"]
	if cmdTemplate == "" {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false,
			Error: fmt.Errorf("wrapper module requires -m cmd:COMMAND parameter")}
	}

	// Replace placeholders
	cmd := cmdTemplate
	cmd = strings.ReplaceAll(cmd, "%H", host)
	cmd = strings.ReplaceAll(cmd, "%P", strconv.Itoa(port))
	cmd = strings.ReplaceAll(cmd, "%U", user)
	cmd = strings.ReplaceAll(cmd, "%W", password)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Execute command via shell
	proc := exec.CommandContext(ctx, "sh", "-c", cmd)
	output, err := proc.CombinedOutput()

	if ctx.Err() != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: ctx.Err()}
	}

	banner := ""
	if len(output) > 0 {
		// Capture first line of output as banner (truncated)
		lines := strings.SplitN(string(output), "\n", 2)
		banner = strings.TrimSpace(lines[0])
		if len(banner) > 200 {
			banner = banner[:200]
		}
	}

	if err != nil {
		// Non-zero exit code = auth failure (but connection succeeded)
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err, Banner: banner}
	}

	// Exit code 0 = success
	return &BruteResult{AuthSuccess: true, ConnectionSuccess: true, Banner: banner}
}

func init() { Register("wrapper", BruteWrapper) }
