package brutespray

import (
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestExecutePrintHostsExitsBeforeCredentialAttempts(t *testing.T) {
	if os.Getenv("BRUTESPRAY_PRINT_HOSTS_HELPER") == "1" {
		originalArgs := os.Args
		originalCommandLine := flag.CommandLine
		defer func() {
			os.Args = originalArgs
			flag.CommandLine = originalCommandLine
		}()

		os.Args = []string{
			os.Args[0],
			"-q", "-nc", "--no-tui", "-P",
			"-H", "ftp://127.0.0.1:1",
			"-u", "print-hosts-user",
			"-p", "print-hosts-password",
			"-r", "0",
			"-t", "1",
			"-T", "1",
			"-w", "10ms",
			"-o", t.TempDir(),
		}
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
		Execute()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestExecutePrintHostsExitsBeforeCredentialAttempts$", "-test.v")
	cmd.Env = append(os.Environ(), "BRUTESPRAY_PRINT_HOSTS_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("print-hosts helper failed: %v\n%s", err, out)
	}
	output := string(out)
	if !strings.Contains(output, "127.0.0.1") || !strings.Contains(output, "ftp on port 1") {
		t.Fatalf("parsed host table missing:\n%s", output)
	}
	if strings.Contains(output, "Testing credentials") || strings.Contains(output, "Processing host") {
		t.Fatalf("-P continued into credential attempts:\n%s", output)
	}
}
