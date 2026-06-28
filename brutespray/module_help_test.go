package brutespray

import (
	"strings"
	"testing"
)

func TestFormatModuleHelpIncludesDefaultPort(t *testing.T) {
	out, err := formatModuleHelp("ssh")
	if err != nil {
		t.Fatalf("formatModuleHelp: %v", err)
	}
	for _, want := range []string{"service=ssh", "default_port=22", "credentials=user,password"} {
		if !strings.Contains(out, want) {
			t.Fatalf("module help missing %q in:\n%s", want, out)
		}
	}
}

func TestFormatModuleHelpMarksPasswordOnlyServices(t *testing.T) {
	out, err := formatModuleHelp("vnc")
	if err != nil {
		t.Fatalf("formatModuleHelp: %v", err)
	}
	if !strings.Contains(out, "credentials=password") {
		t.Fatalf("module help should mark vnc password-only:\n%s", out)
	}
}
