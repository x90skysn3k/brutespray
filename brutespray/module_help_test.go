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

func TestFormatModuleHelpIncludesDescriptorParams(t *testing.T) {
	out, err := formatModuleHelp("http-form")
	if err != nil {
		t.Fatalf("formatModuleHelp: %v", err)
	}
	for _, want := range []string{"routing=shared-http-client", "stability=beta", "url", "body", "csrf", "form-url", "content-type"} {
		if !strings.Contains(out, want) {
			t.Fatalf("module help missing %q in:\n%s", want, out)
		}
	}
}

func TestFormatModuleHelpIncludesRoutingCaveats(t *testing.T) {
	out, err := formatModuleHelp("neo4j")
	if err != nil {
		t.Fatalf("formatModuleHelp: %v", err)
	}
	if !strings.Contains(out, "routing=direct-library") {
		t.Fatalf("module help should disclose direct-library routing:\n%s", out)
	}
}
