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

func TestFormatModuleHelpMarksRequiredDescriptorParams(t *testing.T) {
	for _, tc := range []struct {
		service string
		params  []string
	}{
		{service: "http-form", params: []string{"body:required", "url:required"}},
		{service: "wrapper", params: []string{"cmd:required"}},
	} {
		t.Run(tc.service, func(t *testing.T) {
			out, err := formatModuleHelp(tc.service)
			if err != nil {
				t.Fatalf("formatModuleHelp: %v", err)
			}

			for _, want := range tc.params {
				requireModuleHelpParam(t, out, want)
			}
		})
	}
}

func TestFormatModuleHelpMarksTokenCredentialServices(t *testing.T) {
	out, err := formatModuleHelp("influxdb")
	if err != nil {
		t.Fatalf("formatModuleHelp: %v", err)
	}

	var credentials []string
	for _, field := range strings.Fields(out) {
		if strings.HasPrefix(field, "credentials=") {
			credentials = append(credentials, field)
		}
	}
	if len(credentials) != 1 || credentials[0] != "credentials=token" {
		t.Fatalf("module help should expose exactly token credentials for influxdb, got %v in:\n%s", credentials, out)
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

func TestFormatModuleHelpIncludesHTTPDescriptorParamMetadata(t *testing.T) {
	for _, service := range []string{"http", "https"} {
		t.Run(service, func(t *testing.T) {
			out, err := formatModuleHelp(service)
			if err != nil {
				t.Fatalf("formatModuleHelp: %v", err)
			}

			for _, want := range []string{"service=" + service, "routing=shared-http-client", "stability=stable"} {
				requireModuleHelpToken(t, out, want)
			}
			requireModuleHelpMetadataComponents(t, out, "HTTP auth allowed values", "auth", "BASIC", "DIGEST", "NTLM", "AUTO")
			requireModuleHelpMetadataComponents(t, out, "HTTP dir default path", "dir", "/")
		})
	}
}

func TestFormatModuleHelpKeepsHTTPAndHTTPSMetadataInParity(t *testing.T) {
	httpOut, err := formatModuleHelp("http")
	if err != nil {
		t.Fatalf("formatModuleHelp(http): %v", err)
	}
	httpsOut, err := formatModuleHelp("https")
	if err != nil {
		t.Fatalf("formatModuleHelp(https): %v", err)
	}

	httpFields := comparableModuleHelpFields(httpOut)
	httpsFields := comparableModuleHelpFields(httpsOut)
	if len(httpFields) != len(httpsFields) {
		t.Fatalf("http help fields = %v, https help fields = %v", httpFields, httpsFields)
	}
	for field := range httpFields {
		if !httpsFields[field] {
			t.Fatalf("https help missing http metadata field %q\nhttp:  %s\nhttps: %s", field, httpOut, httpsOut)
		}
	}
	for field := range httpsFields {
		if !httpFields[field] {
			t.Fatalf("http help missing https metadata field %q\nhttp:  %s\nhttps: %s", field, httpOut, httpsOut)
		}
	}
}

func TestFormatModuleHelpResolvesBackedAliasesOnly(t *testing.T) {
	out, err := formatModuleHelp("postgres")
	if err != nil {
		t.Fatalf("formatModuleHelp(postgres): %v", err)
	}
	requireModuleHelpToken(t, out, "service=postgres")

	out, err = formatModuleHelp("postgresql")
	if err != nil {
		t.Fatalf("formatModuleHelp(postgresql): %v", err)
	}
	requireModuleHelpToken(t, out, "service=postgres")

	if _, err := formatModuleHelp("pcanywheredata"); err == nil {
		t.Fatal("formatModuleHelp(pcanywheredata) succeeded, want unsupported alias error")
	}
}

func requireModuleHelpParam(t *testing.T, out, want string) {
	t.Helper()
	for _, field := range strings.Fields(out) {
		params, ok := strings.CutPrefix(field, "params=")
		if !ok {
			continue
		}
		for _, param := range strings.Split(params, ",") {
			if param == want {
				return
			}
		}
	}
	t.Fatalf("module help missing param %q in:\n%s", want, out)
}

func requireModuleHelpToken(t *testing.T, out, want string) {
	t.Helper()
	for _, field := range strings.Fields(out) {
		if field == want {
			return
		}
	}
	t.Fatalf("module help missing token %q in:\n%s", want, out)
}

func requireModuleHelpMetadataComponents(t *testing.T, out, label string, parts ...string) {
	t.Helper()
	for _, part := range parts {
		found := false
		for _, field := range strings.Fields(out) {
			if strings.Contains(field, "=") && strings.Contains(field, part) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("module help missing machine-readable %s component %q in:\n%s", label, part, out)
		}
	}
}

func comparableModuleHelpFields(out string) map[string]bool {
	fields := make(map[string]bool)
	for _, field := range strings.Fields(out) {
		if strings.HasPrefix(field, "service=") || strings.HasPrefix(field, "default_port=") {
			continue
		}
		fields[field] = true
	}
	return fields
}
