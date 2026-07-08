package modules

import (
	"strconv"
	"strings"
	"testing"
)

const masscanSample = `[
{"ip":"10.0.0.5","ports":[{"port":22,"proto":"tcp","status":"open"}]},
{"ip":"10.0.0.6","ports":[{"port":3306,"proto":"tcp","status":"open"},{"port":80,"proto":"tcp","status":"closed"}]},
{"ip":"10.0.0.7","ports":[{"port":3389,"proto":"tcp","status":"open"}]},
{"ip":"10.0.0.8","ports":[{"port":11111,"proto":"tcp","status":"open"}]}
]`

func TestParseMasscanJSON(t *testing.T) {
	hosts, err := ParseMasscanJSON(strings.NewReader(masscanSample))
	if err != nil {
		t.Fatalf("ParseMasscanJSON: %v", err)
	}
	// Want 3 hosts: closed port filtered AND unmapped port 11111 filtered
	if len(hosts) != 3 {
		t.Fatalf("want 3 hosts, got %d (%+v)", len(hosts), hosts)
	}
	want := map[string]string{
		"10.0.0.5:22":   "ssh",
		"10.0.0.6:3306": "mysql",
		"10.0.0.7:3389": "rdp",
	}
	for _, h := range hosts {
		key := h.Host + ":" + strconv.Itoa(h.Port)
		got, ok := want[key]
		if !ok || got != h.Service {
			t.Fatalf("unexpected host: %+v", h)
		}
	}
}

func TestParseMasscanJSONCanonicalDuplicateDefaults(t *testing.T) {
	in := `[
{"ip":"10.0.0.25","ports":[{"port":25,"proto":"tcp","status":"open"}]},
{"ip":"10.0.0.80","ports":[{"port":80,"proto":"tcp","status":"open"}]},
{"ip":"10.0.4.43","ports":[{"port":443,"proto":"tcp","status":"open"}]}
]`
	hosts, err := ParseMasscanJSON(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseMasscanJSON: %v", err)
	}
	if len(hosts) != 3 {
		t.Fatalf("want 3 hosts, got %d (%+v)", len(hosts), hosts)
	}
	want := []string{"smtp", "http", "https"}
	for i, service := range want {
		if hosts[i].Service != service {
			t.Fatalf("host %d service = %q, want %q (hosts: %+v)", i, hosts[i].Service, service, hosts)
		}
	}
}

func TestParseMasscanJSONDescriptorOnlyPortHasNoDefaultService(t *testing.T) {
	in := `[{"ip":"10.0.10.80","ports":[{"port":1080,"proto":"tcp","status":"open"}]}]`
	hosts, err := ParseMasscanJSON(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseMasscanJSON: %v", err)
	}
	if len(hosts) != 0 {
		t.Fatalf("descriptor-only port should not infer a default service, got %+v", hosts)
	}
}

func TestParseMasscanJSONEmpty(t *testing.T) {
	hosts, err := ParseMasscanJSON(strings.NewReader("[]"))
	if err != nil {
		t.Fatalf("empty array should parse: %v", err)
	}
	if len(hosts) != 0 {
		t.Fatalf("want empty, got %d", len(hosts))
	}
}

func TestParseMasscanJSONInvalid(t *testing.T) {
	_, err := ParseMasscanJSON(strings.NewReader("not json"))
	if err == nil {
		t.Fatal("expected parse error for garbage input")
	}
}

func TestDefaultServiceForPortKnown(t *testing.T) {
	cases := map[int]string{
		22:   "ssh",
		25:   "smtp",
		80:   "http",
		443:  "https",
		3306: "mysql",
		3389: "rdp",
		3690: "svn",
		5038: "asterisk",
	}
	for port, want := range cases {
		if got := defaultServiceForPort(port); got != want {
			t.Errorf("port %d: got %q, want %q", port, got, want)
		}
	}
}

func TestDefaultServiceForPortUnknown(t *testing.T) {
	if got := defaultServiceForPort(12345); got != "" {
		t.Fatalf("unknown port should return empty, got %q", got)
	}
}
