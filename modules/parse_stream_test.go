package modules

import (
	"strings"
	"testing"
)

func TestDetectStreamFormat(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"bare-host-port", "10.0.0.5:22\n10.0.0.6:3389\n", "naabu"},
		{"nerva-uri", "ssh://10.0.0.5:22\nmysql://10.0.0.6:3306\n", "nerva-uri"},
		{"nerva-json", `{"ip":"10.0.0.5","port":22,"protocol":"ssh"}`, "nerva-json"},
		{"masscan-json", `[{"ip":"10.0.0.5","ports":[{"port":22,"proto":"tcp","status":"open"}]}]`, "masscan-json"},
		{"fingerprintx-json", `{"host":"10.0.0.5","ip":"10.0.0.5","port":22,"service":"ssh","transport":"tcp"}`, "fingerprintx-json"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := DetectStreamFormat(strings.NewReader(c.in))
			if err != nil {
				t.Fatalf("DetectStreamFormat: %v", err)
			}
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestParseStreamNaabu(t *testing.T) {
	hosts, err := ParseStream(strings.NewReader("10.0.0.5:22\n10.0.0.6:3389\n"))
	if err != nil {
		t.Fatalf("ParseStream: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("want 2, got %d", len(hosts))
	}
	if hosts[0].Service != "ssh" || hosts[1].Service != "rdp" {
		t.Fatalf("port→service mapping failed: %+v", hosts)
	}
}

func TestParseStreamNervaURI(t *testing.T) {
	hosts, err := ParseStream(strings.NewReader("ssh://10.0.0.5:22\nmysql://10.0.0.6:3306 (resolved.example)\n"))
	if err != nil {
		t.Fatalf("ParseStream: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("want 2, got %d", len(hosts))
	}
	if hosts[0].Service != "ssh" || hosts[1].Service != "mysql" {
		t.Fatalf("uri parse failed: %+v", hosts)
	}
	if hosts[1].Host != "10.0.0.6" || hosts[1].Port != 3306 {
		t.Fatalf("parenthetical suffix not stripped: %+v", hosts[1])
	}
}

func TestParseStreamNervaJSON(t *testing.T) {
	in := `{"ip":"10.0.0.5","port":22,"protocol":"ssh"}
{"ip":"10.0.0.6","port":3389,"protocol":"rdp"}`
	hosts, err := ParseStream(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseStream: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("want 2, got %d", len(hosts))
	}
}

func TestParseStreamFingerprintX(t *testing.T) {
	in := `{"host":"10.0.0.5","ip":"10.0.0.5","port":22,"service":"ssh","transport":"tcp"}`
	hosts, err := ParseStream(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseStream: %v", err)
	}
	if len(hosts) != 1 || hosts[0].Service != "ssh" {
		t.Fatalf("fingerprintx parse failed: %+v", hosts)
	}
}

func TestParseStreamMasscan(t *testing.T) {
	in := `[{"ip":"10.0.0.5","ports":[{"port":22,"proto":"tcp","status":"open"}]}]`
	hosts, err := ParseStream(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseStream: %v", err)
	}
	if len(hosts) != 1 || hosts[0].Service != "ssh" {
		t.Fatalf("masscan parse failed: %+v", hosts)
	}
}

func TestDetectStreamEmpty(t *testing.T) {
	_, err := DetectStreamFormat(strings.NewReader(""))
	if err == nil {
		t.Fatal("empty stream should error")
	}
}
