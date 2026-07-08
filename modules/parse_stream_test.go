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

func TestParseStreamNaabuCanonicalDuplicateDefaults(t *testing.T) {
	hosts, err := ParseStream(strings.NewReader("10.0.0.25:25\n10.0.0.80:80\n10.0.4.43:443\n"))
	if err != nil {
		t.Fatalf("ParseStream: %v", err)
	}
	if len(hosts) != 3 {
		t.Fatalf("want 3, got %d (%+v)", len(hosts), hosts)
	}
	want := []string{"smtp", "http", "https"}
	for i, service := range want {
		if hosts[i].Service != service {
			t.Fatalf("host %d service = %q, want %q (hosts: %+v)", i, hosts[i].Service, service, hosts)
		}
	}
}

func TestParseStreamNaabuPortZeroHasNoDefaultService(t *testing.T) {
	hosts, err := ParseStream(strings.NewReader("127.0.0.1:0\n"))
	if err != nil {
		t.Fatalf("ParseStream: %v", err)
	}
	if len(hosts) != 0 {
		t.Fatalf("port 0 should not infer a default service, got %+v", hosts)
	}
}

func TestParseStreamNaabuDescriptorOnlyPortHasNoDefaultService(t *testing.T) {
	hosts, err := ParseStream(strings.NewReader("127.0.0.1:1080\n"))
	if err != nil {
		t.Fatalf("ParseStream: %v", err)
	}
	if len(hosts) != 0 {
		t.Fatalf("descriptor-only port should not infer a default service, got %+v", hosts)
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
{"ip":"10.0.0.6","port":3389,"protocol":"ms-wbt-server"}`
	hosts, err := ParseStream(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseStream: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("want 2, got %d", len(hosts))
	}
	if hosts[1].Service != "rdp" {
		t.Fatalf("raw scanner alias did not map to rdp: %+v", hosts)
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

func TestParseStreamServiceAliasesNormalize(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "nerva-uri",
			in:   "ms-wbt-server://10.0.0.5:3389\n",
			want: "rdp",
		},
		{
			name: "nerva-json",
			in:   `{"ip":"10.0.0.6","port":445,"protocol":"microsoft-ds"}`,
			want: "smbnt",
		},
		{
			name: "fingerprintx-json",
			in:   `{"host":"10.0.0.7","ip":"10.0.0.7","port":3389,"service":"ms-wbt-server","transport":"tcp"}`,
			want: "rdp",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hosts, err := ParseStream(strings.NewReader(tc.in))
			if err != nil {
				t.Fatalf("ParseStream: %v", err)
			}
			if len(hosts) != 1 {
				t.Fatalf("want 1 host, got %d (%+v)", len(hosts), hosts)
			}
			if hosts[0].Service != tc.want {
				t.Fatalf("service = %q, want %q (hosts: %+v)", hosts[0].Service, tc.want, hosts)
			}
		})
	}
}

func TestParseStreamAcceptsCanonicalServicesReachableFromScannerAliases(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want Host
	}{
		{
			name: "nerva-uri-rdp",
			in:   "rdp://10.0.0.5:3389\n",
			want: Host{Service: "rdp", Host: "10.0.0.5", Port: 3389},
		},
		{
			name: "nerva-json-mssql",
			in:   `{"ip":"10.0.0.6","port":1433,"protocol":"mssql"}`,
			want: Host{Service: "mssql", Host: "10.0.0.6", Port: 1433},
		},
		{
			name: "fingerprintx-json-smbnt",
			in:   `{"host":"10.0.0.7","ip":"10.0.0.7","port":445,"service":"smbnt","transport":"tcp"}`,
			want: Host{Service: "smbnt", Host: "10.0.0.7", Port: 445},
		},
		{
			name: "nerva-json-winrm",
			in:   `{"ip":"10.0.0.8","port":5985,"protocol":"winrm"}`,
			want: Host{Service: "winrm", Host: "10.0.0.8", Port: 5985},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hosts, err := ParseStream(strings.NewReader(tc.in))
			if err != nil {
				t.Fatalf("ParseStream: %v", err)
			}
			if len(hosts) != 1 {
				t.Fatalf("want 1 host, got %d (%+v)", len(hosts), hosts)
			}
			if hosts[0] != tc.want {
				t.Fatalf("host = %+v, want %+v", hosts[0], tc.want)
			}
		})
	}
}

func TestParseStreamDropsAllowlistedServiceWithoutDescriptorAndKeepsValidHosts(t *testing.T) {
	in := "pcanywheredata://10.0.0.11:5631\nssh://10.0.0.5:22\n"
	hosts, err := ParseStream(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseStream: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("want only valid host, got %+v", hosts)
	}
	if hosts[0] != (Host{Service: "ssh", Host: "10.0.0.5", Port: 22}) {
		t.Fatalf("unexpected host %+v", hosts[0])
	}
}

func TestParseStreamUnsupportedServicesFailClosed(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{
			name: "nerva-uri",
			in:   "gopher://10.0.0.5:70\n",
		},
		{
			name: "nerva-uri legacy allowlisted without descriptor",
			in:   "pcanywheredata://10.0.0.11:5631\n",
		},
		{
			name: "nerva-uri descriptor-only",
			in:   "http-template://10.0.0.8:80\n",
		},
		{
			name: "nerva-json",
			in:   `{"ip":"10.0.0.6","port":70,"protocol":"gopher"}`,
		},
		{
			name: "nerva-json legacy allowlisted without descriptor",
			in:   `{"ip":"10.0.0.12","port":5631,"protocol":"pcanywheredata"}`,
		},
		{
			name: "nerva-json descriptor-only",
			in:   `{"ip":"10.0.0.9","port":1080,"protocol":"socks5-auth"}`,
		},
		{
			name: "fingerprintx-json",
			in:   `{"host":"10.0.0.7","ip":"10.0.0.7","port":70,"service":"gopher","transport":"tcp"}`,
		},
		{
			name: "fingerprintx-json legacy allowlisted without descriptor",
			in:   `{"host":"10.0.0.13","ip":"10.0.0.13","port":5631,"service":"pcanywheredata","transport":"tcp"}`,
		},
		{
			name: "fingerprintx-json descriptor-only",
			in:   `{"host":"10.0.0.10","ip":"10.0.0.10","port":0,"service":"wrapper","transport":"tcp"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hosts, err := ParseStream(strings.NewReader(tc.in))
			if err != nil {
				t.Fatalf("ParseStream: %v", err)
			}
			if len(hosts) != 0 {
				t.Fatalf("unsupported service should be omitted, got %+v", hosts)
			}
		})
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
