package modules

import (
	"os"
	"testing"
)

func TestParseGNMAP(t *testing.T) {
	hosts, err := ParseGNMAP("testdata/test.gnmap")
	if err != nil {
		t.Fatalf("ParseGNMAP: %v", err)
	}

	expected := []Host{
		{Service: "ssh", Host: "10.0.0.1", Port: 22},
		{Service: "mysql", Host: "10.0.0.2", Port: 3306},
		{Service: "postgres", Host: "10.0.0.2", Port: 5432},
		{Service: "smbnt", Host: "10.0.0.3", Port: 445},
	}

	for _, h := range expected {
		if _, ok := hosts[h]; !ok {
			t.Errorf("ParseGNMAP: missing host %+v", h)
		}
	}
}

func TestParseXML(t *testing.T) {
	hosts, err := ParseXML("testdata/test_nmap.xml")
	if err != nil {
		t.Fatalf("ParseXML: %v", err)
	}

	expected := []Host{
		{Service: "ssh", Host: "10.0.0.1", Port: 22},
		{Service: "http", Host: "10.0.0.1", Port: 80},
		{Service: "mysql", Host: "10.0.0.2", Port: 3306},
	}

	for _, h := range expected {
		if _, ok := hosts[h]; !ok {
			t.Errorf("ParseXML: missing host %+v", h)
		}
	}
}

func TestParseJSON(t *testing.T) {
	hosts, err := ParseJSON("testdata/test.json")
	if err != nil {
		t.Fatalf("ParseJSON: %v", err)
	}

	expected := []Host{
		{Service: "ssh", Host: "10.0.0.1", Port: 22},
		{Service: "mysql", Host: "10.0.0.2", Port: 3306},
	}

	for _, h := range expected {
		if _, ok := hosts[h]; !ok {
			t.Errorf("ParseJSON: missing host %+v", h)
		}
	}

	if len(hosts) != 2 {
		t.Errorf("ParseJSON: expected 2 hosts, got %d", len(hosts))
	}
}

func TestParseList(t *testing.T) {
	hosts, err := ParseList("testdata/test.list")
	if err != nil {
		t.Fatalf("ParseList: %v", err)
	}

	expected := []Host{
		{Service: "ssh", Host: "10.0.0.1", Port: 22},
		{Service: "mysql", Host: "10.0.0.2", Port: 3306},
		{Service: "ftp", Host: "10.0.0.3", Port: 21},
	}

	for _, h := range expected {
		if _, ok := hosts[h]; !ok {
			t.Errorf("ParseList: missing host %+v", h)
		}
	}
}

func TestParseListServiceNames(t *testing.T) {
	cases := []struct {
		line string
		want Host
	}{
		{"rdp:10.0.0.1:3389", Host{Service: "rdp", Host: "10.0.0.1", Port: 3389}},
		{"ms-wbt-server:10.0.0.1:3389", Host{Service: "rdp", Host: "10.0.0.1", Port: 3389}},
		{"mssql:10.0.0.2:1433", Host{Service: "mssql", Host: "10.0.0.2", Port: 1433}},
		{"ms-sql-s:10.0.0.2:1433", Host{Service: "mssql", Host: "10.0.0.2", Port: 1433}},
		{"smbnt:10.0.0.3:445", Host{Service: "smbnt", Host: "10.0.0.3", Port: 445}},
	}
	for _, tc := range cases {
		dir := t.TempDir()
		path := dir + "/targets.list"
		if err := os.WriteFile(path, []byte(tc.line+"\n"), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		hosts, err := ParseList(path)
		if err != nil {
			t.Errorf("ParseList(%q): %v", tc.line, err)
			continue
		}
		if _, ok := hosts[tc.want]; !ok {
			t.Errorf("ParseList(%q): missing host %+v, got %v", tc.line, tc.want, hosts)
		}
	}

	dir := t.TempDir()
	path := dir + "/bad.list"
	if err := os.WriteFile(path, []byte("bogus-svc:10.0.0.1:1234\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, err := ParseList(path); err == nil {
		t.Error("ParseList: expected error for unsupported service, got nil")
	}
}

func TestMapService(t *testing.T) {
	tests := map[string]string{
		"ms-sql-s":     "mssql",
		"microsoft-ds": "smbnt",
		"postgresql":   "postgres",
		"smtps":        "smtp",
		"ssh":          "ssh",
		"unknown":      "unknown",
		"exec":         "rexec",
		"login":        "rlogin",
		"shell":        "rsh",
		"ftp-ssl":      "ftps",
		"ftps":         "ftps",
	}

	for input, want := range tests {
		got := MapService(input)
		if got != want {
			t.Errorf("MapService(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestParseGNMAP_FileNotFound(t *testing.T) {
	_, err := ParseGNMAP("testdata/nonexistent.gnmap")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}
