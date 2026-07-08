package modules

import (
	"os"
	"path/filepath"
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

func TestParseGNMAPNormalizesAliasesAndRejectsUnregisteredTokens(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "scan.gnmap")
	data := "# Nmap scan\n" +
		"Host: 10.0.0.4 ()\tPorts: 3389/open/tcp//ms-wbt-server//Microsoft Terminal Services/, 3388/open/tcp//rdp//Canonical RDP/, 1433/open/tcp//ms-sql-s//Microsoft SQL Server/, 5631/open/tcp//pcanywheredata//pcAnywhere/\n"
	if err := os.WriteFile(filename, []byte(data), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	hosts, err := ParseGNMAP(filename)
	if err != nil {
		t.Fatalf("ParseGNMAP: %v", err)
	}

	expected := []Host{
		{Service: "rdp", Host: "10.0.0.4", Port: 3389},
		{Service: "rdp", Host: "10.0.0.4", Port: 3388},
		{Service: "mssql", Host: "10.0.0.4", Port: 1433},
	}
	for _, h := range expected {
		if _, ok := hosts[h]; !ok {
			t.Fatalf("ParseGNMAP missing host %+v (got %+v)", h, hosts)
		}
	}

	rejected := []Host{
		{Service: "pcanywheredata", Host: "10.0.0.4", Port: 5631},
	}
	for _, h := range rejected {
		if _, ok := hosts[h]; ok {
			t.Fatalf("ParseGNMAP included unsupported host %+v (got %+v)", h, hosts)
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

func TestParseJSONFiltersAllowlistedServiceWithoutDescriptor(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "scan.json")
	data := `{"host":"10.0.0.9","port":"5631","service":"pcanywheredata"}`
	if err := os.WriteFile(filename, []byte(data), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	hosts, err := ParseJSON(filename)
	if err != nil {
		t.Fatalf("ParseJSON: %v", err)
	}
	if len(hosts) != 0 {
		t.Fatalf("allowlisted service without descriptor should be omitted, got %+v", hosts)
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

func TestParseListNormalizesAliasBeforeSupportCheck(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "targets.list")
	if err := os.WriteFile(filename, []byte("ms-sql-s:10.0.0.4:1433\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	hosts, err := ParseList(filename)
	if err != nil {
		t.Fatalf("ParseList: %v", err)
	}

	want := Host{Service: "mssql", Host: "10.0.0.4", Port: 1433}
	if _, ok := hosts[want]; !ok {
		t.Fatalf("ParseList missing normalized alias host %+v (got %+v)", want, hosts)
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
