package modules

import (
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
