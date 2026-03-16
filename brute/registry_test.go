package brute

import (
	"testing"
)

func TestAllModulesRegistered(t *testing.T) {
	expected := []string{
		"ssh", "ftp", "ftps", "smtp", "mssql", "telnet", "smbnt", "postgres",
		"imap", "pop3", "snmp", "mysql", "vmauthd", "asterisk", "vnc",
		"mongodb", "nntp", "oracle", "teamspeak", "xmpp", "rdp", "redis",
		"http", "https", "ldap", "ldaps", "winrm",
		"smtp-vrfy", "rexec", "rlogin", "rsh", "wrapper",
	}

	for _, svc := range expected {
		if !IsRegistered(svc) {
			t.Errorf("service %q not registered", svc)
		}
	}
}

func TestServicesReturnsSortedList(t *testing.T) {
	services := Services()
	if len(services) == 0 {
		t.Fatal("Services() returned empty list")
	}

	for i := 1; i < len(services); i++ {
		if services[i] < services[i-1] {
			t.Errorf("Services() not sorted: %q before %q", services[i-1], services[i])
		}
	}
}

func TestLookupReturnsFunction(t *testing.T) {
	fn, ok := Lookup("ssh")
	if !ok || fn == nil {
		t.Error("ssh should be registered")
	}

	fn, ok = Lookup("smbnt")
	if !ok || fn == nil {
		t.Error("smbnt should be registered")
	}

	fn, ok = Lookup("http")
	if !ok || fn == nil {
		t.Error("http should be registered")
	}

	fn, ok = Lookup("wrapper")
	if !ok || fn == nil {
		t.Error("wrapper should be registered")
	}

	// Unknown
	_, ok = Lookup("nonexistent")
	if ok {
		t.Error("nonexistent service should not be registered")
	}
}
