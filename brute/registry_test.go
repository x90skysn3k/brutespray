package brute

import (
	"testing"
)

func TestAllModulesRegistered(t *testing.T) {
	expected := []string{
		"ssh", "ftp", "smtp", "mssql", "telnet", "smbnt", "postgres",
		"imap", "pop3", "snmp", "mysql", "vmauthd", "asterisk", "vnc",
		"mongodb", "nntp", "oracle", "teamspeak", "xmpp", "rdp", "redis",
		"http", "https",
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

func TestLookupReturnsCorrectType(t *testing.T) {
	// Standard module
	entry, ok := Lookup("ssh")
	if !ok || entry.standard == nil {
		t.Error("ssh should be a standard module")
	}

	// Domain module
	entry, ok = Lookup("smbnt")
	if !ok || entry.withDomain == nil {
		t.Error("smbnt should be a domain module")
	}

	// HTTP module
	entry, ok = Lookup("http")
	if !ok || entry.http == nil {
		t.Error("http should be an HTTP module")
	}

	// Unknown
	_, ok = Lookup("nonexistent")
	if ok {
		t.Error("nonexistent service should not be registered")
	}
}
