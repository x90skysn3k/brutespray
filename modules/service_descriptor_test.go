package modules

import "testing"

func TestServiceDescriptorsContainRegisteredSurface(t *testing.T) {
	required := []string{
		"ssh", "ftp", "ftps", "telnet", "smtp", "smtp-vrfy", "imap", "pop3",
		"mysql", "postgres", "mssql", "mongodb", "redis", "couchdb", "elasticsearch",
		"influxdb", "neo4j", "cassandra", "vnc", "snmp", "smbnt", "rdp", "http",
		"https", "http-form", "https-form", "vmauthd", "teamspeak", "asterisk",
		"nntp", "oracle", "xmpp", "ldap", "ldaps", "winrm", "rexec", "rlogin",
		"rsh", "wrapper", "socks5-auth", "svn",
	}

	descriptors := ServiceDescriptors()
	for _, service := range required {
		if _, ok := descriptors[service]; !ok {
			t.Fatalf("missing descriptor for %s", service)
		}
	}
}

func TestServiceDescriptorDefaults(t *testing.T) {
	descriptors := ServiceDescriptors()

	ssh, ok := descriptors["ssh"]
	if !ok {
		t.Fatal("missing ssh descriptor")
	}
	if ssh.DefaultPort != 22 {
		t.Fatalf("ssh default port = %d, want 22", ssh.DefaultPort)
	}
	if ssh.CredentialMode != CredentialUserPassword {
		t.Fatalf("ssh credential mode = %s, want %s", ssh.CredentialMode, CredentialUserPassword)
	}
	if ssh.Routing != RoutingConnectionManager {
		t.Fatalf("ssh routing = %s, want %s", ssh.Routing, RoutingConnectionManager)
	}

	vnc := descriptors["vnc"]
	if vnc.CredentialMode != CredentialPasswordOnly {
		t.Fatalf("vnc credential mode = %s, want %s", vnc.CredentialMode, CredentialPasswordOnly)
	}

	neo4j := descriptors["neo4j"]
	if neo4j.Routing != RoutingDirectLibrary {
		t.Fatalf("neo4j routing = %s, want %s", neo4j.Routing, RoutingDirectLibrary)
	}
}

func TestDescriptorForServiceMapsAliases(t *testing.T) {
	descriptor, ok := DescriptorForService("postgresql")
	if !ok {
		t.Fatal("postgresql alias did not resolve")
	}
	if descriptor.Name != "postgres" {
		t.Fatalf("postgresql descriptor = %s, want postgres", descriptor.Name)
	}
}
