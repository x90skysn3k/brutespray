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

func TestDescriptorWinRMDoesNotAdvertiseSharedHTTPRouting(t *testing.T) {
	desc, ok := ServiceDescriptors()["winrm"]
	if !ok {
		t.Fatal("descriptor missing for winrm")
	}
	if desc.Routing == RoutingSharedHTTPClient {
		t.Fatalf("winrm routing = %s; BruteWinRM constructs the WinRM client directly and must not advertise shared HTTP routing", desc.Routing)
	}
	if desc.Routing != RoutingDirectLibrary {
		t.Fatalf("winrm routing = %s, want %s", desc.Routing, RoutingDirectLibrary)
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

func TestServiceDescriptorsIncludeObservedRuntimeParams(t *testing.T) {
	cases := map[string][]string{
		"couchdb":       {"tls"},
		"elasticsearch": {"tls"},
		"ftp":           {"mode"},
		"ftps":          {"mode"},
		"http":          {"auth", "custom-header", "dir", "domain", "https", "method", "user-agent"},
		"https":         {"auth", "custom-header", "dir", "domain", "https", "method", "user-agent"},
		"http-form":     {"body", "content-type", "cookie", "csrf", "fail", "follow", "form-url", "https", "method", "success", "url", "user-agent"},
		"https-form":    {"body", "content-type", "cookie", "csrf", "fail", "follow", "form-url", "https", "method", "success", "url", "user-agent"},
		"http-template": {"template", "template-inline"},
		"imap":          {"auth"},
		"influxdb":      {"mode", "tls"},
		"mssql":         {"domain"},
		"mysql":         {"dbname"},
		"pop3":          {"auth"},
		"postgres":      {"dbname"},
		"rdp":           {"domain"},
		"redis":         {"db"},
		"rexec":         {"cmd"},
		"rlogin":        {"local-user", "terminal"},
		"rsh":           {"cmd", "local-user"},
		"smbnt":         {"domain", "pass"},
		"smtp":          {"auth", "domain", "ehlo"},
		"smtp-vrfy":     {"domain", "verb"},
		"snmp":          {"auth", "mode", "priv", "privpass", "version"},
		"ssh":           {"auth", "key"},
		"svn":           {"https", "path"},
		"telnet":        {"success"},
		"vnc":           {"maxsleep"},
		"wrapper":       {"cmd"},
	}

	descriptors := ServiceDescriptors()
	for service, params := range cases {
		desc, ok := descriptors[service]
		if !ok {
			t.Fatalf("descriptor missing for %s", service)
		}
		have := map[string]bool{}
		for _, p := range desc.Params {
			have[p.Name] = true
		}
		for _, want := range params {
			if !have[want] {
				t.Fatalf("descriptor %s missing observed runtime param %s", service, want)
			}
		}
	}
}

func TestWinRMDescriptorDoesNotExposeUnsupportedDomainParam(t *testing.T) {
	desc, ok := ServiceDescriptors()["winrm"]
	if !ok {
		t.Fatal("descriptor missing for winrm")
	}
	for _, param := range desc.Params {
		if param.Name == "domain" {
			t.Fatal("winrm descriptor exposes unsupported domain param")
		}
	}
}

func TestServiceDescriptorsDoNotExposeInternalWrapperGate(t *testing.T) {
	desc, ok := ServiceDescriptors()["wrapper"]
	if !ok {
		t.Fatal("descriptor missing for wrapper")
	}
	for _, param := range desc.Params {
		if param.Name == "allow-wrapper" {
			t.Fatal("wrapper descriptor exposes internal allow-wrapper gate")
		}
	}
}
