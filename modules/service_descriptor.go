package modules

// CredentialMode describes the credential material a service consumes.
type CredentialMode string

const (
	CredentialUserPassword CredentialMode = "user-password"
	CredentialPasswordOnly CredentialMode = "password-only"
	CredentialUserKey      CredentialMode = "user-key"
	CredentialToken        CredentialMode = "token"
	CredentialNone         CredentialMode = "none"
)

// RoutingSupport describes whether a module honors ConnectionManager routing.
type RoutingSupport string

const (
	RoutingConnectionManager RoutingSupport = "connection-manager"
	RoutingSharedHTTPClient  RoutingSupport = "shared-http-client"
	RoutingDirectLibrary     RoutingSupport = "direct-library"
	RoutingPartial           RoutingSupport = "partial"
)

// ServiceStability mirrors the stable/beta labels used in docs.
type ServiceStability string

const (
	ServiceStable ServiceStability = "stable"
	ServiceBeta   ServiceStability = "beta"
)

// ParamDescriptor documents one accepted -m KEY:VALUE module parameter.
type ParamDescriptor struct {
	Name        string
	Values      []string
	Description string
	Required    bool
	Default     string
}

// ServiceDescriptor is the single metadata record for a brute service.
type ServiceDescriptor struct {
	Name           string
	DefaultPort    int
	Aliases        []string
	ScanAliases    []string
	Stability      ServiceStability
	CredentialMode CredentialMode
	Routing        RoutingSupport
	Params         []ParamDescriptor
	WordlistAlias  string
	RiskFlags      []string
}

// ServiceDescriptors returns BruteSpray's canonical service metadata.
func ServiceDescriptors() map[string]ServiceDescriptor {
	return map[string]ServiceDescriptor{
		"ssh":           descriptor("ssh", 22, ServiceStable, CredentialUserPassword, RoutingConnectionManager, sshParams(), ""),
		"ftp":           descriptor("ftp", 21, ServiceStable, CredentialUserPassword, RoutingConnectionManager, nil, ""),
		"ftps":          descriptor("ftps", 990, ServiceBeta, CredentialUserPassword, RoutingConnectionManager, nil, "ftp"),
		"telnet":        descriptor("telnet", 23, ServiceStable, CredentialUserPassword, RoutingConnectionManager, []ParamDescriptor{{Name: "success", Description: "Custom success string match"}}, ""),
		"smtp":          descriptor("smtp", 25, ServiceStable, CredentialUserPassword, RoutingConnectionManager, smtpParams(), ""),
		"smtp-vrfy":     descriptor("smtp-vrfy", 25, ServiceBeta, CredentialUserPassword, RoutingConnectionManager, nil, ""),
		"imap":          descriptor("imap", 143, ServiceStable, CredentialUserPassword, RoutingConnectionManager, []ParamDescriptor{{Name: "auth", Values: []string{"LOGIN", "PLAIN", "CRAM-MD5"}, Description: "IMAP authentication method"}}, ""),
		"pop3":          descriptor("pop3", 110, ServiceStable, CredentialUserPassword, RoutingConnectionManager, []ParamDescriptor{{Name: "auth", Values: []string{"USER", "PLAIN", "LOGIN", "APOP"}, Description: "POP3 authentication method"}}, "imap"),
		"mysql":         descriptor("mysql", 3306, ServiceStable, CredentialUserPassword, RoutingConnectionManager, []ParamDescriptor{{Name: "dbname", Description: "Target database"}}, ""),
		"postgres":      descriptor("postgres", 5432, ServiceStable, CredentialUserPassword, RoutingConnectionManager, []ParamDescriptor{{Name: "dbname", Default: "postgres", Description: "Target database"}}, ""),
		"mssql":         descriptor("mssql", 1433, ServiceStable, CredentialUserPassword, RoutingConnectionManager, []ParamDescriptor{{Name: "domain", Description: "Windows domain"}}, ""),
		"mongodb":       descriptor("mongodb", 27017, ServiceStable, CredentialUserPassword, RoutingConnectionManager, nil, ""),
		"redis":         descriptor("redis", 6379, ServiceStable, CredentialPasswordOnly, RoutingConnectionManager, []ParamDescriptor{{Name: "db", Default: "0", Description: "Redis database number"}}, ""),
		"couchdb":       descriptor("couchdb", 5984, ServiceStable, CredentialUserPassword, RoutingSharedHTTPClient, []ParamDescriptor{{Name: "tls", Values: []string{"true", "false"}, Description: "Use HTTPS"}}, ""),
		"elasticsearch": descriptor("elasticsearch", 9200, ServiceStable, CredentialUserPassword, RoutingSharedHTTPClient, []ParamDescriptor{{Name: "tls", Values: []string{"true", "false"}, Description: "Use HTTPS"}}, ""),
		"influxdb":      descriptor("influxdb", 8086, ServiceStable, CredentialToken, RoutingSharedHTTPClient, []ParamDescriptor{{Name: "mode", Values: []string{"v1", "v2"}, Default: "v2", Description: "InfluxDB auth mode"}}, ""),
		"neo4j":         descriptor("neo4j", 7687, ServiceBeta, CredentialUserPassword, RoutingDirectLibrary, nil, ""),
		"cassandra":     descriptor("cassandra", 9042, ServiceBeta, CredentialUserPassword, RoutingDirectLibrary, nil, ""),
		"vnc":           descriptor("vnc", 5900, ServiceStable, CredentialPasswordOnly, RoutingConnectionManager, nil, ""),
		"snmp":          descriptor("snmp", 161, ServiceStable, CredentialPasswordOnly, RoutingConnectionManager, snmpParams(), ""),
		"smbnt":         descriptor("smbnt", 445, ServiceStable, CredentialUserPassword, RoutingConnectionManager, []ParamDescriptor{{Name: "domain", Description: "SMB domain"}}, ""),
		"rdp":           descriptor("rdp", 3389, ServiceStable, CredentialUserPassword, RoutingConnectionManager, []ParamDescriptor{{Name: "domain", Description: "RDP domain"}}, ""),
		"http":          descriptor("http", 80, ServiceStable, CredentialUserPassword, RoutingSharedHTTPClient, httpParams(), ""),
		"https":         descriptor("https", 443, ServiceStable, CredentialUserPassword, RoutingSharedHTTPClient, httpParams(), "http"),
		"http-form":     descriptor("http-form", 80, ServiceBeta, CredentialUserPassword, RoutingSharedHTTPClient, httpFormParams(), "http"),
		"https-form":    descriptor("https-form", 443, ServiceBeta, CredentialUserPassword, RoutingSharedHTTPClient, httpFormParams(), "http"),
		"http-template": descriptor("http-template", 80, ServiceBeta, CredentialUserPassword, RoutingSharedHTTPClient, []ParamDescriptor{{Name: "template", Description: "Auth template YAML path"}, {Name: "template-inline", Description: "Inline auth template YAML"}}, "http"),
		"vmauthd":       descriptor("vmauthd", 902, ServiceStable, CredentialUserPassword, RoutingConnectionManager, nil, ""),
		"teamspeak":     descriptor("teamspeak", 10011, ServiceStable, CredentialUserPassword, RoutingConnectionManager, nil, ""),
		"asterisk":      descriptor("asterisk", 5038, ServiceBeta, CredentialUserPassword, RoutingConnectionManager, nil, ""),
		"nntp":          descriptor("nntp", 119, ServiceBeta, CredentialUserPassword, RoutingConnectionManager, nil, "smtp"),
		"oracle":        descriptor("oracle", 1521, ServiceBeta, CredentialUserPassword, RoutingConnectionManager, nil, ""),
		"xmpp":          descriptor("xmpp", 5222, ServiceBeta, CredentialUserPassword, RoutingConnectionManager, nil, ""),
		"ldap":          descriptor("ldap", 389, ServiceBeta, CredentialUserPassword, RoutingConnectionManager, nil, ""),
		"ldaps":         descriptor("ldaps", 636, ServiceBeta, CredentialUserPassword, RoutingConnectionManager, nil, "ldap"),
		"winrm":         descriptor("winrm", 5985, ServiceBeta, CredentialUserPassword, RoutingSharedHTTPClient, []ParamDescriptor{{Name: "domain", Description: "WinRM domain"}}, ""),
		"rexec":         descriptor("rexec", 512, ServiceBeta, CredentialUserPassword, RoutingConnectionManager, nil, ""),
		"rlogin":        descriptor("rlogin", 513, ServiceBeta, CredentialUserPassword, RoutingConnectionManager, nil, ""),
		"rsh":           descriptor("rsh", 514, ServiceBeta, CredentialUserPassword, RoutingConnectionManager, nil, ""),
		"wrapper":       descriptor("wrapper", 0, ServiceBeta, CredentialUserPassword, RoutingPartial, []ParamDescriptor{{Name: "cmd", Required: true, Description: "External command template"}}, ""),
		"socks5-auth":   descriptor("socks5-auth", 1080, ServiceBeta, CredentialUserPassword, RoutingConnectionManager, nil, ""),
		"svn":           descriptor("svn", 3690, ServiceBeta, CredentialUserPassword, RoutingSharedHTTPClient, []ParamDescriptor{{Name: "path", Description: "SVN repository path"}}, ""),
	}
}

func descriptor(name string, port int, stability ServiceStability, mode CredentialMode, routing RoutingSupport, params []ParamDescriptor, wordlistAlias string) ServiceDescriptor {
	return ServiceDescriptor{Name: name, DefaultPort: port, Stability: stability, CredentialMode: mode, Routing: routing, Params: params, WordlistAlias: wordlistAlias}
}

func sshParams() []ParamDescriptor {
	return []ParamDescriptor{
		{Name: "auth", Values: []string{"password", "keyboard-interactive"}, Description: "SSH auth method"},
		{Name: "key", Values: []string{"true", "path"}, Description: "Use SSH private-key authentication"},
	}
}

func smtpParams() []ParamDescriptor {
	return []ParamDescriptor{
		{Name: "auth", Values: []string{"PLAIN", "LOGIN", "NTLM"}, Description: "SMTP authentication method"},
		{Name: "ehlo", Description: "EHLO hostname"},
	}
}

func snmpParams() []ParamDescriptor {
	return []ParamDescriptor{
		{Name: "version", Values: []string{"2c", "3"}, Default: "2c", Description: "SNMP version"},
		{Name: "auth", Values: []string{"MD5", "SHA"}, Description: "SNMPv3 authentication protocol"},
		{Name: "priv", Values: []string{"NONE", "DES", "AES"}, Description: "SNMPv3 privacy protocol"},
		{Name: "privpass", Description: "SNMPv3 privacy passphrase"},
		{Name: "mode", Values: []string{"default", "extended", "full"}, Description: "SNMP community-string tier"},
	}
}

func httpParams() []ParamDescriptor {
	return []ParamDescriptor{
		{Name: "auth", Values: []string{"BASIC", "DIGEST", "NTLM", "AUTO"}, Description: "HTTP authentication method"},
		{Name: "dir", Default: "/", Description: "Target path"},
		{Name: "method", Description: "HTTP method"},
		{Name: "custom-header", Description: "Custom HTTP header"},
		{Name: "user-agent", Description: "Custom User-Agent"},
		{Name: "domain", Description: "NTLM domain"},
	}
}

func httpFormParams() []ParamDescriptor {
	return []ParamDescriptor{
		{Name: "url", Required: true, Description: "Login form path"},
		{Name: "body", Required: true, Description: "POST body with credential placeholders"},
		{Name: "fail", Description: "Failure string in response"},
		{Name: "success", Description: "Success string in response"},
		{Name: "method", Default: "POST", Description: "HTTP method"},
		{Name: "follow", Values: []string{"true", "false"}, Description: "Follow redirects"},
		{Name: "cookie", Description: "Custom cookie header"},
		{Name: "content-type", Default: "application/x-www-form-urlencoded", Description: "Content-Type header"},
		{Name: "csrf", Description: "CSRF hidden field name"},
		{Name: "form-url", Description: "URL to GET for CSRF token"},
	}
}

// DescriptorForService resolves scanner aliases before returning service metadata.
func DescriptorForService(service string) (ServiceDescriptor, bool) {
	canonical := MapService(service)
	descriptor, ok := ServiceDescriptors()[canonical]
	return descriptor, ok
}

// IsPasswordOnlyService reports whether a service ignores usernames.
func IsPasswordOnlyService(service string) bool {
	descriptor, ok := DescriptorForService(service)
	return ok && descriptor.CredentialMode == CredentialPasswordOnly
}
