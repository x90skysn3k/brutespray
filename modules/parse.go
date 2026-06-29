package modules

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type Host struct {
	Service string
	Host    string
	Port    int
}

type NexposeNode struct {
	Address   string            `xml:"address,attr"`
	Endpoints []NexposeEndpoint `xml:"endpoints>endpoint"`
}

type NexposeEndpoint struct {
	Port     string         `xml:"port,attr"`
	Status   string         `xml:"status,attr"`
	Protocol string         `xml:"protocol,attr"`
	Service  NexposeService `xml:"services>service"`
}

type NexposeService struct {
	Name string `xml:"name,attr"`
}

type NessusReport struct {
	Hosts []NessusHost `xml:"Report>ReportHost"`
}

type NessusHost struct {
	Name  string       `xml:"name,attr"`
	Items []NessusItem `xml:"ReportItem"`
}

type NessusItem struct {
	Port    string `xml:"port,attr"`
	SvcName string `xml:"svc_name,attr"`
}

type NmapRun struct {
	Hosts []NmapHost `xml:"host"`
}

type NmapHost struct {
	Addresses []NmapAddress `xml:"address"`
	Ports     []NmapPort    `xml:"ports>port"`
}

type NmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type NmapPort struct {
	PortId    string      `xml:"portid,attr"`
	Protocol  string      `xml:"protocol,attr"`
	PortState NmapState   `xml:"state"`
	Service   NmapService `xml:"service"`
}

type NmapState struct {
	State string `xml:"state,attr"`
}

type NmapService struct {
	Name string `xml:"name,attr"`
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

var NAME_MAP = map[string]string{
	"ms-sql-s":       "mssql",
	"microsoft-ds":   "smbnt",
	"cifs":           "smbnt",
	"postgresql":     "postgres",
	"smtps":          "smtp",
	"submission":     "smtp",
	"imaps":          "imap",
	"pop3s":          "pop3",
	"iss-realsecure": "vmauthd",
	"snmptrap":       "snmp",
	"mysql":          "mysql",
	"vnc":            "vnc",
	"mongod":         "mongodb",
	"textui":         "teamspeak",
	"xmpp-client":    "xmpp",
	"ms-wbt-server":  "rdp",
	"ldaps":          "ldaps",
	"wsman":          "winrm",
	"wsmans":         "winrm",
	"exec":           "rexec",
	"login":          "rlogin",
	"shell":          "rsh",
	"ftp-ssl":        "ftps",
	"ftps":           "ftps",
	"ftps-data":      "ftps",
}

func MapService(service string) string {
	if mappedService, ok := NAME_MAP[service]; ok {
		return mappedService
	}
	return service
}

// supportedScanServices is the canonical list of nmap/scanner service names
// that brutespray recognises from scan input files. Names are pre-mapping
// (i.e. the raw names scanners emit); MapService() converts them to
// brutespray module names at parse time.
var supportedScanServices = []string{
	"ssh", "ftp", "ftp-ssl", "ftps", "postgres", "postgresql", "telnet",
	"mysql", "ms-sql-s", "vnc", "imap", "imaps", "nntp",
	"pcanywheredata", "pop3", "pop3s",
	"exec", "login", "shell",
	"microsoft-ds", "cifs",
	"smtp", "smtps", "submission",
	"svn", "iss-realsecure", "snmptrap", "snmp",
	"ms-wbt-server", "mongod", "mongodb",
	"oracle", "textui", "xmpp-client",
	"redis", "ldap", "ldaps",
	"wsman", "wsmans",
	"http", "https",
	"asterisk", "vmauthd", "teamspeak",
	"rsh", "rexec", "rlogin",
}

func ParseGNMAP(filename string) (map[Host]int, error) {
	supported := supportedScanServices

	hosts := make(map[Host]int)

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		for _, name := range supported {
			matches := regexp.MustCompile(fmt.Sprintf(`([0-9][0-9]*)/open/[a-z][a-z]*//%s`, name))
			portMatches := matches.FindStringSubmatch(line)
			if len(portMatches) == 0 {
				continue
			}
			port, err := strconv.Atoi(portMatches[1])
			if err != nil || port <= 0 {
				continue
			}
			ipMatches := regexp.MustCompile(`[0-9]+(?:\.[0-9]+){3}`).FindAllString(line, -1)

			for _, ip := range ipMatches {
				mappedService := MapService(name)
				h := Host{Service: mappedService, Host: ip, Port: port}
				hosts[h] = 1
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return hosts, nil
}
func ParseJSON(filename string) (map[Host]int, error) {
	supported := supportedScanServices

	hosts := make(map[Host]int)

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	for {
		var data map[string]interface{}
		err := decoder.Decode(&data)
		if err != nil {
			break
		}
		host, _ := data["host"].(string)
		port, _ := data["port"].(string)
		name, _ := data["service"].(string)
		if contains(supported, name) {
			p, err := strconv.Atoi(port)
			if err != nil || p <= 0 {
				continue
			}
			mappedService := MapService(name)
			h := Host{Service: mappedService, Host: host, Port: p}
			hosts[h] = 1
		}
	}

	return hosts, nil
}
func ParseXML(filename string) (map[Host]int, error) {
	supported := supportedScanServices

	hosts := make(map[Host]int)

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := xml.NewDecoder(file)
	var report NmapRun
	err = decoder.Decode(&report)
	if err != nil {
		return nil, err
	}

	for _, host := range report.Hosts {
		// Pick IPv4 address if available, else first address
		var ip string
		if len(host.Addresses) > 0 {
			for _, a := range host.Addresses {
				if strings.EqualFold(a.AddrType, "ipv4") {
					ip = a.Addr
					break
				}
			}
			if ip == "" {
				ip = host.Addresses[0].Addr
			}
		}
		if ip == "" {
			continue
		}
		for _, port := range host.Ports {
			if port.PortState.State == "open" {
				name := port.Service.Name
				if contains(supported, name) {
					p, err := strconv.Atoi(port.PortId)
					if err != nil || p <= 0 {
						continue
					}
					mappedService := MapService(name)
					h := Host{Service: mappedService, Host: ip, Port: p}
					hosts[h] = 1
				}
			}
		}
	}

	return hosts, nil
}
func ParseNexpose(filename string) (map[Host]int, error) {
	supported := supportedScanServices

	hosts := make(map[Host]int)
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := xml.NewDecoder(file)
	var nodes []NexposeNode
	for {
		token, _ := decoder.Token()
		if token == nil {
			break
		}
		switch se := token.(type) {
		case xml.StartElement:
			if se.Name.Local == "node" {
				var node NexposeNode
				err = decoder.DecodeElement(&node, &se)
				nodes = append(nodes, node)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	for _, node := range nodes {
		ip := node.Address
		for _, port := range node.Endpoints {
			if port.Status == "open" {
				name := port.Service.Name
				name = strings.ToLower(name)
				if contains(supported, name) {
					p, err := strconv.Atoi(port.Port)
					if err != nil || p <= 0 {
						continue
					}
					mappedService := MapService(name)
					h := Host{Service: mappedService, Host: ip, Port: p}
					hosts[h] = 1
				}
			}
		}
	}
	return hosts, nil
}
func ParseNessus(filename string) (map[Host]int, error) {
	supported := supportedScanServices

	hosts := make(map[Host]int)
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := xml.NewDecoder(file)
	var report NessusReport
	err = decoder.Decode(&report)
	if err != nil {
		return nil, err
	}
	for _, host := range report.Hosts {
		ip := host.Name
		for _, port := range host.Items {
			if port.Port != "0" {
				name := port.SvcName
				if contains(supported, name) {
					p, err := strconv.Atoi(port.Port)
					if err != nil || p <= 0 {
						continue
					}
					mappedService := MapService(name)
					h := Host{Service: mappedService, Host: ip, Port: p}
					hosts[h] = 1
				}
			}
		}
	}

	return hosts, nil
}
func ParseList(filename string) (map[Host]int, error) {
	supportedServices := supportedScanServices
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	hosts := make(map[Host]int)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			return nil, fmt.Errorf("invalid list line: %q (expected service:ip:port)", line)
		}
		service := MapService(parts[0])
		ip := parts[1]
		port, err := strconv.Atoi(parts[2])
		if err != nil {
			return nil, fmt.Errorf("invalid port in line %q: %v", line, err)
		}
		h := Host{Service: service, Host: ip, Port: port}
		hosts[h] = 1

		var found bool
		for _, services := range supportedServices {
			if service == services {
				found = true
				break
			}
		}

		if !found {
			return nil, fmt.Errorf("unsupported service: %s", h.Service)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return hosts, nil
}

// ParseDirectTarget parses a single service://host target and rejects CIDR expansion.
func ParseDirectTarget(target string) (Host, error) {
	hosts, err := (&Host{}).Parse(target)
	if err != nil {
		return Host{}, err
	}
	if len(hosts) != 1 {
		return Host{}, fmt.Errorf("target expands to %d hosts", len(hosts))
	}
	return hosts[0], nil
}

func splitHostPortDefault(target string) (host string, port string, err error) {
	if strings.HasPrefix(target, "[") {
		end := strings.LastIndex(target, "]")
		if end < 0 {
			return "", "", fmt.Errorf("invalid bracketed IPv6 target: %s", target)
		}
		host = target[1:end]
		rest := target[end+1:]
		if rest == "" {
			return host, "", nil
		}
		if !strings.HasPrefix(rest, ":") {
			return "", "", fmt.Errorf("invalid bracketed IPv6 target: %s", target)
		}
		return host, rest[1:], nil
	}
	if strings.Contains(target, "/") {
		return target, "", nil
	}
	if strings.Count(target, ":") > 1 {
		return "", "", fmt.Errorf("IPv6 targets with ports must use brackets: %s", target)
	}
	portIndex := strings.LastIndex(target, ":")
	if portIndex == -1 {
		return target, "", nil
	}
	return target[:portIndex], target[portIndex+1:], nil
}

func (h *Host) Parse(host string) ([]Host, error) {
	supportedServices := SupportedServicePorts()

	parts := strings.Split(host, "://")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid host format: %s", host)
	}

	service := MapService(parts[0])
	remaining := parts[1]

	remaining, portStr, err := splitHostPortDefault(remaining)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		if portStr == "" {
			port = supportedServices[service]
		} else {
			return nil, fmt.Errorf("invalid port in host: %s", host)
		}
	}

	if _, ok := supportedServices[service]; !ok {
		return nil, fmt.Errorf("unsupported service: %s", service)
	}

	var hosts []Host
	if strings.Contains(remaining, "/") {
		_, ipnet, err := net.ParseCIDR(remaining)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR in host: %s", host)
		}

		for _, host := range generateHostList(ipnet) {
			hosts = append(hosts, Host{Service: service, Host: host.String(), Port: port})
		}
	} else {
		hosts = append(hosts, Host{Service: service, Host: remaining, Port: port})
	}

	return hosts, nil
}

// maxCIDRHosts is the maximum number of hosts generated from a CIDR range.
// A /16 generates ~65534 hosts; anything larger is likely a mistake.
const maxCIDRHosts = 65536

func generateHostList(ipnet *net.IPNet) []net.IP {
	var ips []net.IP
	startIP := ipnet.IP.Mask(ipnet.Mask)
	startIP[len(startIP)-1]++
	for ip := startIP; ipnet.Contains(ip); inc(ip) {
		if !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !isBroadcast(ip, ipnet) {
			ips = append(ips, append([]byte(nil), ip...))
			if len(ips) >= maxCIDRHosts {
				fmt.Fprintf(os.Stderr, "[!] CIDR range too large, capped at %d hosts\n", maxCIDRHosts)
				break
			}
		}
	}
	return ips
}

func isBroadcast(ip net.IP, ipnet *net.IPNet) bool {
	if ip == nil || ipnet == nil || ip.To4() == nil {
		return false
	}
	network := ipnet.IP.Mask(ipnet.Mask)
	// Compute broadcast: network OR NOT(mask)
	broadcast := make(net.IP, len(network))
	copy(broadcast, network)
	for i := 0; i < len(ipnet.Mask) && i < len(broadcast); i++ {
		broadcast[i] |= ^ipnet.Mask[i]
	}
	return ip.Equal(broadcast)
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
