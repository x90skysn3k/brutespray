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
}

func MapService(service string) string {
	if mappedService, ok := NAME_MAP[service]; ok {
		return mappedService
	}
	return service
}

func ParseGNMAP(filename string) (map[Host]int, error) {
	supported := []string{"ssh", "ftp", "postgres", "telnet", "mysql", "ms-sql-s", "shell",
		"vnc", "imap", "imaps", "nntp", "pcanywheredata", "pop3", "pop3s",
		"exec", "login", "microsoft-ds", "smtp", "smtps", "submission",
		"svn", "iss-realsecure", "snmptrap", "snmp", "ms-wbt-server", "mongod", "nntp", "oracle", "textui", "xmpp-client"}

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
			port, _ := strconv.Atoi(portMatches[1])
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
	supported := []string{"ssh", "ftp", "postgres", "telnet", "mysql", "ms-sql-s", "shell",
		"vnc", "imap", "imaps", "nntp", "pcanywheredata", "pop3", "pop3s",
		"exec", "login", "microsoft-ds", "smtp", "smtps", "submission",
		"svn", "iss-realsecure", "snmptrap", "snmp", "mongodb", "nntp", "oracle", "textui", "xmpp-client", "ms-wbt-server"}

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
			p, _ := strconv.Atoi(port)
			mappedService := MapService(name)
			h := Host{Service: mappedService, Host: host, Port: p}
			hosts[h] = 1
		}
	}

	return hosts, nil
}
func ParseXML(filename string) (map[Host]int, error) {
	supported := []string{"ssh", "ftp", "postgresql", "telnet", "mysql", "ms-sql-s", "rsh",
		"vnc", "imap", "imaps", "nntp", "pcanywheredata", "pop3", "pop3s",
		"exec", "login", "microsoft-ds", "smtp", "smtps", "submission",
		"svn", "iss-realsecure", "snmptrap", "snmp", "mongod", "nntp", "oracle", "textui", "xmpp-client", "ms-wbt-server"}

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
		ip := host.Addresses[0].Addr
		for _, port := range host.Ports {
			if port.PortState.State == "open" {
				name := port.Service.Name
				if contains(supported, name) {
					p, _ := strconv.Atoi(port.PortId)
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
	supported := []string{"ssh", "ftp", "postgresql", "telnet", "mysql", "ms-sql-s", "rsh",
		"vnc", "imap", "imaps", "nntp", "pcanywheredata", "pop3", "pop3s",
		"exec", "login", "microsoft-ds", "smtp", "smtps", "submission",
		"svn", "iss-realsecure", "snmptrap", "snmp", "cifs", "mongod", "nntp", "oracle", "textui", "xmpp-client", "ms-wbt-server"}

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
					p, _ := strconv.Atoi(port.Port)
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
	supported := []string{"ssh", "ftp", "postgresql", "telnet", "mysql", "ms-sql-s", "rsh",
		"vnc", "imap", "imaps", "nntp", "pcanywheredata", "pop3", "pop3s",
		"exec", "login", "microsoft-ds", "smtp", "smtps", "submission",
		"svn", "iss-realsecure", "snmptrap", "snmp", "cifs", "mongod", "nntp", "oracle", "textui", "xmpp-client", "ms-wbt-server"}

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
					p, _ := strconv.Atoi(port.Port)
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
	supportedServices := []string{"ssh", "ftp", "smtp", "mssql", "telnet", "smbnt", "postgres", "imap", "pop3", "snmp", "mysql", "vmauthd", "asterisk", "vnc", "mongod", "nntp", "oracle", "teamspeak", "xmpp", "rdp"}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	hosts := make(map[Host]int)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		service := MapService(parts[0])
		ip := parts[1]
		port, _ := strconv.Atoi(parts[2])
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

func (h *Host) Parse(host string) ([]Host, error) {
	supportedServices := map[string]int{
		"ssh":       22,
		"ftp":       21,
		"smtp":      25,
		"mssql":     1433,
		"telnet":    23,
		"smbnt":     139,
		"postgres":  5432,
		"imap":      143,
		"pop3":      110,
		"snmp":      161,
		"mysql":     3306,
		"vmauthd":   902,
		"asterisk":  10000,
		"vnc":       5900,
		"mongodb":   27017,
		"nntp":      119,
		"oracle":    1521,
		"teamspeak": 10011,
		"xmpp":      5222,
		"rdp":       3389,
	}

	parts := strings.Split(host, "://")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid host format: %s", host)
	}

	service := MapService(parts[0])
	remaining := parts[1]

	portIndex := strings.LastIndex(remaining, ":")

	var portStr string
	if portIndex == -1 {
		portStr = ""
	} else {
		portStr = remaining[portIndex+1:]
		remaining = remaining[:portIndex]
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

func generateHostList(ipnet *net.IPNet) []net.IP {
	var ips []net.IP
	startIP := ipnet.IP.Mask(ipnet.Mask)
	startIP[len(startIP)-1]++
	for ip := startIP; ipnet.Contains(ip); inc(ip) {
		if !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !isBroadcast(ip, ipnet.Mask) {
			ips = append(ips, append([]byte(nil), ip...))
		}
	}
	return ips
}

func isBroadcast(ip net.IP, mask net.IPMask) bool {
	for i := 0; i < len(ip); i++ {
		if ip[i] != mask[i]|^ip[i] {
			return false
		}
	}
	return true
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
