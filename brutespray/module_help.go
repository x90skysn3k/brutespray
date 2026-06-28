package brutespray

import (
	"fmt"
	"sort"
	"strings"

	"github.com/x90skysn3k/brutespray/v2/brute"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

func formatModuleHelp(selection string) (string, error) {
	selection = strings.TrimSpace(selection)
	if selection == "" {
		selection = "all"
	}
	ports := modules.SupportedServicePorts()
	services := brute.Services()
	if selection != "all" {
		if !brute.IsRegistered(selection) {
			return "", fmt.Errorf("unknown service: %s", selection)
		}
		services = []string{selection}
	}
	sort.Strings(services)

	var b strings.Builder
	for _, service := range services {
		port, ok := ports[service]
		if !ok {
			port = 0
		}
		credentials := "user,password"
		if service == "vnc" || service == "snmp" {
			credentials = "password"
		}
		params := moduleHelpParams(service)
		fmt.Fprintf(&b, "service=%s default_port=%d credentials=%s", service, port, credentials)
		if len(params) > 0 {
			fmt.Fprintf(&b, " params=%s", strings.Join(params, ","))
		}
		if service == "wrapper" {
			b.WriteString(" requires=--allow-wrapper")
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func moduleHelpParams(service string) []string {
	switch service {
	case "http", "https", "http-form", "https-form":
		return []string{"path", "method", "success", "failure", "auth"}
	case "imap":
		return []string{"auth"}
	case "smbnt", "rdp", "mssql", "winrm":
		return []string{"domain"}
	case "wrapper":
		return []string{"cmd"}
	default:
		return nil
	}
}
