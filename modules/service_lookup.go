package modules

import "sort"

// SupportedServicePorts returns BruteSpray's default service-to-port mapping.
func SupportedServicePorts() map[string]int {
	ports := make(map[string]int, len(ServiceDescriptors()))
	for name, descriptor := range ServiceDescriptors() {
		ports[name] = descriptor.DefaultPort
	}
	return ports
}

// SupportedServiceNames returns canonical service names in stable order.
func SupportedServiceNames() []string {
	names := make([]string, 0, len(ServiceDescriptors()))
	for name := range ServiceDescriptors() {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// defaultServiceForPort returns brutespray's canonical service name for a
// well-known port, or "" when the port has no default mapping. Used by
// stream parsers (masscan JSON, naabu line) that supply only host:port and
// need to fill in the service.
func defaultServiceForPort(port int) string {
	for name, descriptor := range ServiceDescriptors() {
		if descriptor.DefaultPort == port {
			return name
		}
	}

	// Alternate common ports that intentionally do not replace descriptor
	// defaults. Keep this list small and only for documented protocol variants.
	switch port {
	case 587:
		return "smtp"
	case 5901, 5902:
		return "vnc"
	case 5986:
		return "winrm"
	}
	return ""
}
