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
// need to fill in the service. When several services share a default port
// (e.g. http/http-form on 80), the stable descriptor with the shortest
// canonical name wins so parsing stays deterministic.
func defaultServiceForPort(port int) string {
	descriptors := ServiceDescriptors()
	var matches []string
	for name, descriptor := range descriptors {
		if descriptor.DefaultPort == port {
			matches = append(matches, name)
		}
	}
	if len(matches) > 0 {
		sort.Strings(matches)
		for _, name := range matches {
			if descriptors[name].Stability == ServiceStable {
				return name
			}
		}
		return matches[0]
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
