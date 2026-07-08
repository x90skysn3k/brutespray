package modules

import "sort"

var canonicalDefaultServicesByPort = map[int]string{
	25:  "smtp",
	80:  "http",
	443: "https",
}

var defaultServicesByPort = buildDefaultServicesByPort()

func buildDefaultServicesByPort() map[int]string {
	services := make(map[int]string, len(supportedScanServices)+len(canonicalDefaultServicesByPort)+4)
	for port, service := range canonicalDefaultServicesByPort {
		services[port] = service
	}
	for _, scannerService := range supportedScanServices {
		descriptor, ok := DescriptorForService(scannerService)
		if !ok {
			continue
		}
		if descriptor.DefaultPort <= 0 {
			continue
		}
		if _, ok := services[descriptor.DefaultPort]; ok {
			continue
		}
		services[descriptor.DefaultPort] = MapService(scannerService)
	}

	// Alternate common ports that intentionally do not replace descriptor
	// defaults. Keep this list small and only for documented protocol variants.
	services[587] = "smtp"
	services[5901] = "vnc"
	services[5902] = "vnc"
	services[5986] = "winrm"

	return services
}

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
	if service, ok := defaultServicesByPort[port]; ok {
		return service
	}
	return ""
}
