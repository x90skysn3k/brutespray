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
		descriptor, ok := modules.DescriptorForService(service)
		if !ok {
			return "", fmt.Errorf("missing descriptor for service: %s", service)
		}
		credentials := "user,password"
		if descriptor.CredentialMode == modules.CredentialPasswordOnly {
			credentials = "password"
		}
		fmt.Fprintf(&b, "service=%s default_port=%d credentials=%s routing=%s stability=%s",
			descriptor.Name, descriptor.DefaultPort, credentials, descriptor.Routing, descriptor.Stability)
		params := moduleHelpParams(descriptor)
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

func moduleHelpParams(descriptor modules.ServiceDescriptor) []string {
	params := make([]string, 0, len(descriptor.Params))
	for _, param := range descriptor.Params {
		params = append(params, param.Name)
	}
	sort.Strings(params)
	return params
}
