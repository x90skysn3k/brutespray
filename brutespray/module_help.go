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
		descriptor, ok := modules.DescriptorForService(selection)
		if !ok || !brute.IsRegistered(descriptor.Name) {
			return "", fmt.Errorf("unknown service: %s", selection)
		}
		services = []string{descriptor.Name}
	}
	sort.Strings(services)

	var b strings.Builder
	for _, service := range services {
		descriptor, ok := modules.DescriptorForService(service)
		if !ok {
			return "", fmt.Errorf("missing descriptor for service: %s", service)
		}
		credentials := moduleHelpCredentialMode(descriptor.CredentialMode)
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

func moduleHelpCredentialMode(mode modules.CredentialMode) string {
	switch mode {
	case modules.CredentialUserPassword:
		return "user,password"
	case modules.CredentialPasswordOnly:
		return "password"
	case modules.CredentialUserKey:
		return "user,key"
	case modules.CredentialToken:
		return "token"
	case modules.CredentialNone:
		return "none"
	default:
		return string(mode)
	}
}

func moduleHelpParams(descriptor modules.ServiceDescriptor) []string {
	params := make([]string, 0, len(descriptor.Params))
	for _, param := range descriptor.Params {
		params = append(params, formatModuleHelpParam(param))
	}
	sort.Strings(params)
	return params
}

func formatModuleHelpParam(param modules.ParamDescriptor) string {
	parts := []string{param.Name}
	if len(param.Values) > 0 {
		parts = append(parts, "values="+strings.Join(param.Values, "|"))
	}
	if param.Required {
		parts = append(parts, "required")
	}
	if param.Default != "" {
		parts = append(parts, "default="+param.Default)
	}
	return strings.Join(parts, ":")
}
