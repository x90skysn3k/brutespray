package brute

import (
	"testing"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func TestRegisteredServicesHaveDescriptors(t *testing.T) {
	descriptors := modules.ServiceDescriptors()
	for _, service := range Services() {
		if _, ok := descriptors[service]; !ok {
			t.Fatalf("registered service %s lacks descriptor", service)
		}
	}
}

func TestDescriptorsHaveRegisteredModules(t *testing.T) {
	for service := range modules.ServiceDescriptors() {
		if !IsRegistered(service) {
			t.Fatalf("descriptor service %s is not registered", service)
		}
	}
}
