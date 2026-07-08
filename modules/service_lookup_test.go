package modules

import "testing"

func TestSupportedServicePortsFromDescriptors(t *testing.T) {
	ports := SupportedServicePorts()

	tests := map[string]int{
		"ssh":           22,
		"couchdb":       5984,
		"elasticsearch": 9200,
		"influxdb":      8086,
		"neo4j":         7687,
		"cassandra":     9042,
		"socks5-auth":   1080,
		"http-form":     80,
		"https-form":    443,
		"svn":           3690,
		"asterisk":      5038,
	}

	for service, want := range tests {
		if got := ports[service]; got != want {
			t.Fatalf("%s port = %d, want %d", service, got, want)
		}
	}
}

func TestSupportedServiceNamesSorted(t *testing.T) {
	names := SupportedServiceNames()
	if len(names) == 0 {
		t.Fatal("expected service names")
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("service names not sorted at %d: %q > %q", i, names[i-1], names[i])
		}
	}
}

func TestServiceLookupDefaultServiceForPortCanonicalDuplicateDefaults(t *testing.T) {
	cases := map[int]string{
		25:  "smtp",
		80:  "http",
		443: "https",
	}

	for port, want := range cases {
		if got := defaultServiceForPort(port); got != want {
			t.Fatalf("port %d maps to %q, want %q", port, got, want)
		}
	}
}

func TestServiceLookupDefaultServiceForPortIgnoresNonPositiveDescriptorDefaults(t *testing.T) {
	if got := defaultServiceForPort(0); got != "" {
		t.Fatalf("port 0 maps to %q, want no default service", got)
	}
}

func TestServiceLookupDuplicateDefaultPortsHaveExplicitCanonicalDefaults(t *testing.T) {
	duplicates := make(map[int][]string)
	for name, descriptor := range ServiceDescriptors() {
		duplicates[descriptor.DefaultPort] = append(duplicates[descriptor.DefaultPort], name)
	}

	wantCanonical := map[int]string{
		25:  "smtp",
		80:  "http",
		443: "https",
	}
	if len(canonicalDefaultServicesByPort) != len(wantCanonical) {
		t.Fatalf("canonical duplicate defaults = %v, want exactly %v", canonicalDefaultServicesByPort, wantCanonical)
	}

	for port, services := range duplicates {
		if len(services) < 2 {
			continue
		}

		want, ok := wantCanonical[port]
		if !ok {
			t.Fatalf("duplicate default port %d has no expected canonical default (services: %v)", port, services)
		}
		got, ok := canonicalDefaultServicesByPort[port]
		if !ok {
			t.Fatalf("duplicate default port %d has no explicit canonical default (services: %v)", port, services)
		}
		if got != want {
			t.Fatalf("duplicate default port %d canonical default = %q, want %q (services: %v)", port, got, want, services)
		}
	}
}

func TestDefaultServiceForPortUsesSupportedScanServicesOnly(t *testing.T) {
	cases := map[int]string{
		3690: "svn",
		5038: "asterisk",
	}
	for port, want := range cases {
		if got := defaultServiceForPort(port); got != want {
			t.Fatalf("%d maps to %q, want %q", port, got, want)
		}
	}

	descriptorOnlyPorts := []int{1080, 5984, 7687, 8086, 9042, 9200}
	for _, port := range descriptorOnlyPorts {
		if got := defaultServiceForPort(port); got != "" {
			t.Fatalf("descriptor-only port %d maps to %q, want no default service", port, got)
		}
	}
}
