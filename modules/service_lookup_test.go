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

func TestDefaultServiceForPortUsesDescriptors(t *testing.T) {
	if got := defaultServiceForPort(5984); got != "couchdb" {
		t.Fatalf("5984 maps to %q, want couchdb", got)
	}
	if got := defaultServiceForPort(9200); got != "elasticsearch" {
		t.Fatalf("9200 maps to %q, want elasticsearch", got)
	}
	if got := defaultServiceForPort(5038); got != "asterisk" {
		t.Fatalf("5038 maps to %q, want asterisk", got)
	}
}
