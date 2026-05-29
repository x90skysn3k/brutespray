package brute

import (
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func TestBruteInfluxDBNoServer(t *testing.T) {
	cm, _ := modules.NewConnectionManager("", 1*time.Second, "")
	r := BruteInfluxDB("127.0.0.1", 1, "admin", "admin", 1*time.Second, cm, nil)
	if r.ConnectionSuccess {
		t.Fatalf("expected ConnectionSuccess=false against closed port, got %+v", r)
	}
}

func TestBruteInfluxDBRegistered(t *testing.T) {
	if !IsRegistered("influxdb") {
		t.Fatal("influxdb module not registered")
	}
}

func TestBruteInfluxDBV1Mode(t *testing.T) {
	cm, _ := modules.NewConnectionManager("", 1*time.Second, "")
	r := BruteInfluxDB("127.0.0.1", 1, "admin", "admin", 1*time.Second, cm, ModuleParams{"mode": "v1"})
	// Just confirm v1 path doesn't panic on closed-port path
	if r.ConnectionSuccess {
		t.Fatalf("v1 mode: expected ConnectionSuccess=false, got %+v", r)
	}
}
