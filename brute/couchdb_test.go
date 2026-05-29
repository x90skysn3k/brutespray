package brute

import (
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func TestBruteCouchDBNoServer(t *testing.T) {
	cm, _ := modules.NewConnectionManager("", 1*time.Second, "")
	r := BruteCouchDB("127.0.0.1", 1, "admin", "admin", 1*time.Second, cm, nil)
	if r.ConnectionSuccess {
		t.Fatalf("expected ConnectionSuccess=false against closed port, got %+v", r)
	}
}

func TestBruteCouchDBRegistered(t *testing.T) {
	if !IsRegistered("couchdb") {
		t.Fatal("couchdb module not registered")
	}
}
