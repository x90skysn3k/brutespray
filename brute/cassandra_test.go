package brute

import (
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func TestBruteCassandraNoServer(t *testing.T) {
	cm, _ := modules.NewConnectionManager("", 1*time.Second, "")
	r := BruteCassandra("127.0.0.1", 1, "cassandra", "cassandra", 1*time.Second, cm, nil)
	if r.ConnectionSuccess {
		t.Fatalf("expected ConnectionSuccess=false against closed port, got %+v", r)
	}
}

func TestBruteCassandraRegistered(t *testing.T) {
	if !IsRegistered("cassandra") {
		t.Fatal("cassandra module not registered")
	}
}
