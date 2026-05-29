package brute

import (
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func TestBruteNeo4jNoServer(t *testing.T) {
	cm, _ := modules.NewConnectionManager("", 1*time.Second, "")
	r := BruteNeo4j("127.0.0.1", 1, "neo4j", "neo4j", 1*time.Second, cm, nil)
	if r.ConnectionSuccess {
		t.Fatalf("expected ConnectionSuccess=false against closed port, got %+v", r)
	}
}

func TestBruteNeo4jRegistered(t *testing.T) {
	if !IsRegistered("neo4j") {
		t.Fatal("neo4j module not registered")
	}
}
