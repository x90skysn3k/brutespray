package brute

import (
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func TestBruteElasticsearchNoServer(t *testing.T) {
	cm, _ := modules.NewConnectionManager("", 1*time.Second, "")
	r := BruteElasticsearch("127.0.0.1", 1, "elastic", "elastic", 1*time.Second, cm, nil)
	if r.ConnectionSuccess {
		t.Fatalf("expected ConnectionSuccess=false against closed port, got %+v", r)
	}
}

func TestBruteElasticsearchRegistered(t *testing.T) {
	if !IsRegistered("elasticsearch") {
		t.Fatal("elasticsearch module not registered")
	}
}
