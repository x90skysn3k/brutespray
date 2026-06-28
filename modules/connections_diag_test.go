package modules

import (
	"strings"
	"testing"
	"time"
)

func TestDiagnoseRouteReportsSelectedLocalAddress(t *testing.T) {
	cm, err := NewConnectionManager("", time.Second)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}
	diag := cm.DiagnoseRoute("tcp", "127.0.0.1:1")
	if diag.Target != "127.0.0.1:1" {
		t.Fatalf("Target = %q, want 127.0.0.1:1", diag.Target)
	}
	if diag.SelectedLocalAddr == "" {
		t.Fatalf("SelectedLocalAddr is empty: %#v", diag)
	}
	if !strings.HasPrefix(diag.SelectedLocalAddr, "127.") {
		t.Fatalf("SelectedLocalAddr = %q, want loopback", diag.SelectedLocalAddr)
	}
}
