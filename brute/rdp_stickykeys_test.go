package brute

import "testing"

func TestStickyKeysVerdictFromFlags(t *testing.T) {
	cases := []struct {
		name            string
		beforeIsCmdLike bool
		afterIsCmdLike  bool
		differ          bool
		wantSev         string
		wantCode        string
	}{
		{"identical-no-change", false, false, false, "", ""},
		{"change-but-not-cmd", false, false, true, "INFO", "rdp-stickykeys-inconclusive"},
		{"change-to-cmd", false, true, true, "CRITICAL", "rdp-stickykeys"},
	}
	for _, c := range cases {
		got := stickyKeysVerdict(c.beforeIsCmdLike, c.afterIsCmdLike, c.differ)
		if c.wantCode == "" {
			if got != nil {
				t.Fatalf("%s: want nil, got %+v", c.name, got)
			}
			continue
		}
		if got == nil || got.Severity != c.wantSev || got.Code != c.wantCode {
			t.Fatalf("%s: got %+v want sev=%s code=%s", c.name, got, c.wantSev, c.wantCode)
		}
	}
}

func TestFramebuffersDiffer(t *testing.T) {
	if framebuffersDiffer(nil, nil) {
		t.Fatal("nil != nil")
	}
	if !framebuffersDiffer([]byte{1, 2, 3}, []byte{1, 2, 4}) {
		t.Fatal("differ failed")
	}
	if framebuffersDiffer([]byte{1, 2, 3}, []byte{1, 2, 3}) {
		t.Fatal("same flagged differ")
	}
	if !framebuffersDiffer([]byte{1, 2, 3}, []byte{1, 2, 3, 4}) {
		t.Fatal("length diff missed")
	}
}

func TestLooksLikeCmdConsoleOnGarbage(t *testing.T) {
	if looksLikeCmdConsole(nil) {
		t.Fatal("nil should be false")
	}
	if looksLikeCmdConsole([]byte("not a png")) {
		t.Fatal("garbage should be false")
	}
}
