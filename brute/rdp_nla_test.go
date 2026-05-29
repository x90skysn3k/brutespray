package brute

import "testing"

func TestNLAFindingFromStatus(t *testing.T) {
	cases := []struct {
		status   string
		wantSev  string
		wantCode string
	}{
		{"required", "INFO", "rdp-nla-required"},
		{"not-enforced", "WARN", "rdp-nla-missing"},
		{"hybrid-ex", "INFO", "rdp-nla-hybridex"},
		{"unknown", "", ""},
	}
	for _, c := range cases {
		f := nlaFinding(c.status)
		if c.wantCode == "" {
			if f != nil {
				t.Fatalf("status %q: expected nil finding, got %+v", c.status, f)
			}
			continue
		}
		if f == nil || f.Severity != c.wantSev || f.Code != c.wantCode {
			t.Fatalf("status %q: got %+v want sev=%s code=%s", c.status, f, c.wantSev, c.wantCode)
		}
	}
}
