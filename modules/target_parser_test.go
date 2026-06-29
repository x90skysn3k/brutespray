package modules

import "testing"

func TestParseTargetIPv6WithPort(t *testing.T) {
	target, err := ParseDirectTarget("ssh://[2001:db8::1]:2222")
	if err != nil {
		t.Fatalf("ParseDirectTarget: %v", err)
	}
	if target.Host != "2001:db8::1" || target.Port != 2222 || target.Service != "ssh" {
		t.Fatalf("target = %+v", target)
	}
}

func TestParseTargetIPv6DefaultPort(t *testing.T) {
	target, err := ParseDirectTarget("ssh://[2001:db8::1]")
	if err != nil {
		t.Fatalf("ParseDirectTarget: %v", err)
	}
	if target.Port != 22 || target.Host != "2001:db8::1" {
		t.Fatalf("target = %+v", target)
	}
}

func TestParseTargetIPv6CIDR(t *testing.T) {
	targets, err := (&Host{}).Parse("ssh://2001:db8::/126")
	if err != nil {
		t.Fatalf("Parse IPv6 CIDR: %v", err)
	}
	if len(targets) == 0 {
		t.Fatal("expected IPv6 CIDR targets")
	}
	if targets[0].Host != "2001:db8::1" {
		t.Fatalf("first target = %+v", targets[0])
	}
	if len(targets) != 3 || targets[len(targets)-1].Host != "2001:db8::3" {
		t.Fatalf("IPv6 CIDR targets = %+v", targets)
	}
}

func TestParseTargetRejectsUnbracketedIPv6WithPort(t *testing.T) {
	if _, err := ParseDirectTarget("ssh://2001:db8::1:22"); err == nil {
		t.Fatal("expected unbracketed IPv6 with port to fail")
	}
}
