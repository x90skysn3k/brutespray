package brute

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestRedisNoAuthProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("+PONG\r\n"))
	}()
	findings, err := runFirstProbe("redis", targetFromAddr("redis", ln.Addr().String()))
	if err != nil {
		t.Fatalf("run probe: %v", err)
	}
	if len(findings) != 1 || findings[0].Code != "redis-no-auth" {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestElasticsearchUnauthenticatedProbe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_cluster/health" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"status":"green"}`)
	}))
	defer server.Close()
	findings, err := runFirstProbe("elasticsearch", targetFromURL("elasticsearch", server.URL))
	if err != nil {
		t.Fatalf("run probe: %v", err)
	}
	if len(findings) != 1 || findings[0].Code != "elasticsearch-unauthenticated" {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestCouchDBUnauthenticatedProbe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_all_dbs" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `["_users"]`)
	}))
	defer server.Close()
	findings, err := runFirstProbe("couchdb", targetFromURL("couchdb", server.URL))
	if err != nil {
		t.Fatalf("run probe: %v", err)
	}
	if len(findings) != 1 || findings[0].Code != "couchdb-unauthenticated" {
		t.Fatalf("findings = %+v", findings)
	}
}

func runFirstProbe(service string, target PreAuthTarget) ([]Finding, error) {
	probes := PreAuthProbes(service)
	if len(probes) == 0 {
		return nil, fmt.Errorf("missing %s probe", service)
	}
	return probes[0].Run(context.Background(), target)
}

func targetFromURL(service, rawURL string) PreAuthTarget {
	serverURL := mustParseURL(rawURL)
	host, portString, _ := net.SplitHostPort(serverURL.Host)
	port := mustAtoi(portString)
	return PreAuthTarget{Service: service, Host: host, Port: port, Timeout: time.Second}
}

func targetFromAddr(service, addr string) PreAuthTarget {
	host, portString, _ := net.SplitHostPort(addr)
	port := mustAtoi(portString)
	return PreAuthTarget{Service: service, Host: host, Port: port, Timeout: time.Second}
}

func mustParseURL(rawURL string) *url.URL {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return parsed
}

func mustAtoi(value string) int {
	i, err := strconv.Atoi(value)
	if err != nil {
		panic(err)
	}
	return i
}
