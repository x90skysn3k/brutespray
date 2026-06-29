package brute

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

func init() {
	RegisterPreAuthProbe("redis", PreAuthProbe{Code: "redis-no-auth", Description: "Redis PING succeeds without authentication", Default: true, Run: probeRedisNoAuth})
	RegisterPreAuthProbe("elasticsearch", PreAuthProbe{Code: "elasticsearch-unauthenticated", Description: "Elasticsearch cluster health is readable without authentication", Default: true, Run: probeElasticsearchUnauthenticated})
	RegisterPreAuthProbe("couchdb", PreAuthProbe{Code: "couchdb-unauthenticated", Description: "CouchDB database list is readable without authentication", Default: true, Run: probeCouchDBUnauthenticated})
}

func probeRedisNoAuth(ctx context.Context, target PreAuthTarget) ([]Finding, error) {
	conn, err := preAuthDial(ctx, target, "tcp", target.Address())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(target.Timeout)
	if target.Timeout <= 0 {
		deadline = time.Now().Add(5 * time.Second)
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		return nil, err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(line, "+PONG") {
		return []Finding{{Severity: "HIGH", Code: "redis-no-auth", Message: "Redis accepted PING without authentication"}}, nil
	}
	return nil, nil
}

func probeElasticsearchUnauthenticated(ctx context.Context, target PreAuthTarget) ([]Finding, error) {
	return probeHTTPStatus(ctx, target, "/_cluster/health", "elasticsearch-unauthenticated", "Elasticsearch cluster health is readable without authentication")
}

func probeCouchDBUnauthenticated(ctx context.Context, target PreAuthTarget) ([]Finding, error) {
	return probeHTTPStatus(ctx, target, "/_all_dbs", "couchdb-unauthenticated", "CouchDB database list is readable without authentication")
}

func probeHTTPStatus(ctx context.Context, target PreAuthTarget, path, code, message string) ([]Finding, error) {
	client := http.DefaultClient
	if target.CM != nil && target.CM.SharedHTTPClient != nil {
		client = target.CM.SharedHTTPClient
	}
	scheme := "http"
	if strings.EqualFold(target.Params["tls"], "true") {
		scheme = "https"
	}
	url := scheme + "://" + target.Address() + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return []Finding{{Severity: "HIGH", Code: code, Message: message}}, nil
	}
	return nil, nil
}

func preAuthDial(ctx context.Context, target PreAuthTarget, network, address string) (net.Conn, error) {
	if target.CM != nil {
		return target.CM.Dial(network, address)
	}
	timeout := target.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", address, err)
	}
	return conn, nil
}
