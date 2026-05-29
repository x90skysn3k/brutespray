package modules

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

var (
	nervaURIRE = regexp.MustCompile(`^[a-z][a-z0-9+-]*://[^:/]+:\d+`)
	hostPortRE = regexp.MustCompile(`^[^\s:]+:\d+$`)
)

// DetectStreamFormat peeks at the first non-blank line of a stream and
// returns one of: "naabu", "nerva-uri", "nerva-json", "masscan-json",
// "fingerprintx-json". The caller must pass a reader that has not yet
// been consumed (this function does NOT rewind).
func DetectStreamFormat(r io.Reader) (string, error) {
	br := bufio.NewReader(r)
	peek, _ := br.Peek(4096)
	var line []byte
	for _, raw := range bytes.Split(peek, []byte("\n")) {
		t := bytes.TrimSpace(raw)
		if len(t) > 0 {
			line = t
			break
		}
	}
	if len(line) == 0 {
		return "", fmt.Errorf("empty stream")
	}
	s := string(line)
	switch {
	case s[0] == '[':
		return "masscan-json", nil
	case s[0] == '{':
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(line, &probe); err != nil {
			return "", fmt.Errorf("invalid JSON: %w", err)
		}
		_, hasService := probe["service"]
		_, hasProtocol := probe["protocol"]
		_, hasPort := probe["port"]
		switch {
		case hasService && hasPort:
			return "fingerprintx-json", nil
		case hasProtocol && hasPort:
			return "nerva-json", nil
		}
		return "", fmt.Errorf("unrecognized JSON shape")
	case nervaURIRE.MatchString(s):
		return "nerva-uri", nil
	case hostPortRE.MatchString(s):
		return "naabu", nil
	}
	return "", fmt.Errorf("unrecognized line format: %s", s)
}

// ParseStream reads a full stream, auto-detects the format, and returns
// the parsed Hosts. Convenience over DetectStreamFormat + format-specific
// parser when callers want one-shot ingestion.
func ParseStream(r io.Reader) ([]Host, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read stream: %w", err)
	}
	format, err := DetectStreamFormat(bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	switch format {
	case "naabu":
		return parseNaabuLines(buf), nil
	case "nerva-uri":
		return parseNervaURI(buf), nil
	case "nerva-json":
		return parseNervaJSON(buf)
	case "masscan-json":
		return ParseMasscanJSON(bytes.NewReader(buf))
	case "fingerprintx-json":
		return parseFingerprintXJSON(buf)
	}
	return nil, fmt.Errorf("unsupported format: %s", format)
}

func parseNaabuLines(buf []byte) []Host {
	var out []Host
	for _, raw := range bytes.Split(buf, []byte("\n")) {
		s := strings.TrimSpace(string(raw))
		if s == "" {
			continue
		}
		host, port, err := splitHostPort(s)
		if err != nil {
			continue
		}
		svc := defaultServiceForPort(port)
		if svc == "" {
			continue
		}
		out = append(out, Host{Service: svc, Host: host, Port: port})
	}
	return out
}

func parseNervaURI(buf []byte) []Host {
	var out []Host
	for _, raw := range bytes.Split(buf, []byte("\n")) {
		s := strings.TrimSpace(string(raw))
		if s == "" {
			continue
		}
		// Strip parenthetical resolution suffix like "ssh://github.com:22 (140.82.121.4)"
		if idx := strings.Index(s, " "); idx > 0 {
			s = s[:idx]
		}
		schemeEnd := strings.Index(s, "://")
		if schemeEnd < 0 {
			continue
		}
		scheme := s[:schemeEnd]
		rest := s[schemeEnd+3:]
		host, port, err := splitHostPort(rest)
		if err != nil {
			continue
		}
		out = append(out, Host{Service: scheme, Host: host, Port: port})
	}
	return out
}

type nervaRow struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

func parseNervaJSON(buf []byte) ([]Host, error) {
	var out []Host
	dec := json.NewDecoder(bytes.NewReader(buf))
	for dec.More() {
		var row nervaRow
		if err := dec.Decode(&row); err != nil {
			return nil, fmt.Errorf("decode nerva-json: %w", err)
		}
		out = append(out, Host{Service: row.Protocol, Host: row.IP, Port: row.Port})
	}
	return out, nil
}

type fpxRow struct {
	Host    string `json:"host"`
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Service string `json:"service"`
}

func parseFingerprintXJSON(buf []byte) ([]Host, error) {
	var out []Host
	dec := json.NewDecoder(bytes.NewReader(buf))
	for dec.More() {
		var row fpxRow
		if err := dec.Decode(&row); err != nil {
			return nil, fmt.Errorf("decode fingerprintx-json: %w", err)
		}
		h := row.Host
		if h == "" {
			h = row.IP
		}
		out = append(out, Host{Service: row.Service, Host: h, Port: row.Port})
	}
	return out, nil
}

func splitHostPort(s string) (string, int, error) {
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return "", 0, fmt.Errorf("no port: %s", s)
	}
	port, err := strconv.Atoi(s[idx+1:])
	if err != nil {
		return "", 0, err
	}
	return s[:idx], port, nil
}
