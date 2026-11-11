package modules

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

type masscanPort struct {
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	Status string `json:"status"`
}

type masscanHost struct {
	IP    string        `json:"ip"`
	Ports []masscanPort `json:"ports"`
}

// ParseMasscanJSON reads masscan -oJ output (a JSON array of host objects,
// each carrying an array of open-port records) and returns one Host per
// open port. Service is inferred from port via defaultServiceForPort;
// ports with no mapping are dropped. Newline-delimited records of the same
// shape (e.g. `jq -c '.[]' scan.json`) are also accepted.
func ParseMasscanJSON(r io.Reader) ([]Host, error) {
	br := bufio.NewReader(r)
	if err := skipBlankAndCommentLines(br); err != nil {
		return nil, fmt.Errorf("decode masscan json: empty input")
	}
	dec := json.NewDecoder(br)
	var out []Host
	if b, _ := br.Peek(1); len(b) > 0 && b[0] == '[' {
		if _, err := dec.Token(); err != nil { // consume '['
			return nil, fmt.Errorf("decode masscan json: %w", err)
		}
	}
	for dec.More() {
		var row masscanHost
		if err := dec.Decode(&row); err != nil {
			return nil, fmt.Errorf("decode masscan json: %w", err)
		}
		out = appendHosts(out, row)
	}
	return out, nil
}

// skipBlankAndCommentLines advances br past leading blank lines and
// '#' comment lines.
func skipBlankAndCommentLines(br *bufio.Reader) error {
	for {
		b, err := br.Peek(1)
		if err != nil {
			return err
		}
		switch b[0] {
		case '#':
			if _, err := br.ReadString('\n'); err != nil && err != io.EOF {
				return err
			}
		case ' ', '\t', '\n', '\r':
			if _, err := br.Discard(1); err != nil {
				return err
			}
		default:
			return nil
		}
	}
}

func appendHosts(out []Host, row masscanHost) []Host {
	for _, p := range row.Ports {
		if p.Status != "open" {
			continue
		}
		svc := defaultServiceForPort(p.Port)
		if svc == "" {
			continue
		}
		out = append(out, Host{Service: svc, Host: row.IP, Port: p.Port})
	}
	return out
}

// ParseMasscanJSONFile reads masscan -oJ output from a file.
func ParseMasscanJSONFile(filename string) (map[Host]int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	hosts, err := ParseMasscanJSON(file)
	if err != nil {
		return nil, err
	}
	return hostSliceToMap(hosts), nil
}

// ParseMasscanList reads masscan -oL output:
//
//	#masscan
//	open tcp 443 203.0.113.10 1786719582
//	# end
//
// Columns are status, protocol, port, IP, timestamp. Header/footer lines
// start with '#'. Only "open" rows survive; ports without a service
// mapping are dropped.
func ParseMasscanList(r io.Reader) ([]Host, error) {
	var out []Host
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "open" {
			continue
		}
		port, err := strconv.Atoi(fields[2])
		if err != nil || port <= 0 {
			continue
		}
		svc := defaultServiceForPort(port)
		if svc == "" {
			continue
		}
		out = append(out, Host{Service: svc, Host: fields[3], Port: port})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ParseMasscanListFile reads masscan -oL output from a file.
func ParseMasscanListFile(filename string) (map[Host]int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	hosts, err := ParseMasscanList(file)
	if err != nil {
		return nil, err
	}
	return hostSliceToMap(hosts), nil
}
