package modules

import (
	"encoding/json"
	"fmt"
	"io"
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
// ports with no mapping are dropped.
func ParseMasscanJSON(r io.Reader) ([]Host, error) {
	var rows []masscanHost
	if err := json.NewDecoder(r).Decode(&rows); err != nil {
		return nil, fmt.Errorf("decode masscan json: %w", err)
	}
	var out []Host
	for _, row := range rows {
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
	}
	return out, nil
}
