// Package badkeys provides a curated, embedded bundle of known-compromised
// SSH private keys (Rapid7 ssh-badkeys + Vagrant + vendor defaults). Each
// entry pairs a key with its default username and CVE metadata so brute
// modules can surface CVE-tagged findings without external files.
package badkeys

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"gopkg.in/yaml.v3"
)

type Entry struct {
	File        string
	Username    string
	Vendor      string
	CVE         string
	Description string
	PEM         []byte
	Fingerprint string // sha256 hex of PEM bytes
}

type metaEntry struct {
	File        string `yaml:"file"`
	Username    string `yaml:"username"`
	Vendor      string `yaml:"vendor"`
	CVE         string `yaml:"cve"`
	Description string `yaml:"description"`
}

func Load() ([]Entry, error) {
	raw, err := assets.ReadFile("metadata.yaml")
	if err != nil {
		return nil, fmt.Errorf("read metadata.yaml: %w", err)
	}
	var metas []metaEntry
	if err := yaml.Unmarshal(raw, &metas); err != nil {
		return nil, fmt.Errorf("parse metadata.yaml: %w", err)
	}
	out := make([]Entry, 0, len(metas))
	for _, m := range metas {
		pem, err := assets.ReadFile("keys/" + m.File)
		if err != nil {
			return nil, fmt.Errorf("read keys/%s: %w", m.File, err)
		}
		sum := sha256.Sum256(pem)
		out = append(out, Entry{
			File:        m.File,
			Username:    m.Username,
			Vendor:      m.Vendor,
			CVE:         m.CVE,
			Description: m.Description,
			PEM:         pem,
			Fingerprint: hex.EncodeToString(sum[:]),
		})
	}
	return out, nil
}
