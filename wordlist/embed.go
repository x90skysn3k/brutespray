package wordlist

import "embed"

//go:embed manifest.yaml all:_base all:_layers all:overrides snmp couchdb elasticsearch influxdb
var FS embed.FS
