package wordlist

import "embed"

//go:embed manifest.yaml all:_base all:_layers all:overrides snmp
var FS embed.FS
