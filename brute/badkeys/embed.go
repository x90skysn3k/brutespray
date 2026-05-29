package badkeys

import "embed"

//go:embed keys/* metadata.yaml
var assets embed.FS
