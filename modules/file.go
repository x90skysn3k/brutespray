package modules

import (
	"fmt"
	"io"
	"os"
	"strings"
)

func Contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func IsFile(fileName string) bool {
	if _, err := os.Stat(fileName); err == nil {
		return true
	}
	return false
}

// maxDetectBytes bounds how much of a file detectFileFormat inspects.
const maxDetectBytes = 1 << 20

// detectFileFormat reads the leading lines of a file to determine its
// format. Blank lines and generic full-line comments ("#...") are skipped,
// except where a comment header itself identifies the scanner format
// ("# Nmap"/"# Masscan" grepable output, "#masscan" list output).
func detectFileFormat(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

	head, err := io.ReadAll(io.LimitReader(file, maxDetectBytes))
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(string(head)) == "" {
		return "", fmt.Errorf("file is empty")
	}

	header := ""
	first := ""
	var probe []string
	for _, raw := range strings.Split(string(head), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "# Nmap") || strings.HasPrefix(line, "# Masscan") {
			header = "gnmap"
			continue
		}
		if strings.HasPrefix(line, "#masscan") {
			header = "masscan-list"
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		if first == "" {
			first = line
		}
		probe = append(probe, line)
		if len(probe) >= 64 {
			break
		}
	}

	switch {
	case strings.HasPrefix(first, "["):
		return "masscan-json", nil
	case strings.HasPrefix(first, "{") && strings.Contains(first, `"ports"`):
		// newline-delimited masscan records (e.g. `jq -c '.[]' scan.json`)
		return "masscan-json", nil
	case strings.HasPrefix(first, "{"):
		return "json", nil
	}

	if header != "" {
		return header, nil
	}

	if strings.HasPrefix(first, "<") {
		for _, line := range probe {
			if strings.Contains(line, "nmaprun") {
				return "xml", nil
			}
			if strings.Contains(line, "NessusClientData") {
				return "xml_nessus", nil
			}
			if strings.Contains(line, "<NexposeReport") {
				return "xml_nexpose", nil
			}
		}
		if strings.HasPrefix(first, "<?xml") {
			return "", fmt.Errorf("file is not a supported format")
		}
	}
	return "list", nil
}

// hostSliceToMap converts a parsed host slice into the deduplicated map
// shape ParseFile and its per-format parsers return.
func hostSliceToMap(hosts []Host) map[Host]int {
	m := make(map[Host]int, len(hosts))
	for _, h := range hosts {
		m[h] = 1
	}
	return m
}

// ParseFile detects the format of the input file and parses it.
func ParseFile(filename string) (map[Host]int, error) {
	format, err := detectFileFormat(filename)
	if err != nil {
		return nil, err
	}

	switch format {
	case "gnmap":
		return ParseGNMAP(filename)
	case "json":
		return ParseJSON(filename)
	case "masscan-json":
		return ParseMasscanJSONFile(filename)
	case "masscan-list":
		return ParseMasscanListFile(filename)
	case "xml":
		return ParseXML(filename)
	case "xml_nexpose":
		return ParseNexpose(filename)
	case "xml_nessus":
		return ParseNessus(filename)
	case "list":
		return ParseList(filename)
	default:
		return nil, fmt.Errorf("unsupported file type: %s", format)
	}
}
