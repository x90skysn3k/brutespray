package modules

import (
	"bufio"
	"fmt"
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

// detectFileFormat reads the first lines of a file to determine its format.
func detectFileFormat(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return "", scanner.Err()
	}
	line := scanner.Text()

	if line[0] == '{' {
		return "json", nil
	}
	if strings.HasPrefix(line, "# Nmap") {
		if !scanner.Scan() {
			return "", scanner.Err()
		}
		if !strings.HasPrefix(scanner.Text()[1:], "Nmap") {
			return "gnmap", nil
		}
		return "", fmt.Errorf("file is not a supported format")
	}
	if strings.HasPrefix(line, "<NexposeReport ") {
		return "xml_nexpose", nil
	}
	if strings.Contains(line, "<?xml ") {
		if !scanner.Scan() {
			return "", scanner.Err()
		}
		line = scanner.Text()
		if strings.Contains(line, "nmaprun") {
			return "xml", nil
		}
		if strings.HasPrefix(line, "<NessusClientData") {
			return "xml_nessus", nil
		}
		return "", fmt.Errorf("file is not a supported format")
	}
	return "list", nil
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
