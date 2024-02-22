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

func ParseFile(filename string) (map[Host]int, error) {
	in_format := ""
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return nil, scanner.Err()
	}
	line := scanner.Text()

	if line[0] == '{' {
		in_format = "json"
	} else if strings.HasPrefix(line, "# Nmap") {
		if !scanner.Scan() {
			return nil, scanner.Err()
		}
		line = scanner.Text()
		if !strings.HasPrefix(line[1:], "Nmap") {
			in_format = "gnmap"
		}
	} else if strings.HasPrefix(line, "<NexposeReport ") {
		in_format = "xml_nexpose"
	} else if strings.Contains(line, "<?xml ") {
		if !scanner.Scan() {
			return nil, scanner.Err()
		}
		line = scanner.Text()
		if strings.Contains(line, "nmaprun") {
			in_format = "xml"

		} else if strings.HasPrefix(line, "<NessusClientData") {
			in_format = "xml_nessus"
		}
	} else {
		in_format = "list"
	}

	if in_format == "" {
		fmt.Println("File is not correct format!")
		os.Exit(0)
	}

	switch in_format {
	case "gnmap":
		hosts, err := ParseGNMAP(filename)
		return hosts, err
	case "json":
		hosts, err := ParseJSON(filename)
		return hosts, err
	case "xml":
		hosts, err := ParseXML(filename)
		return hosts, err
	case "xml_nexpose":
		hosts, err := ParseNexpose(filename)
		return hosts, err
	case "xml_nessus":
		hosts, err := ParseNessus(filename)
		return hosts, err
	case "list":
		hosts, err := ParseList(filename)
		return hosts, err
	default:
		return nil, fmt.Errorf("unsupported file type: %s", in_format)
	}
}
