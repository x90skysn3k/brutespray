package brute

import (
	"time"

	"github.com/x90skysn3k/brutesprayx/modules"
)

var NAME_MAP = map[string]string{
	"ms-sql-s":       "mssql",
	"microsoft-ds":   "smbnt",
	"cifs":           "smbnt",
	"postgresql":     "postgres",
	"smtps":          "smtp",
	"submission":     "smtp",
	"imaps":          "imap",
	"pop3s":          "pop3",
	"iss-realsecure": "vmauthd",
	"snmptrap":       "snmp",
	"mysql":          "mysql",
	"vnc":            "vnc",
	//"ms-wbt-server":  "rdp",
}

func MapService(service string) string {
	if mappedService, ok := NAME_MAP[service]; ok {
		return mappedService
	}
	return service
}

func RunBrute(h modules.Host, u string, p string, progressCh chan<- int, timeout time.Duration, retry int) bool {
	service := MapService(h.Service)
	var result bool
	var con_result bool
	var retrying bool = false

	for i := 0; i < retry; i++ {
		switch service {
		case "ssh":
			result, con_result = BruteSSH(h.Host, h.Port, u, p, timeout)
		case "ftp":
			result, con_result = BruteFTP(h.Host, h.Port, u, p, timeout)
		case "mssql":
			result, con_result = BruteMSSQL(h.Host, h.Port, u, p, timeout)
		case "telnet":
			result, con_result = BruteTelnet(h.Host, h.Port, u, p, timeout)
		case "smbnt":
			result, con_result = BruteSMB(h.Host, h.Port, u, p, timeout)
		case "postgres":
			result, con_result = BrutePostgres(h.Host, h.Port, u, p, timeout)
		case "smtp":
			result, con_result = BruteSMTP(h.Host, h.Port, u, p, timeout)
		case "imap":
			result, con_result = BruteIMAP(h.Host, h.Port, u, p, timeout)
		case "pop3":
			result, con_result = BrutePOP3(h.Host, h.Port, u, p, timeout)
		case "snmp":
			result, con_result = BrutePOP3(h.Host, h.Port, u, p, timeout)
		case "mysql":
			result, con_result = BruteMYSQL(h.Host, h.Port, u, p, timeout)
		case "vmauthd":
			result, con_result = BruteVMAuthd(h.Host, h.Port, u, p, timeout)
		case "asterisk":
			result, con_result = BruteAsterisk(h.Host, h.Port, u, p, timeout)
		case "vnc":
			result, con_result = BruteVNC(h.Host, h.Port, u, p, timeout)
		//case "rdp":
		//	result, con_result = brute.BruteRDP(h.Host, h.Port, u, p)
		default:
			//fmt.Printf("Unsupported service: %s\n", h.Service)
			return con_result
		}
		if con_result {
			break
		} else {
			retrying := true
			modules.PrintResult(service, h.Host, h.Port, u, p, result, con_result, progressCh, retrying)
		}
	}
	modules.PrintResult(service, h.Host, h.Port, u, p, result, con_result, progressCh, retrying)
	return con_result
}
