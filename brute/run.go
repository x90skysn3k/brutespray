package brute

import (
	"math"
	"time"

	"github.com/x90skysn3k/brutespray/modules"
)

func RunBrute(h modules.Host, u string, p string, progressCh chan<- int, timeout time.Duration, retry int, output string) bool {
	service := h.Service
	var result bool
	var con_result bool
	var retrying bool = false
	var delayTime time.Duration = 1 * time.Second

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
		case "mongodb":
			result, con_result = BruteMongoDB(h.Host, h.Port, u, p, timeout)
		case "nntp":
			result, con_result = BruteNNTP(h.Host, h.Port, u, p, timeout)
		case "oracle":
			result, con_result = BruteOracle(h.Host, h.Port, u, p, timeout)
		case "teamspeak":
			result, con_result = BruteTeamSpeak(h.Host, h.Port, u, p, timeout)
		case "xmpp":
			result, con_result = BruteXMPP(h.Host, h.Port, u, p, timeout)
		case "rdp":
			result, con_result = BruteRDP(h.Host, h.Port, u, p, timeout)
		default:
			//fmt.Printf("Unsupported service: %s\n", h.Service)
			return con_result
		}
		if con_result {
			break
		} else {
			delayTime = time.Duration(int64(time.Second) * int64(math.Min(10, float64(i+2))))
			retrying := true
			modules.PrintResult(service, h.Host, h.Port, u, p, result, con_result, progressCh, retrying, output, delayTime)
			time.Sleep(delayTime)
		}
	}
	modules.PrintResult(service, h.Host, h.Port, u, p, result, con_result, progressCh, retrying, output, delayTime)
	return con_result
}
