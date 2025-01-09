package brute

import (
	"sync"
	"time"

	"github.com/x90skysn3k/brutespray/modules"
)

var (
	retryMap      = make(map[string]int)
	skipMap       = make(map[string]bool)
	retryMapMutex = &sync.Mutex{}
	skipWg        sync.WaitGroup
)

func ClearMaps() {
	retryMapMutex.Lock()
	defer retryMapMutex.Unlock()

	retryMap = make(map[string]int)
	skipMap = make(map[string]bool)
}

func RunBrute(h modules.Host, u string, p string, progressCh chan<- int, timeout time.Duration, maxRetries int, output string, socks5 string, netInterface string) bool {
	service := h.Service
	var result, con_result bool
	var retrying bool
	var delayTime time.Duration

	key := h.Host + ":" + h.Service

	for {
		retryMapMutex.Lock()

		retries, ok := retryMap[key]
		if !ok {
			retries = 0
		}

		if retries >= maxRetries {
			if !skipMap[key] {
				skipMap[key] = true
				skipWg.Add(1)
				go func(host, service string, retries, maxRetries int) {
					defer skipWg.Done()
					modules.PrintSkipping(host, service, retries, maxRetries)
				}(h.Host, service, retries, maxRetries)
			}
			retryMapMutex.Unlock()
			return false
		}

		retryMap[key] = retries + 1
		retrying = true
		retryMapMutex.Unlock()

		delayTime = timeout * time.Duration(retries)
		if delayTime > 10*time.Second {
			delayTime = 10 * time.Second
		}

		switch service {
		case "ssh":
			result, con_result = BruteSSH(h.Host, h.Port, u, p, timeout, socks5, netInterface)
		case "ftp":
			result, con_result = BruteFTP(h.Host, h.Port, u, p, timeout, socks5, netInterface)
		case "mssql":
			result, con_result = BruteMSSQL(h.Host, h.Port, u, p, timeout, socks5, netInterface)
		case "telnet":
			result, con_result = BruteTelnet(h.Host, h.Port, u, p, timeout, socks5, netInterface)
		case "smbnt":
			result, con_result = BruteSMB(h.Host, h.Port, u, p, timeout, socks5, netInterface)
		case "postgres":
			result, con_result = BrutePostgres(h.Host, h.Port, u, p, timeout, socks5, netInterface)
		case "smtp":
			result, con_result = BruteSMTP(h.Host, h.Port, u, p, timeout, socks5, netInterface)
		case "imap":
			result, con_result = BruteIMAP(h.Host, h.Port, u, p, timeout, socks5, netInterface)
		case "pop3":
			result, con_result = BrutePOP3(h.Host, h.Port, u, p, timeout, socks5, netInterface)
		case "snmp":
			result, con_result = BruteSNMP(h.Host, h.Port, u, p, timeout, socks5, netInterface)
		case "mysql":
			result, con_result = BruteMYSQL(h.Host, h.Port, u, p, timeout, socks5, netInterface)
		case "vmauthd":
			result, con_result = BruteVMAuthd(h.Host, h.Port, u, p, timeout, socks5, netInterface)
		case "asterisk":
			result, con_result = BruteAsterisk(h.Host, h.Port, u, p, timeout, socks5, netInterface)
		case "vnc":
			result, con_result = BruteVNC(h.Host, h.Port, u, p, timeout, socks5, netInterface)
		case "mongodb":
			result, con_result = BruteMongoDB(h.Host, h.Port, u, p, timeout, socks5, netInterface)
		case "nntp":
			result, con_result = BruteNNTP(h.Host, h.Port, u, p, timeout, socks5, netInterface)
		case "oracle":
			result, con_result = BruteOracle(h.Host, h.Port, u, p, timeout, socks5, netInterface)
		case "teamspeak":
			result, con_result = BruteTeamSpeak(h.Host, h.Port, u, p, timeout, socks5, netInterface)
		case "xmpp":
			result, con_result = BruteXMPP(h.Host, h.Port, u, p, timeout, socks5, netInterface)
		case "rdp":
			result, con_result = BruteRDP(h.Host, h.Port, u, p, timeout, socks5, netInterface)
		default:
			return false
		}

		if con_result {
			retryMapMutex.Lock()
			retryMap[key]--
			retryMapMutex.Unlock()
			break
		} else {
			modules.PrintResult(service, h.Host, h.Port, u, p, result, con_result, progressCh, retrying, output, delayTime)
			time.Sleep(delayTime)
		}
	}

	modules.PrintResult(service, h.Host, h.Port, u, p, result, con_result, progressCh, retrying, output, delayTime)
	return con_result
}

func WaitForSkipsToComplete() {
	skipWg.Wait()
}
