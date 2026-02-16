package brute

import (
	"math/rand"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/modules"
)

func ClearMaps() {
	// Deprecated: Maps are now local to RunBrute
}

// calculateBackoff calculates exponential backoff with jitter
func calculateBackoff(retryCount int, baseTimeout time.Duration) time.Duration {
	if retryCount == 0 {
		return baseTimeout
	}

	// Exponential backoff: 2^retryCount * baseTimeout
	backoff := baseTimeout * time.Duration(1<<uint(retryCount))

	// Cap at 10 seconds
	if backoff > 10*time.Second {
		backoff = 10 * time.Second
	}

	// Add jitter (±25%)
	// random in [-0.25, +0.25]
	factor := 1 + (rand.Float64()*0.5 - 0.25)
	backoff = time.Duration(float64(backoff) * factor)

	return backoff
}

func RunBrute(h modules.Host, u string, p string, progressCh chan<- int, timeout time.Duration, maxRetries int, output string, socks5 string, netInterface string, domain string, cm *modules.ConnectionManager) bool {
	service := h.Service
	var result, con_result bool

	// Start performance monitoring
	startTime := time.Now()
	metrics := modules.GetGlobalMetrics()

	retries := 0

	for {
		if retries >= maxRetries {
			// Record failed attempt (connection never succeeded)
			metrics.RecordAttempt(false, time.Since(startTime))
			modules.RecordAttempt(false)
			return false
		}

		// Calculate backoff delay
		delayTime := calculateBackoff(retries, timeout)

		switch service {
		case "ssh":
			result, con_result = BruteSSH(h.Host, h.Port, u, p, timeout, cm)
		case "ftp":
			result, con_result = BruteFTP(h.Host, h.Port, u, p, timeout, cm)
		case "mssql":
			result, con_result = BruteMSSQL(h.Host, h.Port, u, p, timeout, cm)
		case "telnet":
			result, con_result = BruteTelnet(h.Host, h.Port, u, p, timeout, cm)
		case "smbnt":
			parsedUser := u
			parsedDomain := domain
			if parsedDomain == "" && strings.Contains(u, "\\") {
				parts := strings.SplitN(u, "\\", 2)
				if len(parts) == 2 {
					parsedDomain = parts[0]
					parsedUser = parts[1]
				}
			}
			result, con_result = BruteSMB(h.Host, h.Port, parsedUser, p, timeout, cm, parsedDomain)
		case "postgres":
			result, con_result = BrutePostgres(h.Host, h.Port, u, p, timeout, cm)
		case "smtp":
			result, con_result = BruteSMTP(h.Host, h.Port, u, p, timeout, cm)
		case "imap":
			result, con_result = BruteIMAP(h.Host, h.Port, u, p, timeout, cm)
		case "pop3":
			result, con_result = BrutePOP3(h.Host, h.Port, u, p, timeout, cm)
		case "snmp":
			result, con_result = BruteSNMP(h.Host, h.Port, u, p, timeout, cm)
		case "mysql":
			result, con_result = BruteMYSQL(h.Host, h.Port, u, p, timeout, cm)
		case "vmauthd":
			result, con_result = BruteVMAuthd(h.Host, h.Port, u, p, timeout, cm)
		case "asterisk":
			result, con_result = BruteAsterisk(h.Host, h.Port, u, p, timeout, cm)
		case "vnc":
			result, con_result = BruteVNC(h.Host, h.Port, u, p, timeout, cm)
		case "mongodb":
			result, con_result = BruteMongoDB(h.Host, h.Port, u, p, timeout, cm)
		case "nntp":
			result, con_result = BruteNNTP(h.Host, h.Port, u, p, timeout, cm)
		case "oracle":
			result, con_result = BruteOracle(h.Host, h.Port, u, p, timeout, cm)
		case "teamspeak":
			result, con_result = BruteTeamSpeak(h.Host, h.Port, u, p, timeout, cm)
		case "xmpp":
			result, con_result = BruteXMPP(h.Host, h.Port, u, p, timeout, cm)
		case "rdp":
			parsedUser := u
			parsedDomain := domain
			if domain == "" && strings.Contains(u, "\\") {
				parts := strings.SplitN(u, "\\", 2)
				if len(parts) == 2 {
					parsedDomain = parts[0]
					parsedUser = parts[1]
				}
			}
			result, con_result = BruteRDP(h.Host, h.Port, parsedUser, p, timeout, cm, parsedDomain)
		case "redis":
			result, con_result = BruteRedis(h.Host, h.Port, u, p, timeout, cm)
		case "http":
			result, con_result = BruteHTTP(h.Host, h.Port, u, p, timeout, cm)
		case "https":
			result, con_result = BruteHTTP(h.Host, h.Port, u, p, timeout, cm)
		default:
			metrics.RecordAttempt(false, time.Since(startTime))
			modules.RecordAttempt(false)
			return false
		}

		if con_result {
			// Connection succeeded — record attempt exactly once (metrics updates response time only)
			metrics.RecordAttempt(result, time.Since(startTime))
			modules.RecordAttempt(result)

			if result {
				// Authentication succeeded
				modules.RecordSuccess(service, h.Host, h.Port, u, p, time.Since(startTime))
			} else {
				// Authentication failed
				modules.RecordError(false) // Authentication error
			}

			break
		} else {
			// Connection failed: increment the consecutive failure counter
			retries++

			willRetry := retries < maxRetries

			// Record connection error
			metrics.RecordError(true)

			modules.PrintResult(service, h.Host, h.Port, u, p, result, con_result, progressCh, willRetry, output, delayTime)

			if willRetry {
				time.Sleep(delayTime)
			}
		}
	}

	modules.PrintResult(service, h.Host, h.Port, u, p, result, con_result, progressCh, false, output, 0)
	return con_result
}

func WaitForSkipsToComplete() {
	// Deprecated: Scaling logic handles cleanup
}
