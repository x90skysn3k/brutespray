package brute

import (
	"strings"
	"sync"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

var (
	retryMap      = make(map[string]int)
	skipMap       = make(map[string]bool)
	retryMapMutex = &sync.RWMutex{} // Use RWMutex for better performance
	skipWg        sync.WaitGroup
)

// ConnectionPool manages reusable connections for better performance
type ConnectionPool struct {
	pool    map[string][]interface{}
	mutex   sync.RWMutex
	timeout time.Duration
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(timeout time.Duration) *ConnectionPool {
	return &ConnectionPool{
		pool:    make(map[string][]interface{}),
		timeout: timeout,
	}
}

// GetConnection retrieves a connection from the pool
func (cp *ConnectionPool) GetConnection(key string) (interface{}, bool) {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()

	if connections, exists := cp.pool[key]; exists && len(connections) > 0 {
		conn := connections[len(connections)-1]
		cp.pool[key] = connections[:len(connections)-1]
		return conn, true
	}
	return nil, false
}

// PutConnection returns a connection to the pool
func (cp *ConnectionPool) PutConnection(key string, conn interface{}) {
	if conn == nil {
		return
	}

	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	if len(cp.pool[key]) < 10 { // Limit pool size per key
		cp.pool[key] = append(cp.pool[key], conn)
	}
}

// ClearPool clears all connections in the pool
func (cp *ConnectionPool) ClearPool() {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	cp.pool = make(map[string][]interface{})
}

var connectionPool = NewConnectionPool(5 * time.Second)

func ClearMaps() {
	retryMapMutex.Lock()
	defer retryMapMutex.Unlock()

	retryMap = make(map[string]int)
	skipMap = make(map[string]bool)
	connectionPool.ClearPool()
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
	jitter := backoff / 4
	backoff = backoff + time.Duration(float64(jitter)*(0.5-0.25))

	return backoff
}

func RunBrute(h modules.Host, u string, p string, progressCh chan<- int, timeout time.Duration, maxRetries int, output string, socks5 string, netInterface string, domain string) bool {
	service := h.Service
	var result, con_result bool

	// Start performance monitoring
	startTime := time.Now()
	metrics := modules.GetGlobalMetrics()

	// Scope retries to the specific credential attempt (host, service, user, pass)
	key := h.Host + ":" + h.Service + ":" + u + ":" + p

	for {
		retryMapMutex.RLock()
		retries, ok := retryMap[key]
		if !ok {
			retries = 0
		}
		retryMapMutex.RUnlock()

		if retries >= maxRetries {
			retryMapMutex.Lock()
			if !skipMap[key] {
				skipMap[key] = true
				skipWg.Add(1)
				go func(host, service string, retries, maxRetries int) {
					defer skipWg.Done()
					modules.PrintSkipping(host, service, retries, maxRetries)
				}(h.Host, service, retries, maxRetries)
			}
			retryMapMutex.Unlock()

			// Record failed attempt
			metrics.RecordAttempt(false, time.Since(startTime))
			return false
		}

		// Calculate backoff delay
		delayTime := calculateBackoff(retries, timeout)

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
			parsedUser := u
			parsedDomain := domain
			if parsedDomain == "" && strings.Contains(u, "\\") {
				parts := strings.SplitN(u, "\\", 2)
				if len(parts) == 2 {
					parsedDomain = parts[0]
					parsedUser = parts[1]
				}
			}
			result, con_result = BruteSMB(h.Host, h.Port, parsedUser, p, timeout, socks5, netInterface, parsedDomain)
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
			parsedUser := u
			parsedDomain := domain
			if domain == "" && strings.Contains(u, "\\") {
				parts := strings.SplitN(u, "\\", 2)
				if len(parts) == 2 {
					parsedDomain = parts[0]
					parsedUser = parts[1]
				}
			}
			result, con_result = BruteRDP(h.Host, h.Port, parsedUser, p, timeout, socks5, netInterface, parsedDomain)
		case "http":
			result, con_result = BruteHTTP(h.Host, h.Port, u, p, timeout, socks5, netInterface)
		case "https":
			result, con_result = BruteHTTP(h.Host, h.Port, u, p, timeout, socks5, netInterface)
		default:
			metrics.RecordAttempt(false, time.Since(startTime))
			return false
		}

		if con_result {
			// Connection succeeded: reset consecutive failure counter for this host/service.
			retryMapMutex.Lock()
			retryMap[key] = 0
			retryMapMutex.Unlock()

			// Record successful attempt
			metrics.RecordAttempt(result, time.Since(startTime))

			// Record in new statistics system
			if result {
				// Authentication succeeded
				modules.RecordSuccess(service, h.Host, h.Port, u, p, time.Since(startTime))
			} else {
				// Authentication failed
				modules.RecordError(false) // Authentication error
			}

			// Record the attempt (success or failure)
			modules.RecordAttempt(result)

			break
		} else {
			// Connection failed: increment the consecutive failure counter
			retryMapMutex.Lock()
			nextRetries := retryMap[key] + 1
			retryMap[key] = nextRetries
			retryMapMutex.Unlock()

			willRetry := nextRetries < maxRetries

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
	skipWg.Wait()
}
