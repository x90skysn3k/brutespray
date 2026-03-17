package modules

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// maxConnAge is the maximum age of a pooled connection before it is discarded.
const maxConnAge = 30 * time.Second

// timedConn wraps a net.Conn and records when it was created so the pool can
// discard connections that have been idle for too long.
type timedConn struct {
	net.Conn
	created time.Time
}

type ConnectionManager struct {
	Socks5           string
	Timeout          time.Duration
	Iface            string
	LocalIP          net.IP
	Dialer           proxy.Dialer
	DialFunc         func(network, address string) (net.Conn, error)
	ConnPool         map[string]chan net.Conn
	PoolMutex        sync.RWMutex
	SharedHTTPClient *http.Client
	// Proxy rotation
	proxyList    []string
	proxyIndex   uint64
	proxyDialers []proxy.Dialer
}

func NewConnectionManager(socks5 string, timeout time.Duration, iface ...string) (*ConnectionManager, error) {
	var ifaceName string
	var localAddr *net.TCPAddr
	if len(iface) > 0 && iface[0] != "" {
		ifaceName = iface[0]
		ipAddr, err := GetIPv4Address(ifaceName)
		if err != nil {
			return nil, err
		}
		localAddr = &net.TCPAddr{IP: ipAddr}
	} else {
		// Do not bind to any interface: let the kernel choose the source address
		// based on the route to each destination. This fixes VPN/dual-homed setups
		// where the "default" route (e.g. via eth0) is wrong for targets on tun0.
		ifaceName = ""
		// localAddr stays nil - no binding
	}

	cm := &ConnectionManager{
		Socks5:   socks5,
		Timeout:  timeout,
		Iface:    ifaceName,
		ConnPool: make(map[string]chan net.Conn),
	}
	if localAddr != nil {
		cm.LocalIP = localAddr.IP
	}

	if socks5 != "" {
		forward := &net.Dialer{Timeout: timeout}
		if localAddr != nil {
			forward.LocalAddr = localAddr
		}

		var dialer proxy.Dialer
		var err error

		if strings.Contains(socks5, "://") {
			parsed, perr := url.Parse(socks5)
			if perr != nil {
				PrintSocksError("connection_manager", fmt.Sprintf("invalid proxy URL: %v", perr))
				return nil, perr
			}
			if strings.EqualFold(parsed.Scheme, "socks5h") {
				parsed.Scheme = "socks5"
			}
			dialer, err = proxy.FromURL(parsed, forward)
		} else {
			dialer, err = proxy.SOCKS5("tcp", socks5, nil, forward)
		}

		if err != nil {
			PrintSocksError("connection_manager", fmt.Sprintf("%v", err))
			return nil, err
		}

		cm.Dialer = dialer
		cm.DialFunc = func(network, address string) (net.Conn, error) {
			conn, err := dialer.Dial(network, address)
			if err != nil {
				PrintSocksError("Failed to connect to proxy:", fmt.Sprintf("%v", err))
			}
			return conn, err
		}
	} else {
		dialer := &net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}
		if localAddr != nil {
			dialer.LocalAddr = localAddr
		}
		cm.DialFunc = dialer.Dial
	}

	// Initialize Shared HTTP Client
	transport := &http.Transport{
		Dial:                  cm.DialFunc,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
	}

	cm.SharedHTTPClient = &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return cm, nil
}

// isConnAlive performs a non-destructive liveness check that works for any
// net.Conn implementation (including SOCKS5 proxy connections). It sets a
// very short read deadline; a timeout error means the connection is still
// alive (nothing to read but not closed), while any other error means it is
// dead.
func isConnAlive(conn net.Conn) bool {
	_ = conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	// Reset deadline regardless of outcome
	_ = conn.SetReadDeadline(time.Time{})
	if err == nil {
		// Got data unexpectedly — connection may be in a weird state, treat as dead
		return false
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		// Timeout means no data and not closed — connection is alive
		return true
	}
	// EOF or other error — connection is dead
	return false
}

func (cm *ConnectionManager) Dial(network, address string) (net.Conn, error) {
	key := fmt.Sprintf("%s:%s", network, address)

	cm.PoolMutex.RLock()
	if pool, ok := cm.ConnPool[key]; ok {
		cm.PoolMutex.RUnlock()
		select {
		case conn := <-pool:
			if conn != nil {
				// Check TTL — discard connections older than maxConnAge
				if tc, ok := conn.(*timedConn); ok {
					if time.Since(tc.created) > maxConnAge {
						conn.Close()
						break
					}
				}
				if isConnAlive(conn) {
					return conn, nil
				}
				conn.Close()
			}
		default:
		}
	} else {
		cm.PoolMutex.RUnlock()
	}

	raw, err := cm.DialFunc(network, address)
	if err != nil {
		return nil, err
	}

	return &timedConn{Conn: raw, created: time.Now()}, nil
}

func (cm *ConnectionManager) Release(conn net.Conn) {
	if conn == nil {
		return
	}

	// Ensure the connection is wrapped with timing metadata for TTL checks.
	if _, ok := conn.(*timedConn); !ok {
		conn = &timedConn{Conn: conn, created: time.Now()}
	}

	key := fmt.Sprintf("%s:%s", conn.RemoteAddr().Network(), conn.RemoteAddr().String())

	cm.PoolMutex.Lock()
	if _, ok := cm.ConnPool[key]; !ok {
		cm.ConnPool[key] = make(chan net.Conn, 5)
	}

	select {
	case cm.ConnPool[key] <- conn:
	default:
		conn.Close()
	}
	cm.PoolMutex.Unlock()
}

func (cm *ConnectionManager) DialUDP(network, address string) (*net.UDPConn, error) {
	if network != "udp" {
		return nil, fmt.Errorf("DialUDP requires 'udp' network, got %s", network)
	}

	if cm.Socks5 != "" {
		return nil, fmt.Errorf("UDP dialing over SOCKS5 is not supported")
	}

	raddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address %s: %v", address, err)
	}

	var laddr *net.UDPAddr
	if cm.LocalIP != nil {
		laddr = &net.UDPAddr{IP: cm.LocalIP}
	}

	udpConn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial UDP %s from %s: %v", raddr.String(), laddr.String(), err)
	}
	return udpConn, nil
}

func (cm *ConnectionManager) ClearPool() {
	cm.PoolMutex.Lock()
	defer cm.PoolMutex.Unlock()

	for _, pool := range cm.ConnPool {
		close(pool)
		for conn := range pool {
			if conn != nil {
				conn.Close()
			}
		}
	}
	cm.ConnPool = make(map[string]chan net.Conn)
}

// LoadProxyList reads a file containing one proxy per line (socks5://host:port)
// and sets up round-robin proxy rotation.
func (cm *ConnectionManager) LoadProxyList(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("opening proxy list: %w", err)
	}
	defer file.Close()

	var proxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		proxies = append(proxies, line)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading proxy list: %w", err)
	}
	if len(proxies) == 0 {
		return fmt.Errorf("proxy list is empty")
	}

	// Create dialers for each proxy
	forward := &net.Dialer{Timeout: cm.Timeout}
	if cm.LocalIP != nil {
		forward.LocalAddr = &net.TCPAddr{IP: cm.LocalIP}
	}

	var dialers []proxy.Dialer
	for _, p := range proxies {
		var dialer proxy.Dialer
		if strings.Contains(p, "://") {
			parsed, perr := url.Parse(p)
			if perr != nil {
				return fmt.Errorf("invalid proxy URL %q: %v", p, perr)
			}
			if strings.EqualFold(parsed.Scheme, "socks5h") {
				parsed.Scheme = "socks5"
			}
			dialer, err = proxy.FromURL(parsed, forward)
		} else {
			dialer, err = proxy.SOCKS5("tcp", p, nil, forward)
		}
		if err != nil {
			return fmt.Errorf("creating proxy dialer for %q: %v", p, err)
		}
		dialers = append(dialers, dialer)
	}

	cm.proxyList = proxies
	cm.proxyDialers = dialers

	// Randomize starting index
	cm.proxyIndex = uint64(rand.Intn(len(dialers)))

	// Override DialFunc to rotate through proxies
	cm.DialFunc = func(network, address string) (net.Conn, error) {
		idx := atomic.AddUint64(&cm.proxyIndex, 1) % uint64(len(cm.proxyDialers))
		return cm.proxyDialers[idx].Dial(network, address)
	}

	// Rebuild shared HTTP client with new dial function
	transport := &http.Transport{
		Dial:                  cm.DialFunc,
		TLSHandshakeTimeout:   cm.Timeout,
		ResponseHeaderTimeout: cm.Timeout,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
	}
	cm.SharedHTTPClient = &http.Client{
		Transport: transport,
		Timeout:   cm.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return nil
}

func GetIPv4Address(ifaceName string) (net.IP, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %s not found: %v", ifaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("unable to get addresses for interface %s: %v", ifaceName, err)
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP.To4()
		if ip != nil {
			return ip, nil
		}
	}

	return nil, fmt.Errorf("no IPv4 address found for interface %s", ifaceName)
}
