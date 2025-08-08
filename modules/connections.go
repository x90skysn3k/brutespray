package modules

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

type ConnectionManager struct {
	Socks5    string
	Timeout   time.Duration
	Iface     string
	Dialer    proxy.Dialer
	DialFunc  func(network, address string) (net.Conn, error)
	ConnPool  map[string]chan net.Conn
	PoolMutex sync.RWMutex // Use RWMutex for better performance
	// Add connection pool for better performance
	connCache  map[string]*net.Conn
	cacheMutex sync.RWMutex
}

func NewConnectionManager(socks5 string, timeout time.Duration, iface ...string) (*ConnectionManager, error) {
	var ifaceName string
	if len(iface) > 0 && iface[0] != "" {
		ifaceName = iface[0]
	} else {
		defaultIface, err := getDefaultInterface()
		if err != nil {
			return nil, fmt.Errorf("failed to determine default interface: %v", err)
		}
		ifaceName = defaultIface
	}

	cm := &ConnectionManager{
		Socks5:    socks5,
		Timeout:   timeout,
		Iface:     ifaceName,
		ConnPool:  make(map[string]chan net.Conn),
		connCache: make(map[string]*net.Conn),
	}

	ipAddr, err := GetIPv4Address(ifaceName)
	if err != nil {
		return nil, err
	}
	localAddr := &net.TCPAddr{IP: ipAddr}

	if socks5 != "" {
		// Ensure the TCP connection to the proxy binds to the desired interface
		forward := &net.Dialer{Timeout: timeout, LocalAddr: localAddr}

		var dialer proxy.Dialer
		var err error

		// Support full URL format like socks5://user:pass@host:port and socks5h://...
		if strings.Contains(socks5, "://") {
			parsed, perr := url.Parse(socks5)
			if perr != nil {
				PrintSocksError("connection_manager", fmt.Sprintf("invalid proxy URL: %v", perr))
				return nil, perr
			}
			// Normalize socks5h to socks5. Hostname resolution will still be done by SOCKS5.
			if strings.EqualFold(parsed.Scheme, "socks5h") {
				parsed.Scheme = "socks5"
			}
			dialer, err = proxy.FromURL(parsed, forward)
		} else {
			// host:port format without credentials
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
		// Bind to specific network interface with optimized dialer
		dialer := &net.Dialer{
			Timeout:   timeout,
			LocalAddr: localAddr,
			// Add keep-alive settings for better performance
			KeepAlive: 30 * time.Second,
		}
		cm.DialFunc = dialer.Dial
	}

	return cm, nil
}

func (cm *ConnectionManager) Dial(network, address string) (net.Conn, error) {
	key := fmt.Sprintf("%s:%s", network, address)

	// Try to get from cache first
	cm.cacheMutex.RLock()
	if cachedConn, exists := cm.connCache[key]; exists && *cachedConn != nil {
		conn := *cachedConn
		// Check if connection is still alive
		if conn != nil {
			// Quick check if connection is still usable
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				if tcpConn != nil {
					// Try to get connection state
					if _, err := tcpConn.Write([]byte{}); err == nil {
						cm.cacheMutex.RUnlock()
						return conn, nil
					}
				}
			}
		}
		// Remove dead connection from cache
		delete(cm.connCache, key)
	}
	cm.cacheMutex.RUnlock()

	// Try connection pool
	cm.PoolMutex.RLock()
	if pool, ok := cm.ConnPool[key]; ok {
		cm.PoolMutex.RUnlock()
		select {
		case conn := <-pool:
			if conn != nil {
				// Verify connection is still alive
				if tcpConn, ok := conn.(*net.TCPConn); ok {
					if _, err := tcpConn.Write([]byte{}); err == nil {
						return conn, nil
					}
				}
				conn.Close()
			}
		default:
		}
	} else {
		cm.PoolMutex.RUnlock()
	}

	// Create new connection
	conn, err := cm.DialFunc(network, address)
	if err != nil {
		return nil, err
	}

	// Cache the connection for reuse
	cm.cacheMutex.Lock()
	cm.connCache[key] = &conn
	cm.cacheMutex.Unlock()

	return conn, nil
}

func (cm *ConnectionManager) Release(conn net.Conn) {
	if conn == nil {
		return
	}

	key := fmt.Sprintf("%s:%s", conn.RemoteAddr().Network(), conn.RemoteAddr().String())

	// Try to add to pool first
	cm.PoolMutex.Lock()
	if _, ok := cm.ConnPool[key]; !ok {
		cm.ConnPool[key] = make(chan net.Conn, 5) // Reduced pool size for better memory management
	}

	select {
	case cm.ConnPool[key] <- conn:
		// Successfully added to pool
	default:
		// Pool is full, close the connection
		conn.Close()
	}
	cm.PoolMutex.Unlock()
}

func (cm *ConnectionManager) DialUDP(network, address string) (*net.UDPConn, error) {
	if network != "udp" {
		return nil, fmt.Errorf("DialUDP requires 'udp' network, got %s", network)
	}

	conn, err := cm.DialFunc("udp", address)
	if err != nil {
		return nil, err
	}

	// Cast the net.Conn to *net.UDPConn
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("failed to cast connection to *net.UDPConn")
	}

	return udpConn, nil
}

// ClearCache clears all cached connections
func (cm *ConnectionManager) ClearCache() {
	cm.cacheMutex.Lock()
	defer cm.cacheMutex.Unlock()

	for _, connPtr := range cm.connCache {
		if connPtr != nil && *connPtr != nil {
			(*connPtr).Close()
		}
	}
	cm.connCache = make(map[string]*net.Conn)
}

// ClearPool clears all pooled connections
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

func getDefaultInterface() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", fmt.Errorf("failed to determine default interface: %v", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to list interfaces: %v", err)
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || !ipNet.IP.Equal(localAddr.IP) {
				continue
			}
			return iface.Name, nil
		}
	}

	return "", fmt.Errorf("no matching interface found for IP %s", localAddr.IP)
}

func ValidateNetworkInterface(iface string) (string, error) {
	ifaceName := iface
	if ifaceName == "" {
		defaultIface, err := getDefaultInterface()
		if err != nil {
			return "", fmt.Errorf("failed to determine default interface: %v", err)
		}
		ifaceName = defaultIface
		fmt.Printf("Using default interface: %s\n", ifaceName)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("error getting network interfaces: %v", err)
	}

	found := false
	for _, iface := range ifaces {
		if iface.Name == ifaceName {
			found = true
			break
		}
	}

	if !found {
		return "", fmt.Errorf("network interface %s not found or not available", ifaceName)
	}

	return ifaceName, nil
}
