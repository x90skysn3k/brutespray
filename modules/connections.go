package modules

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// InsecureTLS controls whether HTTPS/TLS verification is disabled for HTTP(S) modules
var InsecureTLS bool

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
		Socks5:   socks5,
		Timeout:  timeout,
		Iface:    ifaceName,
		ConnPool: make(map[string]chan net.Conn),
	}

	ipAddr, err := GetIPv4Address(ifaceName)
	if err != nil {
		return nil, err
	}
	cm.LocalIP = ipAddr
	localAddr := &net.TCPAddr{IP: ipAddr}

	if socks5 != "" {
		forward := &net.Dialer{Timeout: timeout, LocalAddr: localAddr}

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
			LocalAddr: localAddr,
			KeepAlive: 30 * time.Second,
		}
		cm.DialFunc = dialer.Dial
	}

	// Initialize Shared HTTP Client
	transport := &http.Transport{
		Dial:                  cm.DialFunc,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: InsecureTLS},
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

func (cm *ConnectionManager) Dial(network, address string) (net.Conn, error) {
	key := fmt.Sprintf("%s:%s", network, address)

	cm.PoolMutex.RLock()
	if pool, ok := cm.ConnPool[key]; ok {
		cm.PoolMutex.RUnlock()
		select {
		case conn := <-pool:
			if conn != nil {
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

	conn, err := cm.DialFunc(network, address)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (cm *ConnectionManager) Release(conn net.Conn) {
	if conn == nil {
		return
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

	laddr := &net.UDPAddr{IP: cm.LocalIP}

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
