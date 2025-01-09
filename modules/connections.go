package modules

import (
	"fmt"
	"net"
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
	PoolMutex sync.Mutex
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
		//fmt.Printf("Using default interface: %s\n", ifaceName)
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
	localAddr := &net.TCPAddr{IP: ipAddr}

	if socks5 != "" {
		dialer, err := proxy.SOCKS5("tcp", socks5, nil, nil)
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
		// Bind to specific network interface
		dialer := &net.Dialer{Timeout: timeout, LocalAddr: localAddr}
		cm.DialFunc = dialer.Dial
		//fmt.Printf("Binding to local address: %s\n", localAddr)
	}

	return cm, nil
}

func (cm *ConnectionManager) Dial(network, address string) (net.Conn, error) {
	key := fmt.Sprintf("%s:%s", network, address)

	cm.PoolMutex.Lock()
	if _, ok := cm.ConnPool[key]; !ok {
		cm.ConnPool[key] = make(chan net.Conn, 10)
	}
	cm.PoolMutex.Unlock()

	select {
	case conn := <-cm.ConnPool[key]:
		return conn, nil
	default:
		conn, err := cm.DialFunc(network, address)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
}

func (cm *ConnectionManager) Release(conn net.Conn) {
	if conn == nil {
		return
	}

	cm.PoolMutex.Lock()
	defer cm.PoolMutex.Unlock()

	key := fmt.Sprintf("%s:%s", conn.RemoteAddr().Network(), conn.RemoteAddr().String())

	if _, ok := cm.ConnPool[key]; !ok {
		cm.ConnPool[key] = make(chan net.Conn, 10)
	}

	select {
	case cm.ConnPool[key] <- conn:
	default:
		conn.Close()
	}
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
