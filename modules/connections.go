package modules

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/net/proxy"
)

type ConnectionManager struct {
	Socks5   string
	Timeout  time.Duration
	Iface    string
	Dialer   proxy.Dialer
	DialFunc func(network, address string) (net.Conn, error)
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
		Socks5:  socks5,
		Timeout: timeout,
		Iface:   ifaceName,
	}

	if socks5 != "" {
		dialer, err := proxy.SOCKS5("tcp", socks5, nil, nil)
		if err != nil {
			PrintSocksError("connection_manager", fmt.Sprintf("%v", err))
			return nil, err
		}
		cm.Dialer = dialer
		cm.DialFunc = cm.Dialer.Dial
	} else {
		// Bind to specific network interface
		ipAddr, err := getIPv4Address(ifaceName)
		if err != nil {
			return nil, err
		}
		localAddr := &net.TCPAddr{IP: ipAddr}
		dialer := &net.Dialer{Timeout: timeout, LocalAddr: localAddr}
		cm.DialFunc = dialer.Dial
		//fmt.Printf("Binding to local address: %s\n", localAddr)
	}

	return cm, nil
}

func (cm *ConnectionManager) Dial(network, address string) (net.Conn, error) {
	return cm.DialFunc(network, address)
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

func getIPv4Address(ifaceName string) (net.IP, error) {
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
	// Connect to a known external address (e.g., 8.8.8.8:80)
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", fmt.Errorf("failed to determine default interface: %v", err)
	}
	defer conn.Close()

	// Get the local address of the connection
	localAddr := conn.LocalAddr().(*net.UDPAddr)

	// Find the interface associated with the local address
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
