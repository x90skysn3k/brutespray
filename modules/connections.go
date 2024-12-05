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
	Dialer   proxy.Dialer
	DialFunc func(network, address string) (net.Conn, error)
}

func NewConnectionManager(socks5 string, timeout time.Duration) (*ConnectionManager, error) {
	cm := &ConnectionManager{
		Socks5:  socks5,
		Timeout: timeout,
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
		cm.DialFunc = func(network, address string) (net.Conn, error) {
			return net.DialTimeout(network, address, timeout)
		}
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

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("failed to cast connection to *net.UDPConn")
	}

	return udpConn, nil
}
