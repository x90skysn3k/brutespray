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
