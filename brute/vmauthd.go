package brute

import (
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/modules"
)

func BruteVMAuthd(host string, port int, user, password string, timeout time.Duration, socks5 string, netInterface string) (bool, bool) {
	address := fmt.Sprintf("%s:%d", host, port)

	cm, err := modules.NewConnectionManager(socks5, timeout, netInterface)
	if err != nil {
		return false, false
	}

	conn, err := cm.Dial("tcp", address)
	if err != nil {
		return false, false
	}
	defer conn.Close()

	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return false, false
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return false, false
	}
	response := string(buf[:n])
	if strings.Contains(response, "SSL Required") {
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
		defer tlsConn.Close()
		conn = tlsConn
	} else {
		err = conn.SetReadDeadline(time.Now().Add(timeout))
		if err != nil {
			return false, false
		}
	}

	cmd := fmt.Sprintf("USER %s\r\n", user)
	_, err = conn.Write([]byte(cmd))
	if err != nil {
		return false, true
	}

	buf = make([]byte, 1024)
	n, err = conn.Read(buf)
	if err != nil {
		return false, true
	}
	response = string(buf[:n])
	if !strings.HasPrefix(response, "331 ") {
		return false, true
	}

	cmd = fmt.Sprintf("PASS %s\r\n", password)
	_, err = conn.Write([]byte(cmd))
	if err != nil {
		return false, true
	}

	buf = make([]byte, 1024)
	n, err = conn.Read(buf)
	if err != nil {
		return false, true
	}
	response = string(buf[:n])

	if strings.HasPrefix(response, "230 ") {
		return true, true
	} else if strings.HasPrefix(response, "530 ") {
		return false, true
	} else {
		// log.Printf("Unexpected response: %s", response)
		return false, true
	}
}
