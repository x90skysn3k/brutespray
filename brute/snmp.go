package brute

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/x90skysn3k/brutespray/modules"
)

func BruteSNMP(host string, port int, user, password string, timeout time.Duration, socks5 string, netInterface string) (bool, bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	hasher := md5.New()
	hasher.Write([]byte(password))
	md5Password := hex.EncodeToString(hasher.Sum(nil))

	communityStrings := []string{user, md5Password}

	type result struct {
		success bool
		err     error
	}
	done := make(chan result)

	cm, err := modules.NewConnectionManager(socks5, timeout, netInterface)
	if err != nil {
		return false, false
	}

	portInt64 := int64(gosnmp.NewHandler().Port())

	for _, communityString := range communityStrings {
		go func(communityString string) {
			udpConn, err := cm.DialUDP("udp", fmt.Sprintf("%s:%d", host, port))
			if err != nil {
				done <- result{false, err}
				return
			}
			defer udpConn.Close()

			gosnmp.Default.Target = host
			gosnmp.Default.Port = uint16(portInt64)
			gosnmp.Default.Community = communityString
			gosnmp.Default.Version = gosnmp.Version3
			gosnmp.Default.Timeout = timeout
			err = gosnmp.Default.Connect()
			if err != nil {
				done <- result{false, err}
				return
			}
			defer gosnmp.Default.Conn.Close()

			done <- result{true, nil}
		}(communityString)
	}

	select {
	case <-timer.C:
		return false, false
	case result := <-done:
		if result.err != nil {
			//fmt.Println("Error:", result.err)
			return false, true
		}
		if result.success {
			return true, true
		}
	}

	return false, false
}
