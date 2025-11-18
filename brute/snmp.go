package brute

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/x90skysn3k/brutespray/modules"
)

func BruteSNMP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
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

	// Create a handler just to get the default port if needed, but we have port.

	for _, communityString := range communityStrings {
		go func(communityString string) {

			gs := &gosnmp.GoSNMP{
				Target:    host,
				Port:      uint16(port),
				Community: communityString,
				Version:   gosnmp.Version2c, // Usually v1 or v2c for brute forcing community strings
				Timeout:   timeout,
			}

			// Pre-dial to check connectivity/proxy (UDP proxy not supported usually but cm handles it)
			conn, err := cm.DialUDP("udp", fmt.Sprintf("%s:%d", host, port))
			if err != nil {
				done <- result{false, err}
				return
			}

			conn.Close() // Close our check connection

			err = gs.Connect()
			if err != nil {
				done <- result{false, err}
				return
			}
			defer gs.Conn.Close()

			// Try a get to verify community string
			_, err = gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // sysDescr
			if err == nil {
				done <- result{true, nil}
			} else {
				done <- result{false, err}
			}
		}(communityString)
	}

	select {
	case <-timer.C:
		return false, false
	case result := <-done:
		if result.err != nil {
			return false, true
		}
		if result.success {
			return true, true
		}
	}

	return false, false
}
