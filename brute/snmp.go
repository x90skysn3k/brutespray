package brute

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"sync"
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
	}
	done := make(chan result, len(communityStrings))

	// Pre-dial to check connectivity (UDP proxy not supported)
	udpConn, err := cm.DialUDP("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false, false
	}
	udpConn.Close()

	// Use a WaitGroup to ensure all goroutines complete before we return,
	// preventing goroutine leaks on timeout.
	var wg sync.WaitGroup

	for _, communityString := range communityStrings {
		wg.Add(1)
		go func(cs string) {
			defer wg.Done()

			gs := &gosnmp.GoSNMP{
				Target:    host,
				Port:      uint16(port),
				Community: cs,
				Version:   gosnmp.Version2c,
				Timeout:   timeout,
			}

			err := gs.Connect()
			if err != nil {
				done <- result{false}
				return
			}
			defer gs.Conn.Close()

			_, err = gs.Get([]string{".1.3.6.1.2.1.1.1.0"}) // sysDescr
			done <- result{err == nil}
		}(communityString)
	}

	// Wait for goroutines to finish in a separate goroutine so we can
	// select on the timer as well.
	allDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(allDone)
	}()

	received := 0
	for received < len(communityStrings) {
		select {
		case <-timer.C:
			// Timeout — wait briefly for any stragglers, then return.
			// The goroutines will still finish (SNMP has its own timeout),
			// but we don't block the caller.
			select {
			case r := <-done:
				if r.success {
					return true, true
				}
			default:
			}
			return false, false
		case r := <-done:
			received++
			if r.success {
				return true, true
			}
		case <-allDone:
			// All goroutines finished without success
			return false, true
		}
	}

	return false, true
}

func init() { Register("snmp", BruteSNMP) }
