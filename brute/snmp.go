package brute

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteSNMP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	hasher := md5.New()
	hasher.Write([]byte(password))
	md5Password := hex.EncodeToString(hasher.Sum(nil))

	communityStrings := []string{user, md5Password}

	// Pre-dial to check connectivity (UDP proxy not supported)
	udpConn, err := cm.DialUDP("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}
	udpConn.Close()

	return RunWithTimeout(timeout, func(ctx context.Context) *BruteResult {
		type result struct {
			success bool
		}
		done := make(chan result, len(communityStrings))

		for _, communityString := range communityStrings {
			go func(cs string) {
				gs := &gosnmp.GoSNMP{
					Target:    host,
					Port:      uint16(port),
					Community: cs,
					Version:   gosnmp.Version2c,
					Timeout:   timeout / 2, // inner timeout shorter than outer
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

		received := 0
		for received < len(communityStrings) {
			select {
			case <-ctx.Done():
				return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: ctx.Err()}
			case r := <-done:
				received++
				if r.success {
					return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
				}
			}
		}

		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
	})
}

func init() { Register("snmp", BruteSNMP) }
