package brute

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteSNMP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	// Check if SNMPv3 is requested
	version := strings.ToLower(params["version"])
	if version == "3" || version == "v3" {
		return bruteSNMPv3(host, port, user, password, timeout, cm, params)
	}

	// v2c path (default)
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
					Timeout:   timeout / 3, // inner timeout well within outer RunWithTimeout
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

// bruteSNMPv3 handles SNMPv3 authentication with USM (User-based Security Model).
func bruteSNMPv3(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	// Pre-dial to check connectivity
	udpConn, err := cm.DialUDP("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}
	udpConn.Close()

	// Determine auth protocol
	authProto := gosnmp.MD5
	switch strings.ToUpper(params["auth"]) {
	case "SHA":
		authProto = gosnmp.SHA
	}

	// Determine privacy protocol and passphrase
	privProto := gosnmp.NoPriv
	privPass := params["privpass"]
	switch strings.ToUpper(params["priv"]) {
	case "DES":
		privProto = gosnmp.DES
	case "AES":
		privProto = gosnmp.AES
	}

	// Set message flags based on privacy
	msgFlags := gosnmp.AuthNoPriv
	if privProto != gosnmp.NoPriv && privPass != "" {
		msgFlags = gosnmp.AuthPriv
	}

	return RunWithTimeout(timeout, func(ctx context.Context) *BruteResult {
		gs := &gosnmp.GoSNMP{
			Target:        host,
			Port:          uint16(port),
			Version:       gosnmp.Version3,
			Timeout:       timeout / 2,
			SecurityModel: gosnmp.UserSecurityModel,
			MsgFlags:      msgFlags,
			SecurityParameters: &gosnmp.UsmSecurityParameters{
				UserName:                 user,
				AuthenticationProtocol:   authProto,
				AuthenticationPassphrase: password,
				PrivacyProtocol:          privProto,
				PrivacyPassphrase:        privPass,
			},
		}

		err := gs.Connect()
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}
		defer gs.Conn.Close()

		// Try to get sysDescr as auth verification
		_, err = gs.Get([]string{".1.3.6.1.2.1.1.1.0"})
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
		}

		return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
	})
}

func init() { Register("snmp", BruteSNMP) }
