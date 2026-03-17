package brute

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteSMB(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	type result struct {
		session *smb2.Session
		conn    net.Conn
		err     error
	}
	done := make(chan result, 1)

	go func() {
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			done <- result{nil, conn, err}
			return
		}

		initiator := &smb2.NTLMInitiator{
			User:     user,
			Password: password,
			Domain:   params["domain"],
		}

		// Pass-the-hash: if params["pass"] == "HASH", treat password as NTLM hash
		if strings.EqualFold(params["pass"], "HASH") {
			hashBytes, err := hex.DecodeString(password)
			if err == nil && len(hashBytes) == 16 {
				initiator.Password = ""
				initiator.Hash = hashBytes
			}
		}

		d := &smb2.Dialer{
			Initiator: initiator,
		}

		session, err := d.Dial(conn)
		done <- result{session, conn, err}
	}()

	handleResult := func(r result) *BruteResult {
		if r.err != nil {
			if r.conn != nil {
				r.conn.Close()
			}
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: r.err}
		}

		// Auth succeeded — list shares to verify
		_, err := r.session.ListSharenames()
		if err != nil {
			_ = r.session.Logoff()
			r.conn.Close()
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
		}

		// Check ADMIN$ access for privilege detection
		banner := ""
		adminShare, adminErr := r.session.Mount(`\\` + host + `\ADMIN$`)
		if adminErr == nil {
			banner = "ADMIN$ Access Allowed (Admin)"
			_ = adminShare.Umount()
		} else {
			banner = "ADMIN$ Access Denied (User)"
		}

		_ = r.session.Logoff()
		r.conn.Close()
		return &BruteResult{AuthSuccess: true, ConnectionSuccess: true, Banner: banner}
	}

	select {
	case <-timer.C:
		_ = conn.SetDeadline(time.Now())
		select {
		case r := <-done:
			return handleResult(r)
		default:
			conn.Close()
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false}
		}
	case r := <-done:
		return handleResult(r)
	}
}

func init() { Register("smbnt", BruteSMB) }
