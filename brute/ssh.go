package brute

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/x90skysn3k/brutespray/v2/brute/badkeys"
	"github.com/x90skysn3k/brutespray/v2/modules"
	"golang.org/x/crypto/ssh"
)

// BadKeyAttempt is one user+key pair to try during the bad-keys pass.
type BadKeyAttempt struct {
	Username string
	Entry    badkeys.Entry
}

// PlanBadKeyAttempts produces the ordered list of SSH bad-key attempts for a
// host. When userOverride is non-empty (operator passed -u explicitly), every
// attempt uses that username; otherwise the entry's metadata-suggested user
// is used (root for F5, vagrant for Vagrant, etc.).
func PlanBadKeyAttempts(bundle []badkeys.Entry, userOverride string) []BadKeyAttempt {
	out := make([]BadKeyAttempt, 0, len(bundle))
	for _, e := range bundle {
		u := e.Username
		if userOverride != "" {
			u = userOverride
		}
		out = append(out, BadKeyAttempt{Username: u, Entry: e})
	}
	return out
}

// badKeyMarker is the synthetic password prefix used by the dispatcher to
// signal a bad-keys bundle attempt. The dispatcher emits passwords of the form
// "::badkey::<index>" before the user's actual password list, and BruteSSH
// dispatches them to attemptBadKey. INTERNAL — not part of any public contract.
const badKeyMarker = "::badkey::"

// sshKeyCache caches key file contents to avoid re-reading on every attempt.
var sshKeyCache sync.Map

func BruteSSH(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	// Bad-keys pre-pass: when the magic password marker "::badkey::" is in play,
	// the caller is asking us to attempt a single embedded bad-key. The dispatcher
	// (Task A4) emits these as synthetic credential pairs before regular passwords.
	if idxStr, ok := strings.CutPrefix(password, badKeyMarker); ok {
		idx, err := strconv.Atoi(idxStr)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false,
				Error: fmt.Errorf("invalid badkey index: %w", err)}
		}
		bundle, err := badkeys.Load()
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false,
				Error: fmt.Errorf("loading badkeys bundle: %w", err)}
		}
		if idx < 0 || idx >= len(bundle) {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false,
				Error: fmt.Errorf("badkey index out of range: %d", idx)}
		}
		return attemptBadKey(host, port, user, bundle[idx], timeout, cm)
	}

	var authMethod ssh.AuthMethod

	keyParam := params["key"]
	if keyParam != "" && keyParam != "false" {
		// Key auth mode. Two sub-modes:
		//   -m key:/path/to/key  — fixed key, brute-force the passphrase via -p
		//   -m key:true          — each -p entry is a key file path (no passphrase)
		var keyPath string
		var passphrase string

		if keyParam == "true" {
			// Each password entry is a key file path
			keyPath = password
			passphrase = ""
		} else {
			// Fixed key file; passwords are passphrases
			keyPath = keyParam
			passphrase = password
		}

		// Cache key file contents
		var keyData []byte
		if cached, ok := sshKeyCache.Load(keyPath); ok {
			keyData = cached.([]byte)
		} else {
			data, err := os.ReadFile(keyPath)
			if err != nil {
				return &BruteResult{AuthSuccess: false, ConnectionSuccess: true,
					Error: fmt.Errorf("reading SSH key %s: %w", keyPath, err)}
			}
			keyData = data
			sshKeyCache.Store(keyPath, data)
		}

		var signer ssh.Signer
		var err error
		if passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, []byte(passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(keyData)
		}
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true,
				Error: fmt.Errorf("parsing SSH key: %w", err)}
		}
		authMethod = ssh.PublicKeys(signer)
	} else {
		// Determine auth method from params
		requestedAuth := strings.ToLower(params["auth"])

		switch requestedAuth {
		case "keyboard-interactive":
			// Force keyboard-interactive only
			authMethod = ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					answers[i] = password
				}
				return answers, nil
			})
		default:
			authMethod = ssh.Password(password)
		}
	}

	// Build auth methods list with automatic keyboard-interactive fallback
	authMethods := []ssh.AuthMethod{authMethod}
	if strings.ToLower(params["auth"]) != "keyboard-interactive" && keyParam == "" {
		// Add keyboard-interactive as fallback for password auth
		authMethods = append(authMethods, ssh.KeyboardInteractive(func(u, instruction string, questions []string, echos []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range questions {
				answers[i] = password
			}
			return answers, nil
		}))
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		client *ssh.Client
		err    error
		banner string
	}
	done := make(chan result, 1)

	var err error
	var conn net.Conn

	conn, err = cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	go func() {
		clientConn, clientChannels, clientRequests, err := ssh.NewClientConn(conn, fmt.Sprintf("%s:%d", host, port), config)
		if err != nil {
			done <- result{nil, err, ""}
			return
		}
		banner := string(clientConn.ServerVersion())
		client := ssh.NewClient(clientConn, clientChannels, clientRequests)
		done <- result{client, nil, banner}
	}()

	select {
	case <-timer.C:
		_ = conn.SetDeadline(time.Now())
		select {
		case result := <-done:
			conn.Close()
			if result.err != nil {
				return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: result.err, Banner: result.banner}
			}
			result.client.Close()
			return &BruteResult{AuthSuccess: true, ConnectionSuccess: true, Banner: result.banner}
		default:
			conn.Close()
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: fmt.Errorf("timeout")}
		}
	case result := <-done:
		conn.Close()
		if result.err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: result.err, Banner: result.banner}
		}
		result.client.Close()
		return &BruteResult{AuthSuccess: true, ConnectionSuccess: true, Banner: result.banner}
	}
}

func attemptBadKey(host string, port int, user string, e badkeys.Entry,
	timeout time.Duration, cm *modules.ConnectionManager) *BruteResult {
	// Fix 2: PEM parsing happens before any network I/O; a parse failure must
	// not set ConnectionSuccess=true (no network was touched, circuit-breaker
	// must not be credited with a success counter).
	signer, err := ssh.ParsePrivateKey(e.PEM)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false,
			Error: fmt.Errorf("parsing badkey %s: %w", e.File, err)}
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	conn, err := cm.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}
	// Fix 1: ssh.ClientConfig.Timeout is only honoured by ssh.Dial, not by
	// ssh.NewClientConn. Set a deadline on the raw connection so a slow
	// responder cannot stall this worker goroutine for the OS socket timeout.
	_ = conn.SetDeadline(time.Now().Add(timeout))
	c, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(host, strconv.Itoa(port)), cfg)
	if err != nil {
		conn.Close()
		if strings.Contains(err.Error(), "unable to authenticate") {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
		}
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()
	// Fix 3: capture server banner (high-value for a bad-key hit).
	return &BruteResult{
		AuthSuccess:       true,
		ConnectionSuccess: true,
		Banner:            string(c.ServerVersion()),
		KeyMatch: &KeyMatch{
			Fingerprint: e.PEMHash,
			Vendor:      e.Vendor,
			CVE:         e.CVE,
			Description: e.Description,
		},
	}
}

func init() { Register("ssh", BruteSSH) }
