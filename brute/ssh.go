package brute

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
	"golang.org/x/crypto/ssh"
)

// sshKeyCache caches key file contents to avoid re-reading on every attempt.
var sshKeyCache sync.Map

func BruteSSH(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
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

func init() { Register("ssh", BruteSSH) }
