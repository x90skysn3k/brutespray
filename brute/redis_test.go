package brute

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func startMockRedisServer(t *testing.T, validPass string) (int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock Redis server: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleRedisConn(conn, validPass)
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	return port, func() { listener.Close() }
}

func handleRedisConn(conn net.Conn, validPass string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	r := bufio.NewReader(conn)
	authenticated := false

	for {
		// Read RESP command
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)

		// RESP array: *N\r\n
		if !strings.HasPrefix(line, "*") {
			continue
		}

		// Read the array elements
		var args []string
		numStr := strings.TrimPrefix(line, "*")
		var num int
		_, _ = fmt.Sscanf(numStr, "%d", &num)

		for i := 0; i < num; i++ {
			// $N\r\n (bulk string length)
			lenLine, err := r.ReadString('\n')
			if err != nil {
				return
			}
			lenLine = strings.TrimSpace(lenLine)
			if !strings.HasPrefix(lenLine, "$") {
				continue
			}
			var strLen int
			_, _ = fmt.Sscanf(strings.TrimPrefix(lenLine, "$"), "%d", &strLen)

			// Read the string data
			data := make([]byte, strLen+2) // +2 for \r\n
			_, err = r.Read(data)
			if err != nil {
				return
			}
			args = append(args, strings.TrimSpace(string(data)))
		}

		if len(args) == 0 {
			continue
		}

		cmd := strings.ToUpper(args[0])
		switch cmd {
		case "AUTH":
			if len(args) >= 2 && args[len(args)-1] == validPass {
				authenticated = true
				fmt.Fprintf(conn, "+OK\r\n")
			} else {
				fmt.Fprintf(conn, "-WRONGPASS invalid username-password pair or user is disabled\r\n")
			}

		case "SELECT":
			if authenticated || validPass == "" {
				fmt.Fprintf(conn, "+OK\r\n")
			} else {
				fmt.Fprintf(conn, "-NOAUTH Authentication required\r\n")
			}

		case "PING":
			if authenticated || validPass == "" {
				fmt.Fprintf(conn, "+PONG\r\n")
			} else {
				fmt.Fprintf(conn, "-NOAUTH Authentication required\r\n")
			}

		case "CLIENT":
			fmt.Fprintf(conn, "+OK\r\n")

		default:
			fmt.Fprintf(conn, "-ERR unknown command\r\n")
		}
	}
}

func TestBruteRedisSuccess(t *testing.T) {
	port, cleanup := startMockRedisServer(t, "redis123")
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteRedis("127.0.0.1", port, "", "redis123", 5*time.Second, cm, ModuleParams{})
	if !result.AuthSuccess {
		t.Fatalf("expected auth success, got error: %v", result.Error)
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success")
	}
}

func TestBruteRedisWrongPass(t *testing.T) {
	port, cleanup := startMockRedisServer(t, "redis123")
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteRedis("127.0.0.1", port, "", "wrongpass", 5*time.Second, cm, ModuleParams{})
	if result.AuthSuccess {
		t.Fatal("expected auth failure")
	}
	if !result.ConnectionSuccess {
		t.Fatal("expected connection success (WRONGPASS is auth failure, not connection)")
	}
}

func TestBruteRedisWithDB(t *testing.T) {
	port, cleanup := startMockRedisServer(t, "redis123")
	defer cleanup()

	cm, _ := modules.NewConnectionManager("", 5*time.Second, "")

	result := BruteRedis("127.0.0.1", port, "", "redis123", 5*time.Second, cm, ModuleParams{"db": "2"})
	if !result.AuthSuccess {
		t.Fatalf("expected auth success with db param, got error: %v", result.Error)
	}
}
