package brutespray

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/brute"
	"github.com/x90skysn3k/brutespray/v2/modules"
	"github.com/x90skysn3k/brutespray/v2/tui"
)

type captureDispatchEventSink struct {
	mu       sync.Mutex
	attempts []tui.AttemptResultMsg
}

func (s *captureDispatchEventSink) Send(msg interface{}) {
	attempt, ok := msg.(tui.AttemptResultMsg)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts = append(s.attempts, attempt)
}

func (s *captureDispatchEventSink) Close() {}

func (s *captureDispatchEventSink) attemptResults() []tui.AttemptResultMsg {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]tui.AttemptResultMsg(nil), s.attempts...)
}

func TestProcessHostQueuesRedisPasswordWithoutUsers(t *testing.T) {
	if os.Getenv("BRUTESPRAY_REDIS_PROCESS_HOST_HELPER") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestProcessHostQueuesRedisPasswordWithoutUsers$", "-test.v")
		cmd.Env = append(os.Environ(), "BRUTESPRAY_REDIS_PROCESS_HOST_HELPER=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("redis ProcessHost helper failed: %v\n%s", err, out)
		}
		return
	}
	originalRedis, ok := brute.Lookup("redis")
	if !ok {
		t.Fatal("redis brute function is not registered")
	}
	defer brute.Register("redis", originalRedis)
	defer brute.GetCircuitBreaker().Reset("127.0.0.1:1")

	brute.Register("redis", func(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params brute.ModuleParams) *brute.BruteResult {
		return &brute.BruteResult{ConnectionSuccess: true}
	})

	cm, err := modules.NewConnectionManager("", time.Millisecond)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}

	const wantPassword = "redis-secret"
	sink := &captureDispatchEventSink{}
	workerPool := NewWorkerPool(1, sink, 1, 1)
	workerPool.noStats = true
	host := modules.Host{Service: "redis", Host: "127.0.0.1", Port: 1}

	workerPool.ProcessHost(host, "redis", "", "", wantPassword, version, time.Millisecond, 1, t.TempDir(), cm, "", brute.ModuleParams{}, false)

	attempts := sink.attemptResults()
	if len(attempts) != 1 {
		t.Fatalf("captured redis attempts = %d, want 1", len(attempts))
	}
	if attempts[0].User != "" {
		t.Fatalf("redis attempt user = %q, want empty", attempts[0].User)
	}
	if attempts[0].Password != wantPassword {
		t.Fatalf("redis attempt password = %q, want %q", attempts[0].Password, wantPassword)
	}
}

func TestProcessHostQueuesRedisInlinePasswordBeforeExplicitPassword(t *testing.T) {
	if os.Getenv("BRUTESPRAY_REDIS_INLINE_PROCESS_HOST_HELPER") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestProcessHostQueuesRedisInlinePasswordBeforeExplicitPassword$", "-test.v")
		cmd.Env = append(os.Environ(), "BRUTESPRAY_REDIS_INLINE_PROCESS_HOST_HELPER=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("redis inline ProcessHost helper failed: %v\n%s", err, out)
		}
		return
	}
	originalRedis, ok := brute.Lookup("redis")
	if !ok {
		t.Fatal("redis brute function is not registered")
	}
	defer brute.Register("redis", originalRedis)
	defer brute.GetCircuitBreaker().Reset("127.0.0.1:1")

	brute.Register("redis", func(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params brute.ModuleParams) *brute.BruteResult {
		return &brute.BruteResult{ConnectionSuccess: true}
	})

	cm, err := modules.NewConnectionManager("", time.Millisecond)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}

	sink := &captureDispatchEventSink{}
	workerPool := NewWorkerPool(1, sink, 1, 1)
	workerPool.noStats = true
	workerPool.inlineCreds = "ignored:redis-inline-secret"
	host := modules.Host{Service: "redis", Host: "127.0.0.1", Port: 1}

	workerPool.ProcessHost(host, "redis", "", "", "base-secret", version, time.Millisecond, 1, t.TempDir(), cm, "", brute.ModuleParams{}, false)

	attempts := sink.attemptResults()
	if len(attempts) != 2 {
		t.Fatalf("captured redis attempts = %d, want 2: %+v", len(attempts), attempts)
	}
	wantPasswords := []string{"redis-inline-secret", "base-secret"}
	for i, wantPassword := range wantPasswords {
		if attempts[i].User != "" {
			t.Fatalf("attempt %d user = %q, want empty", i, attempts[i].User)
		}
		if attempts[i].Password != wantPassword {
			t.Fatalf("attempt %d password = %q, want %q", i, attempts[i].Password, wantPassword)
		}
	}
}

func TestProcessHostQueuesInfluxDBV2TokenOnce(t *testing.T) {
	if os.Getenv("BRUTESPRAY_INFLUX_TOKEN_PROCESS_HOST_HELPER") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestProcessHostQueuesInfluxDBV2TokenOnce$", "-test.v")
		cmd.Env = append(os.Environ(), "BRUTESPRAY_INFLUX_TOKEN_PROCESS_HOST_HELPER=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("influx token ProcessHost helper failed: %v\n%s", err, out)
		}
		return
	}
	originalInflux, ok := brute.Lookup("influxdb")
	if !ok {
		t.Fatal("influxdb brute function is not registered")
	}
	defer brute.Register("influxdb", originalInflux)
	defer brute.GetCircuitBreaker().Reset("127.0.0.1:1")

	brute.Register("influxdb", func(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params brute.ModuleParams) *brute.BruteResult {
		return &brute.BruteResult{ConnectionSuccess: true}
	})

	cm, err := modules.NewConnectionManager("", time.Millisecond)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}
	users := filepath.Join(t.TempDir(), "users.txt")
	if err := os.WriteFile(users, []byte("admin\noperator\n"), 0o600); err != nil {
		t.Fatalf("write users: %v", err)
	}

	const wantToken = "influx-token"
	sink := &captureDispatchEventSink{}
	workerPool := NewWorkerPool(1, sink, 1, 1)
	workerPool.noStats = true
	host := modules.Host{Service: "influxdb", Host: "127.0.0.1", Port: 1}

	workerPool.ProcessHost(host, "influxdb", "", users, wantToken, version, time.Millisecond, 1, t.TempDir(), cm, "", brute.ModuleParams{"mode": "v2"}, false)

	attempts := sink.attemptResults()
	if len(attempts) != 1 {
		t.Fatalf("captured influxdb attempts = %d, want 1", len(attempts))
	}
	if attempts[0].User != "" {
		t.Fatalf("influxdb token attempt user = %q, want empty", attempts[0].User)
	}
	if attempts[0].Password != wantToken {
		t.Fatalf("influxdb token attempt password = %q, want %q", attempts[0].Password, wantToken)
	}
}
