package brutespray

import (
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/brute"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

func TestProcessHostCredentialOrderWithExtrasAndResume(t *testing.T) {
	const service = "consumer-order"
	brute.Register(service, func(_ string, _ int, _, _ string, _ time.Duration, _ *modules.ConnectionManager, _ brute.ModuleParams) *brute.BruteResult {
		return &brute.BruteResult{ConnectionSuccess: true}
	})
	users := writeWordlist(t, "alice", "bob", "carol")
	passwords := writeWordlist(t, "p1", "p2")
	cm, err := modules.NewConnectionManager("", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mode   string
		spray  bool
		resume int
		want   []credentialPair
	}{
		{"host-major", "host-major", false, 0, []credentialPair{{"inline", "secret"}, {"alice", "alice"}, {"alice", "ecila"}, {"alice", "p1"}, {"alice", "p2"}, {"bob", "bob"}, {"bob", "p1"}, {"bob", "p2"}, {"carol", "carol"}, {"carol", "lorac"}, {"carol", "p1"}, {"carol", "p2"}}},
		{"spray", "spray", false, 0, []credentialPair{{"inline", "secret"}, {"alice", "alice"}, {"bob", "bob"}, {"carol", "carol"}, {"alice", "ecila"}, {"carol", "lorac"}, {"alice", "p1"}, {"bob", "p1"}, {"carol", "p1"}, {"alice", "p2"}, {"bob", "p2"}, {"carol", "p2"}}},
		{"auto-spray", "auto", true, 0, []credentialPair{{"inline", "secret"}, {"alice", "alice"}, {"bob", "bob"}, {"carol", "carol"}, {"alice", "ecila"}, {"carol", "lorac"}, {"alice", "p1"}, {"bob", "p1"}, {"carol", "p1"}, {"alice", "p2"}, {"bob", "p2"}, {"carol", "p2"}}},
		{"pairwise", "pairwise", false, 0, []credentialPair{{"inline", "secret"}, {"alice", "alice"}, {"alice", "ecila"}, {"bob", "bob"}, {"carol", "carol"}, {"carol", "lorac"}, {"alice", "p1"}, {"bob", "p2"}}},
		{"resume-host-major", "host-major", false, 3, []credentialPair{{"alice", "p1"}, {"alice", "p2"}, {"bob", "bob"}, {"bob", "p1"}, {"bob", "p2"}, {"carol", "carol"}, {"carol", "lorac"}, {"carol", "p1"}, {"carol", "p2"}}},
		{"resume-pairwise", "pairwise", false, 6, []credentialPair{{"alice", "p1"}, {"bob", "p2"}}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host := modules.Host{Host: "127.0.0.1", Port: 45910 + i, Service: service}
			sink := &captureDispatchEventSink{}
			wp := NewWorkerPool(1, sink, 1, 1)
			wp.noStats = true
			wp.scheduleMode, wp.sprayMode = tc.mode, tc.spray
			wp.useReversedPass = true
			wp.inlineCreds = "inline:secret"
			wp.checkpoint = modules.NewCheckpoint("")
			for range tc.resume {
				wp.checkpoint.RecordAttemptForHost(host.Host, host.Port, service)
			}
			wp.ProcessHost(host, service, "", users, passwords, version, 2*time.Second, 1, t.TempDir(), cm, "", nil, true)
			wp.Stop()
			var got []credentialPair
			for _, attempt := range sink.attemptResults() {
				got = append(got, credentialPair{attempt.User, attempt.Password})
			}
			assertCredentialPairs(t, got, tc.want)
			if got := wp.checkpoint.GetAttemptedCount(host.Host, host.Port, service); got != tc.resume+len(tc.want) {
				t.Fatalf("checkpoint attempted count = %d, want %d", got, tc.resume+len(tc.want))
			}
		})
	}
}

func TestProcessHostWordlistFailureDoesNotCompleteHost(t *testing.T) {
	const service = "consumer-load-failure"
	host := modules.Host{Host: "127.0.0.1", Port: 45920, Service: service}
	cm, err := modules.NewConnectionManager("", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	sink := &captureDispatchEventSink{}
	wp := NewWorkerPool(2, sink, 1, 1)
	wp.noStats = true
	wp.checkpoint = modules.NewCheckpoint("")
	// A directory exists but cannot be scanned as a wordlist.
	wp.ProcessHost(host, service, "", t.TempDir(), "p", version, 2*time.Second, 1, t.TempDir(), cm, "", nil, false)
	wp.Stop()
	if _, completed := sink.lifecycle(); completed != 0 {
		t.Fatalf("load failure emitted %d completed hosts", completed)
	}
	if wp.checkpoint.IsHostCompleted(host.Host, host.Port, service) {
		t.Fatal("wordlist load failure marked target complete")
	}
}
