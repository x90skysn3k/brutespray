package modules

import "testing"

func TestStoreRecordsRunTargetAttemptFinding(t *testing.T) {
	store, err := NewJSONStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewJSONStore: %v", err)
	}
	runID, err := store.CreateRun(StoreRun{EngagementID: "acme", PlanHash: "abc"})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if err := store.RecordTarget(runID, StoreTarget{Service: "ssh", Host: "10.0.0.1", Port: 22}); err != nil {
		t.Fatalf("RecordTarget: %v", err)
	}
	if err := store.RecordAttempt(runID, StoreAttempt{Service: "ssh", Host: "10.0.0.1", Port: 22, User: "root", Success: false}); err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}
	if err := store.RecordFinding(runID, StoreFinding{Service: "redis", Target: "10.0.0.2:6379", Code: "redis-no-auth"}); err != nil {
		t.Fatalf("RecordFinding: %v", err)
	}
	snapshot, err := store.LoadRun(runID)
	if err != nil {
		t.Fatalf("LoadRun: %v", err)
	}
	if snapshot.Run.EngagementID != "acme" || len(snapshot.Targets) != 1 || len(snapshot.Attempts) != 1 || len(snapshot.Findings) != 1 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestJSONStoreRejectsPathTraversalRunID(t *testing.T) {
	store, err := NewJSONStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewJSONStore: %v", err)
	}
	if _, err := store.CreateRun(StoreRun{ID: "../outside"}); err == nil {
		t.Fatal("expected traversal run id to fail")
	}
	if err := store.RecordTarget("../outside", StoreTarget{Service: "ssh"}); err == nil {
		t.Fatal("expected traversal record to fail")
	}
}
