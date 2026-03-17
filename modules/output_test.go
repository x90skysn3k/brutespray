package modules

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func resetGlobalStats() {
	globalStats.mutex.Lock()
	defer globalStats.mutex.Unlock()

	globalStats.StartTime = time.Now()
	globalStats.EndTime = time.Time{}
	globalStats.TotalAttempts = 0
	globalStats.SuccessfulAttempts = 0
	globalStats.FailedAttempts = 0
	globalStats.ConnectionErrors = 0
	globalStats.AuthenticationErrors = 0
	globalStats.SuccessRate = 0
	globalStats.AttemptsPerSecond = 0
	globalStats.AverageResponseTime = 0
	globalStats.PeakConcurrency = 0
	globalStats.TotalHosts = 0
	globalStats.TotalServices = 0
	globalStats.SuccessfulResults = make([]SuccessResult, 0)
	globalStats.ServiceBreakdown = make(map[string]int)
	globalStats.HostBreakdown = make(map[string]int)
	globalStats.ConnectionErrorHosts = make(map[string]int)
}

func TestRecordSuccess(t *testing.T) {
	resetGlobalStats()

	RecordSuccess("ssh", "10.0.0.1", 22, "root", "toor", 500*time.Millisecond)
	RecordSuccess("ftp", "10.0.0.2", 21, "admin", "admin", 300*time.Millisecond)

	stats := GetStats()
	if stats.SuccessfulAttempts != 2 {
		t.Fatalf("expected 2 successful attempts, got %d", stats.SuccessfulAttempts)
	}
	if len(stats.SuccessfulResults) != 2 {
		t.Fatalf("expected 2 results, got %d", len(stats.SuccessfulResults))
	}
	if stats.ServiceBreakdown["ssh"] != 1 {
		t.Fatalf("expected ssh breakdown of 1, got %d", stats.ServiceBreakdown["ssh"])
	}
	if stats.HostBreakdown["10.0.0.1"] != 1 {
		t.Fatalf("expected host breakdown of 1, got %d", stats.HostBreakdown["10.0.0.1"])
	}
}

func TestRecordAttempt(t *testing.T) {
	resetGlobalStats()

	RecordAttempt(true)
	RecordAttempt(false)
	RecordAttempt(false)

	stats := GetStats()
	if stats.TotalAttempts != 3 {
		t.Fatalf("expected 3 total attempts, got %d", stats.TotalAttempts)
	}
	if stats.FailedAttempts != 2 {
		t.Fatalf("expected 2 failed attempts, got %d", stats.FailedAttempts)
	}
}

func TestRecordError(t *testing.T) {
	resetGlobalStats()

	RecordError(true)  // connection error
	RecordError(true)  // connection error
	RecordError(false) // auth error

	stats := GetStats()
	if stats.ConnectionErrors != 2 {
		t.Fatalf("expected 2 connection errors, got %d", stats.ConnectionErrors)
	}
	if stats.AuthenticationErrors != 1 {
		t.Fatalf("expected 1 auth error, got %d", stats.AuthenticationErrors)
	}
}

func TestRecordConnectionError(t *testing.T) {
	resetGlobalStats()

	RecordConnectionError("10.0.0.1")
	RecordConnectionError("10.0.0.1")
	RecordConnectionError("10.0.0.2")

	stats := GetStats()
	if stats.ConnectionErrors != 3 {
		t.Fatalf("expected 3 connection errors, got %d", stats.ConnectionErrors)
	}
	if stats.ConnectionErrorHosts["10.0.0.1"] != 2 {
		t.Fatalf("expected 2 errors for 10.0.0.1, got %d", stats.ConnectionErrorHosts["10.0.0.1"])
	}
}

func TestCalculateFinalStats(t *testing.T) {
	resetGlobalStats()

	RecordAttempt(true)
	RecordAttempt(false)
	RecordSuccess("ssh", "10.0.0.1", 22, "root", "toor", 100*time.Millisecond)

	stats := CalculateFinalStats()
	if stats.TotalAttempts != 2 {
		t.Fatalf("expected 2 total attempts, got %d", stats.TotalAttempts)
	}
	if stats.SuccessRate == 0 {
		t.Fatal("expected non-zero success rate")
	}
	if stats.EndTime.IsZero() {
		t.Fatal("expected end time to be set")
	}
}

func TestWriteToFile(t *testing.T) {
	dir := t.TempDir()
	content := "[ssh] 10.0.0.1:22 - User 'root' - Pass 'toor' - SUCCESS\n"

	err := WriteToFile("ssh", content, 22, dir)
	if err != nil {
		t.Fatalf("WriteToFile failed: %v", err)
	}

	// Verify file exists and has correct content
	filename := filepath.Join(dir, "22-ssh-success.txt")
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if string(data) != content {
		t.Fatalf("file content mismatch: got %q, want %q", string(data), content)
	}

	// Write again to verify append
	err = WriteToFile("ssh", content, 22, dir)
	if err != nil {
		t.Fatalf("second WriteToFile failed: %v", err)
	}
	data, err = os.ReadFile(filename)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if string(data) != content+content {
		t.Fatalf("expected appended content, got %q", string(data))
	}
}

func TestGetStatsCopiesData(t *testing.T) {
	resetGlobalStats()
	RecordSuccess("ssh", "10.0.0.1", 22, "root", "toor", 100*time.Millisecond)

	stats := GetStats()
	// Mutating the copy should not affect the global state
	stats.SuccessfulResults = append(stats.SuccessfulResults, SuccessResult{Service: "fake"})
	stats.ServiceBreakdown["fake"] = 99

	original := GetStats()
	if len(original.SuccessfulResults) != 1 {
		t.Fatal("global stats should not have been modified")
	}
	if original.ServiceBreakdown["fake"] != 0 {
		t.Fatal("global stats should not have been modified")
	}
}

func TestPrintResultJSON(t *testing.T) {
	resetGlobalStats()

	// Save and restore global state
	origFormat := OutputFormatMode
	origSilent := Silent
	origTUI := TUIMode
	origNoColor := NoColorMode
	defer func() {
		OutputFormatMode = origFormat
		Silent = origSilent
		TUIMode = origTUI
		NoColorMode = origNoColor
	}()

	OutputFormatMode = "json"
	Silent = false
	TUIMode = false
	NoColorMode = true

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	dir := t.TempDir()
	PrintResult("ssh", "10.0.0.1", 22, "root", "toor", true, true, false, dir, 0, "OpenSSH_8.9")

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := strings.TrimSpace(buf.String())

	if output == "" {
		t.Fatal("expected JSON output, got empty string")
	}

	var attempt AttemptResult
	if err := json.Unmarshal([]byte(output), &attempt); err != nil {
		t.Fatalf("invalid JSON output: %v\nraw: %s", err, output)
	}

	if attempt.Service != "ssh" {
		t.Errorf("expected service ssh, got %s", attempt.Service)
	}
	if attempt.Host != "10.0.0.1" {
		t.Errorf("expected host 10.0.0.1, got %s", attempt.Host)
	}
	if attempt.Port != 22 {
		t.Errorf("expected port 22, got %d", attempt.Port)
	}
	if !attempt.Success {
		t.Error("expected success=true")
	}
	if !attempt.Connected {
		t.Error("expected connected=true")
	}
	if attempt.Banner != "OpenSSH_8.9" {
		t.Errorf("expected banner OpenSSH_8.9, got %s", attempt.Banner)
	}
	if attempt.Status != "SUCCESS" {
		t.Errorf("expected status SUCCESS, got %s", attempt.Status)
	}
	if attempt.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
}

func TestPrintComprehensiveSummary(t *testing.T) {
	resetGlobalStats()

	RecordSuccess("ssh", "10.0.0.1", 22, "root", "toor", 100*time.Millisecond)
	SetTotalHostsAndServices(1, 1)

	dir := t.TempDir()
	PrintComprehensiveSummary(dir)

	// Check that all expected files were created
	expectedFiles := []string{
		"brutespray-summary.json",
		"brutespray-summary.csv",
		"brutespray-summary.txt",
		"brutespray-msf.rc",
		"brutespray-nxc.sh",
	}

	for _, f := range expectedFiles {
		path := filepath.Join(dir, f)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("expected file %s to exist", f)
		}
	}

	// Verify MSF script contains the module
	msfData, _ := os.ReadFile(filepath.Join(dir, "brutespray-msf.rc"))
	if !strings.Contains(string(msfData), "ssh_login") {
		t.Error("MSF script should contain ssh_login module")
	}
	if !strings.Contains(string(msfData), "set RHOSTS 10.0.0.1") {
		t.Error("MSF script should contain the host")
	}

	// Verify NXC script contains the command
	nxcData, _ := os.ReadFile(filepath.Join(dir, "brutespray-nxc.sh"))
	if !strings.Contains(string(nxcData), "nxc ssh 10.0.0.1") {
		t.Error("NXC script should contain ssh command")
	}
}
