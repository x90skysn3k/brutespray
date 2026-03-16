package modules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsPwDumpFile(t *testing.T) {
	dir := t.TempDir()

	t.Run("valid pwdump", func(t *testing.T) {
		path := filepath.Join(dir, "pwdump.txt")
		content := "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\nGuest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
		os.WriteFile(path, []byte(content), 0644)

		if !IsPwDumpFile(path) {
			t.Fatal("expected PwDump format detection")
		}
	})

	t.Run("not pwdump", func(t *testing.T) {
		path := filepath.Join(dir, "passwords.txt")
		content := "password123\nadmin\nroot\n"
		os.WriteFile(path, []byte(content), 0644)

		if IsPwDumpFile(path) {
			t.Fatal("should not detect regular password file as PwDump")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		if IsPwDumpFile("/nonexistent/file") {
			t.Fatal("should return false for nonexistent file")
		}
	})
}

func TestReadPwDumpFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pwdump.txt")
	content := "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\nGuest:501:aad3b435b51404eeaad3b435b51404ee:c23413a8a1e7665faad3b435b51404ee:::\n"
	os.WriteFile(path, []byte(content), 0644)

	users, hashes, err := ReadPwDumpFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
	if users[0] != "Administrator" {
		t.Errorf("expected Administrator, got %s", users[0])
	}
	if users[1] != "Guest" {
		t.Errorf("expected Guest, got %s", users[1])
	}

	if len(hashes) != 2 {
		t.Fatalf("expected 2 hashes, got %d", len(hashes))
	}
	if hashes[0] != "31d6cfe0d16ae931b73c59d7e0c089c0" {
		t.Errorf("unexpected NTLM hash: %s", hashes[0])
	}
	if hashes[1] != "c23413a8a1e7665faad3b435b51404ee" {
		t.Errorf("unexpected NTLM hash: %s", hashes[1])
	}
}

func TestReadPwDumpFileSkipsInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mixed.txt")
	content := "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\ninvalid line\n"
	os.WriteFile(path, []byte(content), 0644)

	users, hashes, err := ReadPwDumpFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(users) != 1 {
		t.Fatalf("expected 1 valid user, got %d", len(users))
	}
	if len(hashes) != 1 {
		t.Fatalf("expected 1 valid hash, got %d", len(hashes))
	}
}
