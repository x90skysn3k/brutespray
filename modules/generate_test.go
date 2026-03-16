package modules

import (
	"testing"
)

func TestParsePasswordGenerator(t *testing.T) {
	tests := []struct {
		spec    string
		wantErr bool
		minLen  int
		maxLen  int
		count   int
	}{
		{"4:4:1", false, 4, 4, 10000},          // 10^4 = 10000 4-digit PINs
		{"1:2:1", false, 1, 2, 110},             // 10 + 100
		{"1:1:a", false, 1, 1, 26},              // 26 lowercase letters
		{"1:1:A", false, 1, 1, 26},              // 26 uppercase letters
		{"2:2:aA", false, 2, 2, 52 * 52},        // (26+26)^2
		{"1:3:1", false, 1, 3, 10 + 100 + 1000}, // 10 + 100 + 1000
		// Error cases
		{"", true, 0, 0, 0},
		{"4:4", true, 0, 0, 0},
		{"a:4:1", true, 0, 0, 0},
		{"4:a:1", true, 0, 0, 0},
		{"0:4:1", true, 0, 0, 0},  // min < 1
		{"5:3:1", true, 0, 0, 0},  // max < min
		{"1:9:1", true, 0, 0, 0},  // max > 8
		{"4:4:", true, 0, 0, 0},   // empty charset
		{"4:4:z", true, 0, 0, 0},  // unknown charset
	}

	for _, tt := range tests {
		gen, err := ParsePasswordGenerator(tt.spec)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParsePasswordGenerator(%q): expected error", tt.spec)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePasswordGenerator(%q): unexpected error: %v", tt.spec, err)
			continue
		}
		if gen.MinLen != tt.minLen {
			t.Errorf("ParsePasswordGenerator(%q): MinLen = %d, want %d", tt.spec, gen.MinLen, tt.minLen)
		}
		if gen.MaxLen != tt.maxLen {
			t.Errorf("ParsePasswordGenerator(%q): MaxLen = %d, want %d", tt.spec, gen.MaxLen, tt.maxLen)
		}
		if gen.Count() != tt.count {
			t.Errorf("ParsePasswordGenerator(%q): Count = %d, want %d", tt.spec, gen.Count(), tt.count)
		}
	}
}

func TestPasswordGeneratorGenerate(t *testing.T) {
	t.Run("4-digit PINs", func(t *testing.T) {
		gen, err := ParsePasswordGenerator("4:4:1")
		if err != nil {
			t.Fatal(err)
		}

		passwords := gen.Generate()
		if len(passwords) != 10000 {
			t.Fatalf("expected 10000 PINs, got %d", len(passwords))
		}

		// Check first and last
		if passwords[0] != "0000" {
			t.Errorf("first PIN = %q, want 0000", passwords[0])
		}
		if passwords[9999] != "9999" {
			t.Errorf("last PIN = %q, want 9999", passwords[9999])
		}

		// Check all are 4 digits
		for i, p := range passwords {
			if len(p) != 4 {
				t.Errorf("PIN %d has length %d: %q", i, len(p), p)
				break
			}
		}
	})

	t.Run("1 char lowercase", func(t *testing.T) {
		gen, err := ParsePasswordGenerator("1:1:a")
		if err != nil {
			t.Fatal(err)
		}

		passwords := gen.Generate()
		if len(passwords) != 26 {
			t.Fatalf("expected 26 passwords, got %d", len(passwords))
		}
		if passwords[0] != "a" {
			t.Errorf("first = %q, want a", passwords[0])
		}
		if passwords[25] != "z" {
			t.Errorf("last = %q, want z", passwords[25])
		}
	})

	t.Run("variable length", func(t *testing.T) {
		gen, err := ParsePasswordGenerator("1:2:1")
		if err != nil {
			t.Fatal(err)
		}

		passwords := gen.Generate()
		if len(passwords) != 110 {
			t.Fatalf("expected 110 passwords (10 + 100), got %d", len(passwords))
		}

		// First 10 should be single digits
		for i := 0; i < 10; i++ {
			if len(passwords[i]) != 1 {
				t.Errorf("password %d should be 1 char, got %q", i, passwords[i])
			}
		}
		// Next 100 should be 2 digits
		for i := 10; i < 110; i++ {
			if len(passwords[i]) != 2 {
				t.Errorf("password %d should be 2 chars, got %q", i, passwords[i])
			}
		}
	})

	t.Run("symbols charset", func(t *testing.T) {
		gen, err := ParsePasswordGenerator("1:1:!")
		if err != nil {
			t.Fatal(err)
		}

		passwords := gen.Generate()
		if len(passwords) == 0 {
			t.Fatal("expected some passwords with symbol charset")
		}
		// All should be 1 char
		for _, p := range passwords {
			if len(p) != 1 {
				t.Errorf("expected 1 char, got %q", p)
				break
			}
		}
	})
}

func TestPasswordGeneratorCount(t *testing.T) {
	// Use a small spec to avoid generating billions of passwords
	gen, err := ParsePasswordGenerator("1:2:1")
	if err != nil {
		t.Fatal(err)
	}

	count := gen.Count()
	passwords := gen.Generate()
	if count != len(passwords) {
		t.Errorf("Count() = %d but Generate() produced %d", count, len(passwords))
	}
}

func TestPasswordGeneratorDedup(t *testing.T) {
	// Ensure that specifying the same charset multiple times doesn't duplicate chars
	gen, err := ParsePasswordGenerator("1:1:aa")
	if err != nil {
		t.Fatal(err)
	}

	if len(gen.Charset) != 26 {
		t.Errorf("expected 26 unique chars for 'aa', got %d", len(gen.Charset))
	}
}
