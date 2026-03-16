package modules

import (
	"fmt"
	"strings"
)

// PasswordGenerator generates passwords based on a charset and length range.
// Format: MIN:MAX:CHARSET where charset chars are:
//
//	a = lowercase (a-z)
//	A = uppercase (A-Z)
//	1 = digits (0-9)
//	! = symbols (!@#$%^&*()_+-=[]{}|;:',.<>?/`~")
type PasswordGenerator struct {
	MinLen  int
	MaxLen  int
	Charset []byte
}

const symbolChars = `!@#$%^&*()_+-=[]{}|;:',.<>?/` + "`~\""

// ParsePasswordGenerator parses a -x MIN:MAX:CHARSET spec into a PasswordGenerator.
func ParsePasswordGenerator(spec string) (*PasswordGenerator, error) {
	parts := strings.SplitN(spec, ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid -x format: expected MIN:MAX:CHARSET, got %q", spec)
	}

	var minLen, maxLen int
	if _, err := fmt.Sscanf(parts[0], "%d", &minLen); err != nil {
		return nil, fmt.Errorf("invalid min length %q: %v", parts[0], err)
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &maxLen); err != nil {
		return nil, fmt.Errorf("invalid max length %q: %v", parts[1], err)
	}
	if minLen < 1 {
		return nil, fmt.Errorf("min length must be >= 1, got %d", minLen)
	}
	if maxLen < minLen {
		return nil, fmt.Errorf("max length (%d) must be >= min length (%d)", maxLen, minLen)
	}
	if maxLen > 8 {
		return nil, fmt.Errorf("max length %d too large (max 8 to prevent excessive generation)", maxLen)
	}

	charsetSpec := parts[2]
	if charsetSpec == "" {
		return nil, fmt.Errorf("charset must not be empty")
	}

	var charset []byte
	seen := make(map[byte]bool)
	for i := 0; i < len(charsetSpec); i++ {
		switch charsetSpec[i] {
		case 'a':
			for c := byte('a'); c <= 'z'; c++ {
				if !seen[c] {
					charset = append(charset, c)
					seen[c] = true
				}
			}
		case 'A':
			for c := byte('A'); c <= 'Z'; c++ {
				if !seen[c] {
					charset = append(charset, c)
					seen[c] = true
				}
			}
		case '1':
			for c := byte('0'); c <= '9'; c++ {
				if !seen[c] {
					charset = append(charset, c)
					seen[c] = true
				}
			}
		case '!':
			for j := 0; j < len(symbolChars); j++ {
				c := symbolChars[j]
				if !seen[c] {
					charset = append(charset, c)
					seen[c] = true
				}
			}
		default:
			return nil, fmt.Errorf("unknown charset character %q (valid: a, A, 1, !)", string(charsetSpec[i]))
		}
	}

	return &PasswordGenerator{
		MinLen:  minLen,
		MaxLen:  maxLen,
		Charset: charset,
	}, nil
}

// Generate returns all passwords matching the generator's configuration.
func (pg *PasswordGenerator) Generate() []string {
	var passwords []string
	for length := pg.MinLen; length <= pg.MaxLen; length++ {
		pg.generateRecursive(make([]byte, length), 0, &passwords)
	}
	return passwords
}

// Count returns the total number of passwords that would be generated.
func (pg *PasswordGenerator) Count() int {
	total := 0
	charsetLen := len(pg.Charset)
	for length := pg.MinLen; length <= pg.MaxLen; length++ {
		count := 1
		for i := 0; i < length; i++ {
			count *= charsetLen
		}
		total += count
	}
	return total
}

func (pg *PasswordGenerator) generateRecursive(current []byte, pos int, result *[]string) {
	if pos == len(current) {
		*result = append(*result, string(current))
		return
	}
	for _, c := range pg.Charset {
		current[pos] = c
		pg.generateRecursive(current, pos+1, result)
	}
}
