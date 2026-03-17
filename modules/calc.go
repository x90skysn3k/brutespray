package modules

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// UseEmptyPassword instructs GetUsersAndPasswords to include a single empty
// string (blank password) when the password flag was explicitly provided as
// empty by the user (e.g., -p ”).
var UseEmptyPassword bool

func GetUsersAndPasswordsCombo(h *Host, combo string, version string) ([]string, []string) {
	userSlice := []string{}
	passSlice := []string{}

	if IsFile(combo) {
		file, err := os.Open(combo)
		if err != nil {
			fmt.Println("Error opening combo file:", err)
			os.Exit(1)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, ":") {
				splits := strings.SplitN(line, ":", 2)
				userSlice = append(userSlice, splits[0])
				passSlice = append(passSlice, splits[1])
			} else {
				fmt.Printf("Invalid format in combo file: %s\n", line)
				os.Exit(1)
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Println("Error reading combo file:", err)
			os.Exit(1)
		}
	} else {
		splits := strings.SplitN(combo, ":", 2)
		if len(splits) < 2 {
			fmt.Printf("Invalid combo format %q (expected user:pass)\n", combo)
			os.Exit(2)
		}
		userSlice = append(userSlice, splits[0])
		passSlice = append(passSlice, splits[1])
	}

	return userSlice, passSlice
}

func GetUsersAndPasswords(h *Host, user string, password string, version string) ([]string, []string, error) {
	// Auto-detect PwDump format in password file: extracts user+NTLM hash pairs
	if password != "" && IsFile(password) && IsPwDumpFile(password) {
		users, hashes, err := ReadPwDumpFile(password)
		if err != nil {
			return nil, nil, fmt.Errorf("reading PwDump file: %w", err)
		}
		return users, hashes, nil
	}

	type result struct {
		words []string
		err   error
	}
	userCh := make(chan result, 1)
	passCh := make(chan result, 1)

	go func() {
		if user != "" {
			if IsFile(user) {
				users, err := ReadUsersFromFile(user)
				if err != nil {
					userCh <- result{nil, fmt.Errorf("reading user file: %w", err)}
					return
				}
				userCh <- result{users, nil}
			} else {
				userCh <- result{[]string{user}, nil}
			}
		} else {
			users, err := GetUsersFromDefaultWordlist(version, h.Service)
			userCh <- result{users, err}
		}
	}()

	go func() {
		if password != "" {
			if IsFile(password) {
				passwords, err := ReadPasswordsFromFile(password)
				if err != nil {
					passCh <- result{nil, fmt.Errorf("reading password file: %w", err)}
					return
				}
				passCh <- result{passwords, nil}
			} else {
				passCh <- result{[]string{password}, nil}
			}
		} else {
			if UseEmptyPassword {
				passCh <- result{[]string{""}, nil}
			} else {
				passwords, err := GetPasswordsFromDefaultWordlist(version, h.Service)
				passCh <- result{passwords, err}
			}
		}
	}()

	userResult := <-userCh
	if userResult.err != nil {
		return nil, nil, userResult.err
	}

	passResult := <-passCh
	if passResult.err != nil {
		return nil, nil, passResult.err
	}

	return userResult.words, passResult.words, nil
}

// pwdumpRe matches lines in PwDump format: username:uid:LM_hash:NTLM_hash:::
var pwdumpRe = regexp.MustCompile(`^([^:]+):\d+:[0-9a-fA-F]{32}:([0-9a-fA-F]{32}):::$`)

// IsPwDumpFile checks whether a file is in PwDump format by examining the first line.
func IsPwDumpFile(filename string) bool {
	file, err := os.Open(filename)
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		return pwdumpRe.MatchString(scanner.Text())
	}
	return false
}

// ReadPwDumpFile parses a PwDump file and returns users and NTLM hashes.
func ReadPwDumpFile(filename string) (users []string, hashes []string, err error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		matches := pwdumpRe.FindStringSubmatch(line)
		if len(matches) == 3 {
			users = append(users, matches[1])
			hashes = append(hashes, matches[2])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return users, hashes, nil
}

