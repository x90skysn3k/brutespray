package modules

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
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
		userSlice = append(userSlice, splits[0])
		passSlice = append(passSlice, splits[1])
	}

	return userSlice, passSlice
}

func GetUsersAndPasswords(h *Host, user string, password string, version string) ([]string, []string, error) {
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

func CalcCombinations(userCh []string, passCh []string) int {
	var totalCombinations int
	users := []string{}
	passwords := []string{}

	for u := range userCh {
		users = append(users, strconv.Itoa(u))
	}

	for p := range passCh {
		passwords = append(passwords, strconv.Itoa(p))
	}

	totalCombinations = len(users) * len(passwords)
	return totalCombinations
}

func CalcCombinationsPass(passCh []string) int {
	var totalCombinations int
	passwords := []string{}

	for p := range passCh {
		passwords = append(passwords, strconv.Itoa(p))
	}

	totalCombinations = len(passwords)
	return totalCombinations
}

func CalcCombinationsCombo(userCh []string, passCh []string) int {
	var totalCombinations int
	users := []string{}

	for u := range userCh {
		users = append(users, strconv.Itoa(u))
	}

	totalCombinations = len(users)
	return totalCombinations
}
