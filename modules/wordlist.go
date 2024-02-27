package modules

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"

	"github.com/pterm/pterm"
)

func downloadFileFromGithub(url, localPath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	spinner, _ := pterm.DefaultSpinner.Start("Downloading wordlist...")

	if resp.StatusCode == 404 {
		spinner.Fail("Wordlist not found")
		pterm.Error.Println("The requested wordlist cannot be downloaded.")
		os.Exit(1)
	}

	file, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer file.Close()

	buf := make([]byte, 4096)
	var downloaded int
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			_, err := file.Write(buf[:n])
			if err != nil {
				return err
			}
			downloaded += n
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}

	spinner.Success()

	return nil
}

func ReadUsersFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	users := []string{}
	for scanner.Scan() {
		users = append(users, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

func ReadPasswordsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	passwords := []string{}
	for scanner.Scan() {
		passwords = append(passwords, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return passwords, nil
}

func GetUsersFromDefaultWordlist(version string, serviceType string) []string {
	wordlistPath := filepath.Join("wordlist", serviceType, "user")
	url := fmt.Sprintf("https://raw.githubusercontent.com/x90skysn3k/brutespray/%s/wordlist/%s/user", version, serviceType)

	globalWordlistPath := filepath.Join("/usr/share/brutespray/wordlist", serviceType, "user")

	if _, err := os.Stat(globalWordlistPath); !os.IsNotExist(err) {
		wordlistPath = globalWordlistPath
	}

	if runtime.GOOS == "windows" {
		currentUser, _ := user.Current()
		appDataPath := filepath.Join(currentUser.HomeDir, "AppData", "Roaming")
		wordlistPath = filepath.Join(appDataPath, "brutespray", "wordlist", serviceType, "user")
	}

	wordlistDir := filepath.Dir(wordlistPath)
	if _, err := os.Stat(wordlistDir); os.IsNotExist(err) {
		err := os.MkdirAll(wordlistDir, 0755)
		if err != nil {
			fmt.Printf("Error creating wordlist directory: %s\n", err)
			os.Exit(1)
		}
	}

	if _, err := os.Stat(wordlistPath); os.IsNotExist(err) {
		err := downloadFileFromGithub(url, wordlistPath)
		if err != nil {
			fmt.Printf("Error downloading user wordlist: %s\n", err)
			os.Exit(1)
		}
	}

	f, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Printf("Error opening %s wordlist: %s\n", "user", err)
		os.Exit(1)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	users := []string{}
	for scanner.Scan() {
		users = append(users, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading %s wordlist: %s\n", "user", err)
		os.Exit(1)
	}

	return users
}

func GetPasswordsFromDefaultWordlist(version string, serviceType string) []string {
	wordlistPath := filepath.Join("wordlist", serviceType, "password")
	url := fmt.Sprintf("https://raw.githubusercontent.com/x90skysn3k/brutespray/%s/wordlist/%s/password", version, serviceType)

	globalWordlistPath := filepath.Join("/usr/share/brutespray/wordlist", serviceType, "password")

	if _, err := os.Stat(globalWordlistPath); !os.IsNotExist(err) {
		wordlistPath = globalWordlistPath
	}

	if runtime.GOOS == "windows" {
		currentUser, _ := user.Current()
		appDataPath := filepath.Join(currentUser.HomeDir, "AppData", "Roaming")
		wordlistPath = filepath.Join(appDataPath, "brutespray", "wordlist", serviceType, "password")
	}

	wordlistDir := filepath.Dir(wordlistPath)
	if _, err := os.Stat(wordlistDir); os.IsNotExist(err) {
		err := os.MkdirAll(wordlistDir, 0755)
		if err != nil {
			fmt.Printf("Error creating wordlist directory: %s\n", err)
			os.Exit(1)
		}
	}

	if _, err := os.Stat(wordlistPath); os.IsNotExist(err) {
		err := downloadFileFromGithub(url, wordlistPath)
		if err != nil {
			fmt.Printf("Error downloading password wordlist: %s\n", err)
			os.Exit(1)
		}
	}

	f, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Printf("Error opening %s wordlist: %s\n", "pass", err)
		os.Exit(1)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	users := []string{}
	for scanner.Scan() {
		users = append(users, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading %s wordlist: %s\n", "pass", err)
		os.Exit(1)
	}

	return users
}
