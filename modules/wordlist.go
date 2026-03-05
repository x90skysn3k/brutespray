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
	"sync"

	"github.com/pterm/pterm"
)

// WordlistCache provides thread-safe caching of wordlists
type WordlistCache struct {
	cache map[string][]string
	mutex sync.RWMutex
}

var wordlistCache = &WordlistCache{
	cache: make(map[string][]string),
}

func (wc *WordlistCache) Get(key string) ([]string, bool) {
	wc.mutex.RLock()
	defer wc.mutex.RUnlock()
	words, exists := wc.cache[key]
	return words, exists
}

func (wc *WordlistCache) Set(key string, words []string) {
	wc.mutex.Lock()
	defer wc.mutex.Unlock()
	wc.cache[key] = words
}

func downloadFileFromGithub(url, localPath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	spinner, _ := pterm.DefaultSpinner.Start("Downloading wordlist...")

	if resp.StatusCode == 404 {
		spinner.Fail("Wordlist not found")
		return fmt.Errorf("wordlist not found at %s (HTTP 404)", url)
	}

	file, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Use larger buffer for better performance
	buf := make([]byte, 8192)
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

// readFileLines reads lines from a file with optimized buffering
func readFileLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Use larger buffer for better performance
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // 64KB buffer, 1MB max line length

	// Pre-allocate slice with reasonable capacity
	lines := make([]string, 0, 1000)

	for scanner.Scan() {
		line := scanner.Text()
		if line != "" { // Skip empty lines
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

func ReadUsersFromFile(filename string) ([]string, error) {
	return readFileLines(filename)
}

func ReadPasswordsFromFile(filename string) ([]string, error) {
	return readFileLines(filename)
}

func GetUsersFromDefaultWordlist(version string, serviceType string) ([]string, error) {
	cacheKey := fmt.Sprintf("users_%s_%s", version, serviceType)

	// Check cache first
	if cached, exists := wordlistCache.Get(cacheKey); exists {
		return cached, nil
	}

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
		if err := os.MkdirAll(wordlistDir, 0755); err != nil {
			return nil, fmt.Errorf("creating wordlist directory: %w", err)
		}
	}

	if _, err := os.Stat(wordlistPath); os.IsNotExist(err) {
		if err := downloadFileFromGithub(url, wordlistPath); err != nil {
			return nil, fmt.Errorf("downloading user wordlist: %w", err)
		}
	}

	users, err := readFileLines(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("reading user wordlist: %w", err)
	}

	// Cache the result
	wordlistCache.Set(cacheKey, users)

	return users, nil
}

func GetPasswordsFromDefaultWordlist(version string, serviceType string) ([]string, error) {
	cacheKey := fmt.Sprintf("passwords_%s_%s", version, serviceType)

	// Check cache first
	if cached, exists := wordlistCache.Get(cacheKey); exists {
		return cached, nil
	}

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
		if err := os.MkdirAll(wordlistDir, 0755); err != nil {
			return nil, fmt.Errorf("creating wordlist directory: %w", err)
		}
	}

	if _, err := os.Stat(wordlistPath); os.IsNotExist(err) {
		if err := downloadFileFromGithub(url, wordlistPath); err != nil {
			return nil, fmt.Errorf("downloading password wordlist: %w", err)
		}
	}

	passwords, err := readFileLines(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("reading password wordlist: %w", err)
	}

	// Cache the result
	wordlistCache.Set(cacheKey, passwords)

	return passwords, nil
}
