package modules

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/pterm/pterm"
	"github.com/x90skysn3k/brutespray/v2/wordlist"
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

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	lines := make([]string, 0, 1000)

	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
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

// tryManifestFromFS loads a wordlist for a service from a manifest in an fs.FS.
func tryManifestFromFS(fsys fs.FS, serviceType, kind string) ([]string, error) {
	m, err := LoadManifestFS(fsys, "manifest.yaml")
	if err != nil {
		return nil, err
	}
	resolved, err := m.ResolveService(serviceType)
	if err != nil {
		return nil, err
	}
	var refs []string
	if kind == "users" {
		refs = resolved.Users
	} else {
		refs = resolved.Passwords
	}
	if len(refs) == 0 {
		return []string{}, nil
	}
	return m.LoadWordlistFS(refs, fsys)
}

// tryLocalManifest loads a wordlist from a local manifest.yaml on disk.
func tryLocalManifest(serviceType, kind string) ([]string, error) {
	candidates := []string{
		filepath.Join("wordlist", "manifest.yaml"),
		filepath.Join("/usr/share/brutespray/wordlist", "manifest.yaml"),
	}
	if runtime.GOOS == "windows" {
		if u, _ := user.Current(); u != nil {
			candidates = append(candidates,
				filepath.Join(u.HomeDir, "AppData", "Roaming", "brutespray", "wordlist", "manifest.yaml"))
		}
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err != nil {
			continue
		}
		m, err := LoadManifest(c)
		if err != nil {
			continue
		}
		resolved, err := m.ResolveService(serviceType)
		if err != nil {
			continue
		}
		var refs []string
		if kind == "users" {
			refs = resolved.Users
		} else {
			refs = resolved.Passwords
		}
		if len(refs) == 0 {
			return []string{}, nil
		}
		wordlistDir := filepath.Dir(c)
		return m.LoadWordlist(refs, wordlistDir)
	}
	return nil, fmt.Errorf("no local manifest found")
}

func GetUsersFromDefaultWordlist(version string, serviceType string) ([]string, error) {
	cacheKey := fmt.Sprintf("users_%s_%s", version, serviceType)

	if cached, exists := wordlistCache.Get(cacheKey); exists {
		return cached, nil
	}

	// Try local manifest first
	if users, err := tryLocalManifest(serviceType, "users"); err == nil {
		wordlistCache.Set(cacheKey, users)
		return users, nil
	}

	// Try embedded manifest
	if users, err := tryManifestFromFS(wordlist.FS, serviceType, "users"); err == nil {
		wordlistCache.Set(cacheKey, users)
		return users, nil
	}

	// Fallback: flat file / GitHub download
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

	wordlistCache.Set(cacheKey, users)

	return users, nil
}

func GetPasswordsFromDefaultWordlist(version string, serviceType string) ([]string, error) {
	cacheKey := fmt.Sprintf("passwords_%s_%s", version, serviceType)

	if cached, exists := wordlistCache.Get(cacheKey); exists {
		return cached, nil
	}

	// Try local manifest first
	if passwords, err := tryLocalManifest(serviceType, "passwords"); err == nil {
		wordlistCache.Set(cacheKey, passwords)
		return passwords, nil
	}

	// Try embedded manifest
	if passwords, err := tryManifestFromFS(wordlist.FS, serviceType, "passwords"); err == nil {
		wordlistCache.Set(cacheKey, passwords)
		return passwords, nil
	}

	// Fallback: flat file / GitHub download
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

	wordlistCache.Set(cacheKey, passwords)

	return passwords, nil
}
