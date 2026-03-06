package brutespray

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pterm/pterm"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

// WordlistCommand handles the "brutespray wordlist <subcommand>" CLI.
func WordlistCommand(args []string) {
	if len(args) == 0 {
		printWordlistUsage()
		os.Exit(1)
	}

	var err error
	switch args[0] {
	case "seasonal":
		err = cmdSeasonal()
	case "validate":
		err = cmdValidate()
	case "build":
		err = cmdBuild()
	case "research":
		err = cmdResearch()
	case "merge":
		err = cmdMerge()
	case "download":
		err = cmdDownload(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown wordlist command: %s\n", args[0])
		printWordlistUsage()
		os.Exit(1)
	}
	if err != nil {
		pterm.Error.Println(err)
		os.Exit(1)
	}
}

func printWordlistUsage() {
	pterm.DefaultHeader.WithBackgroundStyle(pterm.NewStyle(pterm.BgRed)).Println("BruteSpray Wordlist Manager")
	fmt.Println()
	fmt.Println("Usage: brutespray wordlist <command>")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  seasonal    Regenerate seasonal passwords")
	fmt.Println("  validate    Validate wordlists and manifest")
	fmt.Println("  build       Build flat wordlists from manifest")
	fmt.Println("  research    Research default credentials via Ollama")
	fmt.Println("  merge       Merge research candidates into wordlists")
	fmt.Println("  download    Download rockyou.txt wordlist")
}

// --- seasonal ---

func cmdSeasonal() error {
	currentYear := time.Now().Year()
	startYear := currentYear - 3
	endYear := currentYear + 1

	seasons := []string{"Spring", "Summer", "Fall", "Autumn", "Winter"}
	months := []string{"January", "February", "March", "April", "May", "June",
		"July", "August", "September", "October", "November", "December"}

	seen := make(map[string]struct{})
	var passwords []string
	add := func(p string) {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			passwords = append(passwords, p)
		}
	}

	for year := startYear; year <= endYear; year++ {
		for _, season := range seasons {
			y := fmt.Sprintf("%d", year)
			add(season + y)
			add(strings.ToLower(season) + y)
			add(season + y + "!")
			add(strings.ToLower(season) + y + "!")
		}
	}

	for year := currentYear - 1; year <= currentYear+1; year++ {
		for _, month := range months {
			y := fmt.Sprintf("%d", year)
			add(month + y)
			add(month + y + "!")
		}
	}

	sort.Strings(passwords)

	outPath := filepath.Join("wordlist", "_base", "passwords-seasonal.txt")
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(outPath, []byte(strings.Join(passwords, "\n")+"\n"), 0644); err != nil {
		return err
	}
	pterm.Success.Printfln("Generated %d seasonal passwords → %s", len(passwords), outPath)
	return nil
}

// --- validate ---

func cmdValidate() error {
	manifestPath := filepath.Join("wordlist", "manifest.yaml")
	m, err := modules.LoadManifest(manifestPath)
	if err != nil {
		return fmt.Errorf("loading manifest: %w", err)
	}

	var validationErrors []string

	allRefs := make(map[string]string)
	for k, v := range m.Bases {
		allRefs[k] = v
	}
	for k, v := range m.Layers {
		allRefs[k] = v
	}
	for ref, path := range allRefs {
		fullPath := filepath.Join("wordlist", path)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			validationErrors = append(validationErrors, fmt.Sprintf("base/layer %q references missing file: %s", ref, fullPath))
		}
	}

	for name, svc := range m.Services {
		if svc.Alias != "" {
			if _, ok := m.Services[svc.Alias]; !ok {
				validationErrors = append(validationErrors, fmt.Sprintf("service %q aliases non-existent service %q", name, svc.Alias))
			}
			continue
		}
		for _, ref := range svc.Users {
			if _, ok := allRefs[ref]; !ok {
				path := filepath.Join("wordlist", ref)
				if _, err := os.Stat(path); os.IsNotExist(err) {
					validationErrors = append(validationErrors, fmt.Sprintf("service %q user ref %q: file not found", name, ref))
				}
			}
		}
		for _, ref := range svc.Passwords {
			if _, ok := allRefs[ref]; !ok {
				path := filepath.Join("wordlist", ref)
				if _, err := os.Stat(path); os.IsNotExist(err) {
					validationErrors = append(validationErrors, fmt.Sprintf("service %q password ref %q: file not found", name, ref))
				}
			}
		}
	}

	var filesToCheck []string
	for _, p := range m.Bases {
		filesToCheck = append(filesToCheck, filepath.Join("wordlist", p))
	}
	for _, p := range m.Layers {
		filesToCheck = append(filesToCheck, filepath.Join("wordlist", p))
	}
	overridesDir := filepath.Join("wordlist", "overrides")
	_ = filepath.Walk(overridesDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(path, ".txt") {
			filesToCheck = append(filesToCheck, path)
		}
		return nil
	})
	snmpFile := filepath.Join("wordlist", "snmp", "community.txt")
	if _, err := os.Stat(snmpFile); err == nil {
		filesToCheck = append(filesToCheck, snmpFile)
	}

	for _, path := range filesToCheck {
		if err := validateWordlistFile(path); err != nil {
			validationErrors = append(validationErrors, err.Error())
		}
	}

	if len(validationErrors) > 0 {
		for _, e := range validationErrors {
			pterm.Error.Println(e)
		}
		return fmt.Errorf("%d validation errors found", len(validationErrors))
	}

	pterm.Success.Println("Validation passed.")
	return nil
}

func validateWordlistFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer f.Close()

	seen := make(map[string]int)
	scanner := bufio.NewScanner(f)
	lineNum := 0
	var dupes []string
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			return fmt.Errorf("%s:%d: empty line", path, lineNum)
		}
		if prev, ok := seen[line]; ok {
			dupes = append(dupes, fmt.Sprintf("%q (lines %d and %d)", line, prev, lineNum))
		}
		seen[line] = lineNum
	}
	if len(dupes) > 0 {
		limit := 3
		if len(dupes) < limit {
			limit = len(dupes)
		}
		return fmt.Errorf("%s: %d duplicates: %s", path, len(dupes), strings.Join(dupes[:limit], ", "))
	}
	return scanner.Err()
}

// --- build ---

func cmdBuild() error {
	manifestPath := filepath.Join("wordlist", "manifest.yaml")
	m, err := modules.LoadManifest(manifestPath)
	if err != nil {
		return fmt.Errorf("loading manifest: %w", err)
	}

	wordlistDir := "wordlist"

	for name := range m.Services {
		resolved, err := m.ResolveService(name)
		if err != nil {
			return fmt.Errorf("service %q: %w", name, err)
		}

		serviceDir := filepath.Join(wordlistDir, name)
		if err := os.MkdirAll(serviceDir, 0755); err != nil {
			return err
		}

		var userCount, passCount int

		if len(resolved.Users) > 0 {
			users, err := m.LoadWordlist(resolved.Users, wordlistDir)
			if err != nil {
				return fmt.Errorf("service %q users: %w", name, err)
			}
			userCount = len(users)
			if err := writeWordlistFile(filepath.Join(serviceDir, "user"), users); err != nil {
				return err
			}
		}

		if len(resolved.Passwords) > 0 {
			passwords, err := m.LoadWordlist(resolved.Passwords, wordlistDir)
			if err != nil {
				return fmt.Errorf("service %q passwords: %w", name, err)
			}
			passCount = len(passwords)
			if err := writeWordlistFile(filepath.Join(serviceDir, "password"), passwords); err != nil {
				return err
			}
		}

		pterm.FgLightCyan.Printf("  %-12s ", name)
		fmt.Printf("users=%-4d passwords=%d\n", userCount, passCount)
	}

	pterm.Success.Println("Flat wordlists built successfully.")
	return nil
}

func writeWordlistFile(path string, lines []string) error {
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

// --- research ---

type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type ollamaResponse struct {
	Response string `json:"response"`
}

type researchCandidate struct {
	Service string `json:"service"`
	Type    string `json:"type"`
	Value   string `json:"value"`
	Product string `json:"product"`
	Source  string `json:"source"`
}

func cmdResearch() error {
	model := os.Getenv("OLLAMA_MODEL")
	if model == "" {
		model = "qwen3:14b"
	}
	ollamaURL := os.Getenv("OLLAMA_URL")
	if ollamaURL == "" {
		ollamaURL = "http://localhost:11434"
	}

	services := []string{
		"ssh", "ftp", "telnet", "rdp", "http", "mysql", "mssql",
		"postgres", "oracle", "mongodb", "redis", "snmp", "smtp",
		"imap", "pop3", "ldap", "vnc", "winrm", "smbnt",
	}

	var allCandidates []researchCandidate

	for _, svc := range services {
		spinner, _ := pterm.DefaultSpinner.Start(fmt.Sprintf("Researching %s...", svc))
		prompt := fmt.Sprintf(`List all publicly documented default credentials for %s services and appliances.
Include credentials from vendor documentation, security advisories, and CVE reports.
Do NOT include credentials from data breaches or leaks.

Return ONLY a JSON array with objects like:
[{"product": "ProductName", "username": "admin", "password": "admin", "source": "vendor docs"}]

Focus on:
- Network appliances and IoT devices
- Database default accounts
- Web management interfaces
- Enterprise software defaults
- Cloud service defaults

Return valid JSON only, no other text.`, svc)

		resp, err := queryOllama(ollamaURL, model, prompt)
		if err != nil {
			spinner.Fail(fmt.Sprintf("%s: %v", svc, err))
			continue
		}

		var creds []struct {
			Product  string `json:"product"`
			Username string `json:"username"`
			Password string `json:"password"`
			Source   string `json:"source"`
		}

		jsonStr := extractJSON(resp)
		if err := json.Unmarshal([]byte(jsonStr), &creds); err != nil {
			spinner.Fail(fmt.Sprintf("%s: parse failed: %v", svc, err))
			continue
		}

		for _, c := range creds {
			if c.Username != "" {
				allCandidates = append(allCandidates, researchCandidate{
					Service: svc, Type: "user", Value: c.Username,
					Product: c.Product, Source: c.Source,
				})
			}
			if c.Password != "" {
				allCandidates = append(allCandidates, researchCandidate{
					Service: svc, Type: "password", Value: c.Password,
					Product: c.Product, Source: c.Source,
				})
			}
		}
		spinner.Success(fmt.Sprintf("%s: found %d credentials", svc, len(creds)))
	}

	outPath := filepath.Join("wordlist", "_candidates.json")
	data, _ := json.MarshalIndent(allCandidates, "", "  ")
	if err := os.WriteFile(outPath, data, 0644); err != nil {
		return err
	}

	pterm.Success.Printfln("Wrote %d candidates to %s", len(allCandidates), outPath)
	return nil
}

func queryOllama(baseURL, model, prompt string) (string, error) {
	reqBody, _ := json.Marshal(ollamaRequest{
		Model:  model,
		Prompt: prompt,
		Stream: false,
	})

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Post(baseURL+"/api/generate", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("ollama returned %d: %s", resp.StatusCode, string(body))
	}

	var result ollamaResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parsing response: %w", err)
	}

	return result.Response, nil
}

func extractJSON(s string) string {
	start := strings.Index(s, "[")
	end := strings.LastIndex(s, "]")
	if start >= 0 && end > start {
		return s[start : end+1]
	}
	return s
}

// --- merge ---

func cmdMerge() error {
	candidatesPath := filepath.Join("wordlist", "_candidates.json")
	data, err := os.ReadFile(candidatesPath)
	if err != nil {
		return fmt.Errorf("reading candidates: %w (run 'brutespray wordlist research' first)", err)
	}

	var candidates []researchCandidate
	if err := json.Unmarshal(data, &candidates); err != nil {
		return fmt.Errorf("parsing candidates: %w", err)
	}

	// Group candidates by service and type
	type key struct{ service, typ string }
	grouped := make(map[key][]string)
	for _, c := range candidates {
		k := key{c.Service, c.Type}
		grouped[k] = append(grouped[k], c.Value)
	}

	manifestPath := filepath.Join("wordlist", "manifest.yaml")
	m, err := modules.LoadManifest(manifestPath)
	if err != nil {
		return fmt.Errorf("loading manifest: %w", err)
	}

	var totalAdded int

	for k, values := range grouped {
		resolved, err := m.ResolveService(k.service)
		if err != nil {
			pterm.Warning.Printfln("Skipping %s/%s: %v", k.service, k.typ, err)
			continue
		}

		// Determine the override file path
		var overridePath string
		var refs []string
		if k.typ == "user" {
			refs = resolved.Users
		} else {
			refs = resolved.Passwords
		}

		// Find an existing override file, or create one
		for _, ref := range refs {
			if strings.HasPrefix(ref, "overrides/") {
				overridePath = filepath.Join("wordlist", ref)
				break
			}
		}
		if overridePath == "" {
			// Create a new override file for this service
			var filename string
			if k.typ == "user" {
				filename = "user.txt"
			} else {
				filename = "password.txt"
			}
			overridePath = filepath.Join("wordlist", "overrides", k.service, filename)
		}

		// Read existing entries
		existing := make(map[string]struct{})
		if content, err := os.ReadFile(overridePath); err == nil {
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					existing[line] = struct{}{}
				}
			}
		}

		// Find new unique values
		var newEntries []string
		for _, v := range values {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			if _, exists := existing[v]; !exists {
				existing[v] = struct{}{}
				newEntries = append(newEntries, v)
			}
		}

		if len(newEntries) == 0 {
			continue
		}

		// Append new entries to the file
		if err := os.MkdirAll(filepath.Dir(overridePath), 0755); err != nil {
			return err
		}

		f, err := os.OpenFile(overridePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("opening %s: %w", overridePath, err)
		}
		for _, entry := range newEntries {
			fmt.Fprintln(f, entry)
		}
		f.Close()

		totalAdded += len(newEntries)
		pterm.FgLightCyan.Printf("  %-12s ", k.service)
		fmt.Printf("+%d %ss\n", len(newEntries), k.typ)
	}

	pterm.Success.Printfln("Merged %d new entries from candidates", totalAdded)
	return nil
}

// --- download ---

const rockyouURL = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"

func cmdDownload(args []string) error {
	outPath := "rockyou.txt"
	if len(args) > 0 && args[0] == "-o" && len(args) > 1 {
		outPath = args[1]
	}

	if _, err := os.Stat(outPath); err == nil {
		pterm.Warning.Printfln("%s already exists, skipping download", outPath)
		return nil
	}

	pterm.Info.Printfln("Downloading rockyou.txt → %s", outPath)

	resp, err := http.Get(rockyouURL)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	totalBytes := resp.ContentLength
	bar, _ := pterm.DefaultProgressbar.
		WithTotal(int(totalBytes)).
		WithTitle("rockyou.txt").
		WithBarStyle(pterm.NewStyle(pterm.FgCyan)).
		WithTitleStyle(pterm.NewStyle(pterm.FgLightCyan)).
		WithShowPercentage(true).
		WithShowCount(false).
		Start()

	buf := make([]byte, 32*1024)
	var downloaded int64
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, err := f.Write(buf[:n]); err != nil {
				return err
			}
			downloaded += int64(n)
			bar.Add(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("download error: %w", readErr)
		}
	}

	_, _ = bar.Stop()
	pterm.Success.Printfln("Downloaded %s (%.1f MB)", outPath, float64(downloaded)/(1024*1024))
	return nil
}
