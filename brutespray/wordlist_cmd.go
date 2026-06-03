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
	"unicode"

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
	fmt.Println("  research    Research default credentials via Ollama or OpenAI-compatible APIs")
	fmt.Println("  merge       Merge research candidates into wordlists")
	fmt.Println("  download    Download rockyou.txt wordlist")
}

// --- seasonal ---

func cmdSeasonal() error {
	currentYear := time.Now().Year()
	startYear := currentYear - 3
	endYear := currentYear + 1
	manifestPath := filepath.Join("wordlist", "manifest.yaml")
	if _, err := os.Stat(manifestPath); err == nil {
		m, err := modules.LoadManifest(manifestPath)
		if err != nil {
			return fmt.Errorf("loading manifest: %w", err)
		}
		if m.SeasonalRange[0] > 0 && m.SeasonalRange[1] >= m.SeasonalRange[0] {
			startYear = m.SeasonalRange[0]
			endYear = m.SeasonalRange[1]
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("checking manifest: %w", err)
	}

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

	for year := startYear; year <= endYear; year++ {
		for _, month := range months {
			y := fmt.Sprintf("%d", year)
			add(month + y)
			add(month + y + "!")
		}
	}

	for _, p := range []string{"Welcome1", "Welcome123", "Welcome123!", "Password123!", "Changeme123!"} {
		add(p)
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
		if _, err := m.ResolveService(name); err != nil {
			validationErrors = append(validationErrors, fmt.Sprintf("service %q: %v", name, err))
			continue
		}
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

type researchLLMConfig struct {
	Provider string
	Model    string
	BaseURL  string
}

type openAIChatCompletionRequest struct {
	Model    string              `json:"model"`
	Messages []openAIChatMessage `json:"messages"`
	Stream   bool                `json:"stream"`
}

type openAIChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIChatCompletionResponse struct {
	Choices []struct {
		Message openAIChatMessage `json:"message"`
	} `json:"choices"`
}

type researchCandidate struct {
	Service string `json:"service"`
	Type    string `json:"type"`
	Value   string `json:"value"`
	Product string `json:"product"`
	Source  string `json:"source"`
}

const mergeScoreThreshold = 3

func isJunkValue(value string) bool {
	v := strings.TrimSpace(value)
	if len(v) <= 1 || len(v) > 64 {
		return true
	}
	for _, r := range v {
		if unicode.IsSpace(r) {
			return true
		}
	}
	lower := strings.ToLower(v)
	if strings.Contains(lower, "<") || strings.Contains(lower, ">") {
		return true
	}
	junk := map[string]struct{}{
		"***": {}, "default": {}, "n/a": {}, "na": {}, "none": {}, "null": {},
		"password": {}, "redacted": {}, "unknown": {}, "user": {}, "username": {},
		"your_password": {}, "yourpassword": {},
	}
	_, ok := junk[lower]
	return ok
}

func looksComplex(value string) bool {
	if len(value) < 4 {
		return false
	}
	classes := 0
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range value {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	for _, hasClass := range []bool{hasLower, hasUpper, hasDigit, hasSymbol} {
		if hasClass {
			classes++
		}
	}
	return classes >= 2
}

func scoreCandidate(c researchCandidate) int {
	score := 0
	source := strings.TrimSpace(c.Source)
	if strings.HasPrefix(strings.ToLower(source), "http://") || strings.HasPrefix(strings.ToLower(source), "https://") {
		score += 2
	} else if source != "" {
		score++
	}
	if isSpecificProduct(c.Product) {
		score++
	}
	if looksComplex(strings.TrimSpace(c.Value)) {
		score++
	}

	lowerSource := strings.ToLower(source)
	for _, disallowed := range []string{"breach", "dump", "leak", "pastebin"} {
		if strings.Contains(lowerSource, disallowed) {
			score -= 3
			break
		}
	}
	return score
}

func isSpecificProduct(product string) bool {
	p := strings.TrimSpace(product)
	if p == "" {
		return false
	}
	switch strings.ToLower(p) {
	case "appliance", "database", "device", "firewall", "router", "server", "service", "switch", "web":
		return false
	}
	return len(p) >= 4
}

type braveSearchResponse struct {
	Web struct {
		Results []struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			URL         string `json:"url"`
		} `json:"results"`
	} `json:"web"`
}

func searchBrave(apiKey, query string) (string, error) {
	req, err := http.NewRequest("GET", "https://api.search.brave.com/res/v1/web/search", nil)
	if err != nil {
		return "", err
	}
	q := req.URL.Query()
	q.Set("q", query)
	q.Set("count", "10")
	req.URL.RawQuery = q.Encode()
	req.Header.Set("X-Subscription-Token", apiKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("brave search: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("brave search returned %d: %s", resp.StatusCode, string(body))
	}

	var result braveSearchResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	var snippets []string
	for _, r := range result.Web.Results {
		snippets = append(snippets, fmt.Sprintf("- %s: %s (%s)", r.Title, r.Description, r.URL))
	}
	return strings.Join(snippets, "\n"), nil
}

func researchLLMConfigFromEnv() researchLLMConfig {
	provider := strings.TrimSpace(os.Getenv("WORDLIST_RESEARCH_PROVIDER"))
	if provider == "" {
		provider = "ollama"
	}
	provider = strings.ToLower(provider)

	model := strings.TrimSpace(os.Getenv("WORDLIST_RESEARCH_MODEL"))
	if model == "" {
		model = strings.TrimSpace(os.Getenv("OLLAMA_MODEL"))
	}
	if model == "" {
		model = "qwen3:14b"
	}

	baseURL := strings.TrimSpace(os.Getenv("WORDLIST_RESEARCH_URL"))
	if baseURL == "" {
		baseURL = strings.TrimSpace(os.Getenv("OLLAMA_URL"))
	}
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}

	return researchLLMConfig{
		Provider: provider,
		Model:    model,
		BaseURL:  strings.TrimRight(baseURL, "/"),
	}
}

func cmdResearch() error {
	llm := researchLLMConfigFromEnv()
	braveAPIKey := os.Getenv("BRAVE_API_KEY")

	services := []string{
		"ssh", "ftp", "telnet", "rdp", "http", "mysql", "mssql",
		"postgres", "oracle", "mongodb", "redis", "snmp", "smtp",
		"imap", "pop3", "ldap", "vnc", "winrm", "smbnt",
	}

	var allCandidates []researchCandidate

	for _, svc := range services {
		spinner, _ := pterm.DefaultSpinner.Start(fmt.Sprintf("Researching %s...", svc))

		// Search Brave for recent default credential info
		var searchContext string
		if braveAPIKey != "" {
			queries := []string{
				fmt.Sprintf("default credentials %s service appliance", svc),
				fmt.Sprintf("%s default username password CVE", svc),
			}
			var allSnippets []string
			for _, q := range queries {
				snippets, err := searchBrave(braveAPIKey, q)
				if err != nil {
					pterm.Warning.Printfln("  brave search warning: %v", err)
					continue
				}
				allSnippets = append(allSnippets, snippets)
			}
			if len(allSnippets) > 0 {
				searchContext = "\n\nHere are recent web search results for context:\n" +
					strings.Join(allSnippets, "\n")
			}
		}

		prompt := fmt.Sprintf(`List all publicly documented default credentials for %s services and appliances.
Include credentials from vendor documentation, security advisories, and CVE reports.
Do NOT include credentials from data breaches or leaks.
%s
Return ONLY a JSON array with objects like:
[{"product": "ProductName", "username": "admin", "password": "admin", "source": "vendor docs"}]

Focus on:
- Network appliances and IoT devices
- Database default accounts
- Web management interfaces
- Enterprise software defaults
- Cloud service defaults

Return valid JSON only, no other text.`, svc, searchContext)

		resp, err := queryResearchLLM(llm, prompt)
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

		srcLabel := llm.Provider
		if braveAPIKey != "" {
			srcLabel = "brave+" + llm.Provider
		}
		spinner.Success(fmt.Sprintf("%s: found %d credentials (%s)", svc, len(creds), srcLabel))
	}

	outPath := filepath.Join("wordlist", "_candidates.json")
	data, _ := json.MarshalIndent(allCandidates, "", "  ")
	if err := os.WriteFile(outPath, data, 0644); err != nil {
		return err
	}

	pterm.Success.Printfln("Wrote %d candidates to %s", len(allCandidates), outPath)
	return nil
}

func queryResearchLLM(cfg researchLLMConfig, prompt string) (string, error) {
	switch cfg.Provider {
	case "ollama":
		return queryOllama(cfg.BaseURL, cfg.Model, prompt)
	case "openai":
		return queryOpenAICompatible(cfg.BaseURL, cfg.Model, prompt)
	default:
		return "", fmt.Errorf("unknown wordlist research provider %q", cfg.Provider)
	}
}

func queryOllama(baseURL, model, prompt string) (string, error) {
	reqBody, _ := json.Marshal(ollamaRequest{
		Model:  model,
		Prompt: prompt,
		Stream: false,
	})

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Post(strings.TrimRight(baseURL, "/")+"/api/generate", "application/json", bytes.NewReader(reqBody))
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

func queryOpenAICompatible(baseURL, model, prompt string) (string, error) {
	reqBody, _ := json.Marshal(openAIChatCompletionRequest{
		Model: model,
		Messages: []openAIChatMessage{
			{Role: "user", Content: prompt},
		},
		Stream: false,
	})

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Post(strings.TrimRight(baseURL, "/")+"/v1/chat/completions", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("openai-compatible request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("openai-compatible provider returned %d: %s", resp.StatusCode, string(body))
	}

	var result openAIChatCompletionResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parsing response: %w", err)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("openai-compatible provider returned no choices")
	}

	return result.Choices[0].Message.Content, nil
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

	manifestPath := filepath.Join("wordlist", "manifest.yaml")
	m, err := modules.LoadManifest(manifestPath)
	if err != nil {
		return fmt.Errorf("loading manifest: %w", err)
	}

	type key struct{ service, typ string }
	type candidateChoice struct {
		candidate researchCandidate
		score     int
	}
	grouped := make(map[key]map[string]candidateChoice)
	var reportLines []string
	for _, c := range candidates {
		c.Service = strings.TrimSpace(c.Service)
		c.Type = strings.TrimSpace(c.Type)
		c.Value = strings.TrimSpace(c.Value)
		if c.Type != "user" && c.Type != "password" {
			reportLines = append(reportLines, fmt.Sprintf("- rejected %s/%s %q: invalid type", c.Service, c.Type, c.Value))
			continue
		}
		if isJunkValue(c.Value) {
			reportLines = append(reportLines, fmt.Sprintf("- rejected %s/%s %q: junk value", c.Service, c.Type, c.Value))
			continue
		}
		score := scoreCandidate(c)
		if score < mergeScoreThreshold {
			reportLines = append(reportLines, fmt.Sprintf("- rejected %s/%s %q: score %d below threshold %d", c.Service, c.Type, c.Value, score, mergeScoreThreshold))
			continue
		}
		k := key{c.Service, c.Type}
		if grouped[k] == nil {
			grouped[k] = make(map[string]candidateChoice)
		}
		if prev, ok := grouped[k][c.Value]; !ok || score > prev.score {
			grouped[k][c.Value] = candidateChoice{candidate: c, score: score}
		}
	}

	var totalAdded int

	for k, choices := range grouped {
		resolved, err := m.ResolveService(k.service)
		if err != nil {
			pterm.Warning.Printfln("Skipping %s/%s: %v", k.service, k.typ, err)
			reportLines = append(reportLines, fmt.Sprintf("- rejected %s/%s: %v", k.service, k.typ, err))
			continue
		}

		// Determine the override file path
		var overridePath string
		var overrideRef string
		needsManifestRef := false
		var refs []string
		if k.typ == "user" {
			refs = resolved.Users
		} else if k.typ == "password" {
			refs = resolved.Passwords
		}
		if len(refs) == 0 {
			reportLines = append(reportLines, fmt.Sprintf("- rejected %s/%s: no manifest refs", k.service, k.typ))
			continue
		}

		// Find an existing override file, or create one
		for _, ref := range refs {
			if strings.HasPrefix(ref, "overrides/") {
				overrideRef = ref
				overridePath = filepath.Join("wordlist", ref)
				break
			}
		}
		if overridePath == "" {
			var filename string
			if k.typ == "user" {
				filename = "user.txt"
			} else {
				filename = "password.txt"
			}
			overrideRef = filepath.ToSlash(filepath.Join("overrides", k.service, filename))
			overridePath = filepath.Join("wordlist", overrideRef)
			needsManifestRef = true
		}

		existing := make(map[string]struct{})
		if resolvedEntries, err := m.LoadWordlist(refs, "wordlist"); err == nil {
			for _, line := range resolvedEntries {
				existing[line] = struct{}{}
			}
		} else {
			return fmt.Errorf("loading existing %s/%s wordlist: %w", k.service, k.typ, err)
		}
		needsLeadingNewline := false
		if content, err := os.ReadFile(overridePath); err == nil {
			needsLeadingNewline = len(content) > 0 && content[len(content)-1] != '\n'
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					existing[line] = struct{}{}
				}
			}
		}

		var selected []candidateChoice
		for _, choice := range choices {
			selected = append(selected, choice)
		}
		sort.Slice(selected, func(i, j int) bool {
			return selected[i].candidate.Value < selected[j].candidate.Value
		})

		var newEntries []string
		for _, choice := range selected {
			v := choice.candidate.Value
			if _, exists := existing[v]; exists {
				reportLines = append(reportLines, fmt.Sprintf("- rejected %s/%s %q: already present", k.service, k.typ, v))
				continue
			}
			existing[v] = struct{}{}
			newEntries = append(newEntries, v)
			reportLines = append(reportLines, fmt.Sprintf("- accepted %s/%s %q: score %d product=%q source=%q", k.service, k.typ, v, choice.score, choice.candidate.Product, choice.candidate.Source))
		}

		if len(newEntries) == 0 {
			continue
		}
		if needsManifestRef {
			if err := ensureManifestRef(manifestPath, k.service, k.typ, overrideRef); err != nil {
				return err
			}
		}

		// Append new entries to the file
		if err := os.MkdirAll(filepath.Dir(overridePath), 0755); err != nil {
			return err
		}

		f, err := os.OpenFile(overridePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("opening %s: %w", overridePath, err)
		}
		if needsLeadingNewline {
			if _, err := fmt.Fprintln(f); err != nil {
				_ = f.Close()
				return fmt.Errorf("writing %s: %w", overridePath, err)
			}
		}
		for _, entry := range newEntries {
			if _, err := fmt.Fprintln(f, entry); err != nil {
				_ = f.Close()
				return fmt.Errorf("writing %s: %w", overridePath, err)
			}
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("closing %s: %w", overridePath, err)
		}

		totalAdded += len(newEntries)
		pterm.FgLightCyan.Printf("  %-12s ", k.service)
		fmt.Printf("+%d %ss\n", len(newEntries), k.typ)
	}

	if err := writeCandidateReport(reportLines); err != nil {
		return err
	}

	pterm.Success.Printfln("Merged %d new entries from candidates", totalAdded)
	return nil
}

func writeCandidateReport(lines []string) error {
	sort.Strings(lines)
	reportPath := filepath.Join("wordlist", "_candidates_report.md")
	if err := os.MkdirAll(filepath.Dir(reportPath), 0755); err != nil {
		return err
	}
	content := "# Wordlist Candidate Merge Report\n"
	if len(lines) > 0 {
		content += "\n" + strings.Join(lines, "\n") + "\n"
	}
	return os.WriteFile(reportPath, []byte(content), 0644)
}

func ensureManifestRef(manifestPath, service, typ, ref string) error {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("reading manifest: %w", err)
	}
	text := string(data)
	lines := strings.Split(text, "\n")

	serviceStart := -1
	servicePrefix := "  " + service + ":"
	for i, line := range lines {
		if strings.HasPrefix(line, servicePrefix) {
			serviceStart = i
			break
		}
	}
	if serviceStart < 0 {
		return fmt.Errorf("service %q not found in manifest", service)
	}

	serviceEnd := len(lines)
	for i := serviceStart + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "  ") && !strings.HasPrefix(lines[i], "    ") && strings.TrimSpace(lines[i]) != "" {
			serviceEnd = i
			break
		}
	}

	for i := serviceStart; i < serviceEnd; i++ {
		if strings.Contains(lines[i], ref) {
			return nil
		}
	}

	field := typ + "s"
	fieldLine := -1
	for i := serviceStart + 1; i < serviceEnd; i++ {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), field+":") {
			fieldLine = i
			break
		}
	}
	if fieldLine < 0 {
		return fmt.Errorf("service %q has no %s field in manifest", service, field)
	}

	quotedRef := fmt.Sprintf("%q", ref)
	if closeIdx := strings.LastIndex(lines[fieldLine], "]"); closeIdx >= 0 {
		prefix := lines[fieldLine][:closeIdx]
		suffix := lines[fieldLine][closeIdx:]
		separator := ", "
		if strings.HasSuffix(strings.TrimSpace(prefix), "[") {
			separator = ""
		}
		lines[fieldLine] = prefix + separator + quotedRef + suffix
	} else {
		insertAt := fieldLine + 1
		for insertAt < serviceEnd && strings.HasPrefix(strings.TrimSpace(lines[insertAt]), "- ") {
			insertAt++
		}
		entry := "      - " + ref
		lines = append(lines[:insertAt], append([]string{entry}, lines[insertAt:]...)...)
	}

	if err := os.WriteFile(manifestPath, []byte(strings.Join(lines, "\n")), 0644); err != nil {
		return fmt.Errorf("writing manifest: %w", err)
	}
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
