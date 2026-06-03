package brutespray

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsJunkValue(t *testing.T) {
	junk := []string{
		"", " ", "x", "<password>", "<USERNAME>", "username", "Password",
		"none", "N/A", "redacted", "***", "unknown", "default",
		"has space", "tab\tinside", strings.Repeat("a", 65), "your_password",
	}
	for _, v := range junk {
		if !isJunkValue(v) {
			t.Errorf("isJunkValue(%q) = false, want true", v)
		}
	}

	valid := []string{
		"admin", "root", "Cisco123", "P@ssw0rd!", "ubnt", "raspberry",
		"sap*", "default123", "Wg@2026", "manager",
	}
	for _, v := range valid {
		if isJunkValue(v) {
			t.Errorf("isJunkValue(%q) = true, want false", v)
		}
	}
}

func TestLooksComplex(t *testing.T) {
	complex := []string{"Cisco123", "P@ssw0rd", "Admin1", "ubnt2026", "sap*"}
	for _, v := range complex {
		if !looksComplex(v) {
			t.Errorf("looksComplex(%q) = false, want true", v)
		}
	}
	simple := []string{"admin", "root", "password", "ADMIN", "123456"}
	for _, v := range simple {
		if looksComplex(v) {
			t.Errorf("looksComplex(%q) = true, want false", v)
		}
	}
}

func TestScoreCandidate(t *testing.T) {
	tests := []struct {
		name string
		c    researchCandidate
		want int
	}{
		{
			name: "url source + specific product + complex value",
			c:    researchCandidate{Value: "Cisco123", Product: "Cisco IOS 15", Source: "https://cisco.com/docs"},
			want: 4, // +2 url, +1 product, +1 complex
		},
		{
			name: "url source + plain value + vague product",
			c:    researchCandidate{Value: "admin", Product: "router", Source: "https://example.com"},
			want: 2, // +2 url only
		},
		{
			name: "non-url source + specific product",
			c:    researchCandidate{Value: "admin", Product: "Dahua DVR", Source: "vendor manual"},
			want: 2, // +1 source, +1 product
		},
		{
			name: "breach source penalised below threshold",
			c:    researchCandidate{Value: "Hunter2!", Product: "Acme 9000", Source: "https://pastebin.com/leak dump"},
			want: 1, // +2 url +1 product +1 complex -3 disallowed = 1 (< threshold)
		},
		{
			name: "bare value no attribution",
			c:    researchCandidate{Value: "admin", Product: "", Source: ""},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scoreCandidate(tt.c); got != tt.want {
				t.Errorf("scoreCandidate(%+v) = %d, want %d", tt.c, got, tt.want)
			}
		})
	}
}

// TestScoreThresholdGate documents the effective admission rule: a candidate
// needs a real URL source plus one more signal, OR a non-URL source with both a
// specific product and a complex value, to reach mergeScoreThreshold.
func TestScoreThresholdGate(t *testing.T) {
	pass := researchCandidate{Value: "Cisco123", Product: "Cisco IOS", Source: "https://cisco.com/docs"}
	if scoreCandidate(pass) < mergeScoreThreshold {
		t.Errorf("well-sourced candidate scored %d, below threshold %d", scoreCandidate(pass), mergeScoreThreshold)
	}
	fail := researchCandidate{Value: "admin", Product: "router", Source: "vendor docs"}
	if scoreCandidate(fail) >= mergeScoreThreshold {
		t.Errorf("weak candidate scored %d, at/above threshold %d", scoreCandidate(fail), mergeScoreThreshold)
	}
}

func TestCmdSeasonalGuaranteesPatterns(t *testing.T) {
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	if err := cmdSeasonal(); err != nil {
		t.Fatalf("cmdSeasonal: %v", err)
	}

	data, err := os.ReadFile(filepath.Join("wordlist", "_base", "passwords-seasonal.txt"))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	got := make(map[string]struct{})
	for _, line := range strings.Split(string(data), "\n") {
		got[line] = struct{}{}
	}

	// Year-less corp-word variants are always present regardless of the year.
	for _, want := range []string{"Welcome1", "Welcome123", "Welcome123!", "Password123!", "Changeme123!"} {
		if _, ok := got[want]; !ok {
			t.Errorf("seasonal output missing guaranteed pattern %q", want)
		}
	}
}

func TestCmdSeasonalUsesManifestRange(t *testing.T) {
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	writeFile(t, filepath.Join("wordlist", "manifest.yaml"), `seasonal_range: [2030, 2030]
bases:
  seasonal_passwords: "_base/passwords-seasonal.txt"
services: {}
`)

	if err := cmdSeasonal(); err != nil {
		t.Fatalf("cmdSeasonal: %v", err)
	}

	data, err := os.ReadFile(filepath.Join("wordlist", "_base", "passwords-seasonal.txt"))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	if !strings.Contains(string(data), "Winter2030!") || !strings.Contains(string(data), "January2030!") {
		t.Fatalf("seasonal output did not use manifest range 2030: %s", data)
	}
}

func TestCmdSeasonalRejectsMalformedManifest(t *testing.T) {
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	writeFile(t, filepath.Join("wordlist", "manifest.yaml"), `seasonal_range: [`)

	if err := cmdSeasonal(); err == nil {
		t.Fatal("cmdSeasonal succeeded with malformed manifest, want error")
	}
}

func TestCmdValidateRejectsCircularAliases(t *testing.T) {
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	writeFile(t, filepath.Join("wordlist", "manifest.yaml"), `services:
  ssh:
    alias: telnet
  telnet:
    alias: ssh
`)

	if err := cmdValidate(); err == nil {
		t.Fatal("cmdValidate succeeded with circular aliases, want error")
	}
}

func TestResearchLLMConfigDefaultsToOllamaLegacy(t *testing.T) {
	clearResearchEnv(t)

	cfg := researchLLMConfigFromEnv()

	if cfg.Provider != "ollama" {
		t.Fatalf("Provider = %q, want ollama", cfg.Provider)
	}
	if cfg.Model != "qwen3:14b" {
		t.Fatalf("Model = %q, want qwen3:14b", cfg.Model)
	}
	if cfg.BaseURL != "http://localhost:11434" {
		t.Fatalf("BaseURL = %q, want http://localhost:11434", cfg.BaseURL)
	}
}

func TestResearchLLMConfigPreservesOllamaEnv(t *testing.T) {
	clearResearchEnv(t)
	t.Setenv("OLLAMA_MODEL", "legacy-model")
	t.Setenv("OLLAMA_URL", "http://ollama.local:11434/")

	cfg := researchLLMConfigFromEnv()

	if cfg.Provider != "ollama" {
		t.Fatalf("Provider = %q, want ollama", cfg.Provider)
	}
	if cfg.Model != "legacy-model" {
		t.Fatalf("Model = %q, want legacy-model", cfg.Model)
	}
	if cfg.BaseURL != "http://ollama.local:11434" {
		t.Fatalf("BaseURL = %q, want trimmed legacy URL", cfg.BaseURL)
	}
}

func TestResearchLLMConfigPrefersGenericEnv(t *testing.T) {
	clearResearchEnv(t)
	t.Setenv("OLLAMA_MODEL", "legacy-model")
	t.Setenv("OLLAMA_URL", "http://ollama.local:11434")
	t.Setenv("WORDLIST_RESEARCH_PROVIDER", "openai")
	t.Setenv("WORDLIST_RESEARCH_MODEL", "served-model")
	t.Setenv("WORDLIST_RESEARCH_URL", "http://ai.tiden.local:8000/")

	cfg := researchLLMConfigFromEnv()

	if cfg.Provider != "openai" {
		t.Fatalf("Provider = %q, want openai", cfg.Provider)
	}
	if cfg.Model != "served-model" {
		t.Fatalf("Model = %q, want served-model", cfg.Model)
	}
	if cfg.BaseURL != "http://ai.tiden.local:8000" {
		t.Fatalf("BaseURL = %q, want trimmed generic URL", cfg.BaseURL)
	}
}

func TestQueryOllamaPostsGenerate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/generate" {
			t.Fatalf("path = %s, want /api/generate", r.URL.Path)
		}
		var req ollamaRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Model != "qwen" || req.Prompt != "prompt text" || req.Stream {
			t.Fatalf("request = %+v, want model qwen prompt and stream false", req)
		}
		_, _ = io.WriteString(w, `{"response":"[{\"product\":\"Router\"}]"}`)
	}))
	defer server.Close()

	got, err := queryOllama(server.URL+"/", "qwen", "prompt text")
	if err != nil {
		t.Fatalf("queryOllama: %v", err)
	}
	if got != `[{"product":"Router"}]` {
		t.Fatalf("response = %q, want JSON array", got)
	}
}

func TestQueryOpenAICompatiblePostsChatCompletions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("path = %s, want /v1/chat/completions", r.URL.Path)
		}
		var req openAIChatCompletionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Model != "served-model" || req.Stream || len(req.Messages) != 1 {
			t.Fatalf("request = %+v, want one non-streaming message", req)
		}
		if req.Messages[0].Role != "user" || req.Messages[0].Content != "prompt text" {
			t.Fatalf("message = %+v, want user prompt", req.Messages[0])
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"[{\"product\":\"Camera\"}]"}}]}`)
	}))
	defer server.Close()

	got, err := queryOpenAICompatible(server.URL+"/", "served-model", "prompt text")
	if err != nil {
		t.Fatalf("queryOpenAICompatible: %v", err)
	}
	if got != `[{"product":"Camera"}]` {
		t.Fatalf("response = %q, want JSON array", got)
	}
}

func TestQueryResearchLLMRejectsUnknownProvider(t *testing.T) {
	_, err := queryResearchLLM(researchLLMConfig{Provider: "bad", Model: "m", BaseURL: "http://example.com"}, "prompt")
	if err == nil {
		t.Fatal("queryResearchLLM succeeded with unknown provider, want error")
	}
	if !strings.Contains(err.Error(), "unknown wordlist research provider") {
		t.Fatalf("error = %q, want unknown provider message", err)
	}
}

func clearResearchEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"WORDLIST_RESEARCH_PROVIDER",
		"WORDLIST_RESEARCH_MODEL",
		"WORDLIST_RESEARCH_URL",
		"OLLAMA_MODEL",
		"OLLAMA_URL",
	} {
		t.Setenv(key, "")
	}
}
