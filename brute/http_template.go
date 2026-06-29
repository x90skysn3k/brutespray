package brute

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

func init() { Register("http-template", BruteHTTPTemplate) }

// BruteHTTPTemplate executes a safe declarative HTTP auth template.
func BruteHTTPTemplate(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	tpl, err := loadAuthTemplate(params)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}
	client := http.DefaultClient
	if cm != nil && cm.SharedHTTPClient != nil {
		client = cm.SharedHTTPClient
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	baseURL := tpl.Transport + "://" + hostPort(host, port)
	connected := false
	for _, step := range tpl.Steps {
		body := renderTemplateValue(step.Request.Body, host, port, user, password)
		req, err := http.NewRequestWithContext(ctx, step.Request.Method, baseURL+step.Request.Path, strings.NewReader(body))
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: connected, Error: err}
		}
		for key, value := range step.Request.Headers {
			req.Header.Set(key, renderTemplateValue(value, host, port, user, password))
		}
		resp, err := client.Do(req)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: connected, Error: err}
		}
		connected = true
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if !matchTemplateStep(step, resp.StatusCode, string(data)) {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true}
		}
	}
	return &BruteResult{AuthSuccess: true, ConnectionSuccess: true, Proof: Proof{ProofType: ProofHTTPMatcher, Confidence: ConfidenceConfirmed, Detail: tpl.ID}}
}

func loadAuthTemplate(params ModuleParams) (modules.AuthTemplate, error) {
	if inline := params["template-inline"]; inline != "" {
		return modules.ParseAuthTemplate([]byte(inline))
	}
	path := params["template"]
	if path == "" {
		return modules.AuthTemplate{}, fmt.Errorf("template or template-inline module parameter is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return modules.AuthTemplate{}, err
	}
	return modules.ParseAuthTemplate(data)
}

func matchTemplateStep(step modules.AuthTemplateStep, status int, body string) bool {
	for _, matcher := range step.Matchers {
		switch matcher.Type {
		case "status":
			matched := false
			for _, want := range matcher.Status {
				if status == want {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		case "body_contains":
			if !strings.Contains(body, matcher.Body) {
				return false
			}
		case "body_not_contains":
			if strings.Contains(body, matcher.Body) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func renderTemplateValue(value string, host string, port int, user string, password string) string {
	replacer := strings.NewReplacer(
		"{{host}}", host,
		"{{port}}", strconv.Itoa(port),
		"{{username}}", user,
		"{{password}}", password,
	)
	return replacer.Replace(value)
}

func hostPort(host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]:" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port)
}
