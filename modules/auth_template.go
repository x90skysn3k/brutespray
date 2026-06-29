package modules

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// AuthTemplate is a safe declarative HTTP authentication workflow.
type AuthTemplate struct {
	ID        string             `yaml:"id" json:"id"`
	Service   string             `yaml:"service" json:"service"`
	Transport string             `yaml:"transport" json:"transport"`
	Steps     []AuthTemplateStep `yaml:"steps" json:"steps"`
}

// AuthTemplateStep is one request/match step.
type AuthTemplateStep struct {
	Request  AuthTemplateRequest   `yaml:"request" json:"request"`
	Matchers []AuthTemplateMatcher `yaml:"matchers" json:"matchers"`
}

// AuthTemplateRequest describes one HTTP request.
type AuthTemplateRequest struct {
	Method  string            `yaml:"method" json:"method"`
	Path    string            `yaml:"path" json:"path"`
	Headers map[string]string `yaml:"headers" json:"headers,omitempty"`
	Body    string            `yaml:"body" json:"body,omitempty"`
}

// AuthTemplateMatcher describes success/failure checks.
type AuthTemplateMatcher struct {
	Type   string `yaml:"type" json:"type"`
	Status []int  `yaml:"status" json:"status,omitempty"`
	Body   string `yaml:"body" json:"body,omitempty"`
}

// ParseAuthTemplate parses and validates a safe auth template.
func ParseAuthTemplate(data []byte) (AuthTemplate, error) {
	var tpl AuthTemplate
	if err := yaml.Unmarshal(data, &tpl); err != nil {
		return AuthTemplate{}, fmt.Errorf("parsing auth template: %w", err)
	}
	if tpl.ID == "" {
		return AuthTemplate{}, fmt.Errorf("template id is required")
	}
	transport := strings.ToLower(strings.TrimSpace(tpl.Transport))
	if transport == "" {
		transport = "http"
	}
	if transport != "http" && transport != "https" {
		return AuthTemplate{}, fmt.Errorf("unsupported template transport %q", tpl.Transport)
	}
	tpl.Transport = transport
	if len(tpl.Steps) == 0 {
		return AuthTemplate{}, fmt.Errorf("template requires at least one step")
	}
	for i := range tpl.Steps {
		method := strings.ToUpper(strings.TrimSpace(tpl.Steps[i].Request.Method))
		if method == "" {
			method = "GET"
		}
		switch method {
		case "GET", "POST", "PUT", "PATCH", "DELETE":
		default:
			return AuthTemplate{}, fmt.Errorf("unsupported method %q", method)
		}
		tpl.Steps[i].Request.Method = method
		if tpl.Steps[i].Request.Path == "" || !strings.HasPrefix(tpl.Steps[i].Request.Path, "/") {
			return AuthTemplate{}, fmt.Errorf("step %d path must start with /", i+1)
		}
		if len(tpl.Steps[i].Matchers) == 0 {
			return AuthTemplate{}, fmt.Errorf("step %d requires at least one matcher", i+1)
		}
		for j := range tpl.Steps[i].Matchers {
			matcherType := strings.ToLower(strings.TrimSpace(tpl.Steps[i].Matchers[j].Type))
			switch matcherType {
			case "status", "body_contains", "body_not_contains":
				tpl.Steps[i].Matchers[j].Type = matcherType
			default:
				return AuthTemplate{}, fmt.Errorf("step %d has unsupported matcher %q", i+1, tpl.Steps[i].Matchers[j].Type)
			}
			if matcherType == "status" && len(tpl.Steps[i].Matchers[j].Status) == 0 {
				return AuthTemplate{}, fmt.Errorf("step %d status matcher requires status codes", i+1)
			}
			if matcherType != "status" && tpl.Steps[i].Matchers[j].Body == "" {
				return AuthTemplate{}, fmt.Errorf("step %d body matcher requires body text", i+1)
			}
		}
	}
	return tpl, nil
}
