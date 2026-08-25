package modules

import "testing"

func TestAuthTemplateParsesHTTPJSONLogin(t *testing.T) {
	input := []byte(`
id: json-login
service: http-template
transport: http
steps:
  - request:
      method: POST
      path: /login
      headers:
        content-type: application/json
      body: '{"username":"{{username}}","password":"{{password}}"}'
    matchers:
      - type: status
        status: [200]
`)
	tpl, err := ParseAuthTemplate(input)
	if err != nil {
		t.Fatalf("ParseAuthTemplate: %v", err)
	}
	if tpl.ID != "json-login" || tpl.Steps[0].Request.Method != "POST" || tpl.Steps[0].Matchers[0].Status[0] != 200 {
		t.Fatalf("template = %+v", tpl)
	}
}

func TestAuthTemplateRejectsShellTransport(t *testing.T) {
	input := []byte(`id: bad
service: http-template
transport: shell
steps: []
`)
	if _, err := ParseAuthTemplate(input); err == nil {
		t.Fatal("expected shell transport rejection")
	}
}

func TestAuthTemplateRequiresStepAndMatcher(t *testing.T) {
	if _, err := ParseAuthTemplate([]byte(`id: empty
transport: http
steps: []
`)); err == nil {
		t.Fatal("expected empty template rejection")
	}
	if _, err := ParseAuthTemplate([]byte(`id: no-matcher
transport: http
steps:
  - request:
      path: /login
`)); err == nil {
		t.Fatal("expected missing matcher rejection")
	}
	if _, err := ParseAuthTemplate([]byte(`id: bad-matcher
transport: http
steps:
  - request:
      path: /login
    matchers:
      - type: shell
`)); err == nil {
		t.Fatal("expected unknown matcher rejection")
	}
}
