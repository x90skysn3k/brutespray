# BruteSpray 2.7.x Patch Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the existing BruteSpray 2.7.x evidence, plan, checkpoint/session, descriptor/help, parser-normalization, and documentation surfaces without adding content discovery or feature-expansion work.

**Architecture:** Build on the existing `modules.EvidenceConfig`, dry-run plan, checkpoint/session, service descriptor, and parser normalization systems. Each task adds behavior-defending tests first, then applies the smallest production/doc change needed to make the tests pass.

**Tech Stack:** Go 1.26.1, standard `testing` package, stdlib flag/config patterns, existing BruteSpray modules, no new dependencies.

## Global Constraints

- Target release is `2.7.x`; bump `2.7.1` to `2.7.2` exactly once only after implementation changes pass verification.
- No content discovery, directory brute force, path fuzzing, recursion, extension guessing, soft-404 calibration, crawler behavior, or `brutespray content` command/docs.
- No TUI search/filter implementation, no new findings dashboard, no auth-template feature expansion, no new planner UI.
- Build on existing scaffolding: `modules/evidence.go`, `brutespray/plan.go`, `modules/checkpoint.go`, `modules/sessionlog.go`, `modules/service_descriptor.go`, and `brutespray/module_help.go`.
- Tests use the standard Go `testing` package only.
- Preserve intentional plaintext operational success artifacts unless an existing test/doc contract says otherwise.
- Unsupported scanner services must still fail closed.

---

## File Map

- `modules/output_test.go` — add/strengthen tests for evidence-mode JSON and write/error secrecy.
- `modules/output.go` — narrow fixes only if tests expose a leak in JSON/error/shareable paths.
- `modules/evidence_test.go` — add tests documenting mode semantics if missing.
- `brutespray/plan_test.go` and `brutespray/plan_command_test.go` — add acknowledgement failure/success coverage and hash stability coverage.
- `brutespray/config_test.go` — add `.jsonl` resume path normalization test if no existing coverage.
- `modules/checkpoint_test.go` and `modules/sessionlog_test.go` — add permissions/malformed input tests.
- `brutespray/module_help_test.go` — add alias/stability/param metadata tests.
- `brutespray/module_help.go` — narrow alias/help rendering fixes only.
- `modules/service_descriptor.go` — add metadata for runtime-supported params only.
- `modules/service_descriptor_test.go` and `brute/registry_descriptor_test.go` — add descriptor parity/coverage assertions.
- `modules/parse_stream_test.go`, `modules/parse_masscan_test.go`, and parser-specific tests — add scanner alias normalization tests.
- `modules/parse.go`, `modules/parse_stream.go`, `modules/service_lookup.go` — narrow parser/lookup fixes only if tests fail.
- `docs/output.md`, `docs/advanced.md`, `docs/services.md`, `docs/usage.md`, `README.md`, `brutespray/config.go` — documentation/version updates.

---

### Task 1: Evidence and Output Secrecy Patch

**Files:**
- Test: `modules/output_test.go`
- Test: `modules/evidence_test.go`
- Modify if needed: `modules/output.go`
- Docs later in Task 6: `docs/output.md`, `docs/advanced.md`

**Interfaces:**
- Consumes: `modules.EvidenceConfig.RenderSecret(secret string) (display string, digest string, redacted bool)`.
- Consumes: `modules.SetEvidenceConfig(cfg EvidenceConfig)` and `modules.GetEvidenceConfig()`.
- Produces: Regression tests proving JSON attempts and write/error paths do not leak raw credentials under evidence modes.

- [ ] **Step 1: Add failing/coverage tests for JSON evidence output**

Add tests in `modules/output_test.go` that set `OutputFormatMode = "json"`, `NoColorMode = true`, and `SetEvidenceConfig(EvidenceConfig{Mode: EvidenceHash, HMACKey: []byte("engagement-key")})`, then call `PrintResult(...)` for a successful attempt with password `raw-evidence-secret-2f3b`. Assert:

```go
if strings.Contains(output, "raw-evidence-secret-2f3b") {
    t.Fatalf("raw password leaked in JSON evidence output: %s", output)
}
if !strings.Contains(output, "\"password\":\"[REDACTED]\"") {
    t.Fatalf("redacted password missing in JSON output: %s", output)
}
if !strings.Contains(output, "\"secret_hmac_sha256\":") {
    t.Fatalf("secret HMAC missing in JSON output: %s", output)
}
if !strings.Contains(output, "\"secret_redacted\":true") {
    t.Fatalf("secret_redacted flag missing in JSON output: %s", output)
}
```

- [ ] **Step 2: Add tests for invalid/default evidence semantics**

In `modules/evidence_test.go`, add table coverage that `EvidenceMode("bogus").Validate()` fails and `EvidenceConfig{Mode: ""}.RenderSecret("secret")` behaves like full mode. Expected default mode remains full for compatibility.

- [ ] **Step 3: Run evidence/output tests red or coverage-green**

Run:

```bash
go test ./modules -run 'TestEvidence|TestPrintResultJSON|TestPrintResultWriteError' -count=1
```

Expected:
- If current behavior is already correct, tests pass and no production change is needed.
- If a raw credential appears in JSON or write-error output, test fails before implementation.

- [ ] **Step 4: Apply minimal output fix only if a test fails**

If a failure shows a raw credential in JSON/error output, modify only `modules/output.go` at the path emitting that credential. Do not redact success files/checkpoints/session logs in this patch unless the failure is in that exact code path.

- [ ] **Step 5: Re-run focused tests**

Run:

```bash
go test ./modules -run 'TestEvidence|TestPrintResultJSON|TestPrintResultWriteError' -count=1
```

Expected: PASS.

---

### Task 2: Plan Acknowledgement and Resume Path Coverage

**Files:**
- Test: `brutespray/plan_test.go`
- Test: `brutespray/plan_command_test.go`
- Test: `brutespray/config_test.go`
- Modify if needed: `brutespray/plan_command.go`, `brutespray/config.go`

**Interfaces:**
- Consumes: `BuildExecutionPlan(cfg *Config, manifest EngagementManifest) (ExecutionPlan, error)`.
- Consumes: `ValidatePlanAcknowledgement(cfg *Config, plan ExecutionPlan) error`.
- Consumes: `ParseConfig()` path normalization for `-resume`.
- Produces: Regression coverage for hash acknowledgement and `.jsonl` resume normalization.

- [ ] **Step 1: Add plan acknowledgement tests**

In `brutespray/plan_command_test.go`, add:

```go
func TestValidatePlanAcknowledgementAcceptsMatchingHash(t *testing.T) {
    plan := ExecutionPlan{Hash: "abc123"}
    cfg := &Config{RequirePlanAck: "abc123"}
    if err := ValidatePlanAcknowledgement(cfg, plan); err != nil {
        t.Fatalf("ValidatePlanAcknowledgement: %v", err)
    }
}

func TestValidatePlanAcknowledgementRejectsMismatchedHash(t *testing.T) {
    plan := ExecutionPlan{Hash: "expected-hash"}
    cfg := &Config{RequirePlanAck: "wrong-hash"}
    err := ValidatePlanAcknowledgement(cfg, plan)
    if err == nil {
        t.Fatal("expected mismatched plan acknowledgement to fail")
    }
    msg := err.Error()
    if !strings.Contains(msg, "expected-hash") || !strings.Contains(msg, "wrong-hash") {
        t.Fatalf("error should include expected and supplied hashes, got %q", msg)
    }
}
```

Add `strings` import if needed.

- [ ] **Step 2: Strengthen hash stability if needed**

If `brutespray/plan_test.go` already covers host input order, leave it. If not, add a test that builds equivalent configs with reversed `Hosts` order and asserts equal hashes.

- [ ] **Step 3: Add `.jsonl` resume normalization test**

In `brutespray/config_test.go`, add a test around the existing ParseConfig test harness pattern. Set args equivalent to:

```text
brutespray -resume engagement-run.jsonl -H ssh://127.0.0.1:22 -u root -p toor --no-tui
```

Assert:

```go
if cfg.ResumeFile != "engagement-run.json" {
    t.Fatalf("ResumeFile = %q, want engagement-run.json", cfg.ResumeFile)
}
```

Use existing global flag/reset helpers in `config_test.go`; do not invent a second parser.

- [ ] **Step 4: Run focused brutespray tests**

Run:

```bash
go test ./brutespray -run 'TestValidatePlanAcknowledgement|TestBuildExecutionPlanHash|TestParseConfig.*Resume' -count=1
```

Expected: PASS after narrow fixes.

---

### Task 3: Checkpoint and Session Behavior Guardrails

**Files:**
- Test: `modules/checkpoint_test.go`
- Test: `modules/sessionlog_test.go`
- Modify if needed: `modules/checkpoint.go`, `modules/sessionlog.go`

**Interfaces:**
- Consumes: `NewCheckpoint(filePath string) *Checkpoint`.
- Consumes: `LoadCheckpoint(filePath string) (*Checkpoint, error)`.
- Consumes: `NewSessionLog(path string) (*SessionLog, error)`.
- Consumes: `LoadSessionLog(path string) ([]SessionEntry, error)`.
- Produces: Tests documenting permissions and malformed file behavior.

- [ ] **Step 1: Add malformed checkpoint test**

In `modules/checkpoint_test.go`, add:

```go
func TestLoadCheckpointRejectsMalformedJSON(t *testing.T) {
    path := filepath.Join(t.TempDir(), "checkpoint.json")
    if err := os.WriteFile(path, []byte(`{"completed_hosts":`), 0o600); err != nil {
        t.Fatalf("write malformed checkpoint: %v", err)
    }
    if _, err := LoadCheckpoint(path); err == nil {
        t.Fatal("expected malformed checkpoint to fail")
    }
}
```

Add imports only if absent.

- [ ] **Step 2: Add session log permissions/malformed-line behavior test**

In `modules/sessionlog_test.go`, add/strengthen tests for owner-only permissions after `NewSessionLog(path)`. If current `LoadSessionLog` intentionally skips malformed JSONL lines, add a test that documents that behavior using one good line, one malformed line, and one good line; assert two entries are returned. Do not change behavior unless the existing function contradicts docs.

- [ ] **Step 3: Run focused modules persistence tests**

Run:

```bash
go test ./modules -run 'TestCheckpoint|TestSessionLog|TestLoadCheckpoint|TestLoadSessionLog' -count=1
```

Expected: PASS after narrow fixes.

---

### Task 4: Descriptor, Module Help, and Alias Parity

**Files:**
- Test: `modules/service_descriptor_test.go`
- Test: `brute/registry_descriptor_test.go`
- Test: `brutespray/module_help_test.go`
- Modify: `modules/service_descriptor.go`
- Modify if needed: `brutespray/module_help.go`
- Modify if needed: `brutespray/config.go`

**Interfaces:**
- Consumes: `modules.ServiceDescriptors() map[string]ServiceDescriptor`.
- Consumes: `modules.DescriptorForService(service string) (ServiceDescriptor, bool)`.
- Consumes: `formatModuleHelp(service string) (string, error)`.
- Produces: Descriptor metadata for existing runtime params and parity tests preventing drift.

- [ ] **Step 1: Derive descriptor metadata tests from actual runtime params**

Before editing descriptors, inspect actual `params["..."]` / `params[...]` usage in `brute/*.go` with the built-in search tool. The current source scan observed these runtime keys, and the test should defend this set unless implementation-time source has changed:

```go
func TestServiceDescriptorsIncludeObservedRuntimeParams(t *testing.T) {
    cases := map[string][]string{
        "couchdb":       {"tls"},
        "elasticsearch": {"tls"},
        "ftp":           {"mode"},
        "http":          {"auth", "custom-header", "dir", "domain", "https", "method", "user-agent"},
        "https":         {"auth", "custom-header", "dir", "domain", "https", "method", "user-agent"},
        "http-form":     {"body", "content-type", "cookie", "csrf", "fail", "follow", "form-url", "https", "method", "success", "url", "user-agent"},
        "https-form":    {"body", "content-type", "cookie", "csrf", "fail", "follow", "form-url", "https", "method", "success", "url", "user-agent"},
        "http-template": {"template", "template-inline"},
        "imap":          {"auth"},
        "influxdb":      {"mode", "tls"},
        "mssql":         {"domain"},
        "mysql":         {"dbname"},
        "pop3":          {"auth"},
        "postgres":      {"dbname"},
        "rdp":           {"domain"},
        "redis":         {"db"},
        "rexec":         {"cmd"},
        "rlogin":        {"local-user", "terminal"},
        "rsh":           {"cmd", "local-user"},
        "smbnt":         {"domain", "pass"},
        "smtp":          {"auth", "domain", "ehlo"},
        "smtp-vrfy":     {"domain", "verb"},
        "snmp":          {"auth", "mode", "priv", "privpass", "version"},
        "ssh":           {"auth", "key"},
        "svn":           {"https", "path"},
        "telnet":        {"success"},
        "vnc":           {"maxsleep"},
        "wrapper":       {"cmd"},
    }
    descriptors := ServiceDescriptors()
    for service, params := range cases {
        desc, ok := descriptors[service]
        if !ok {
            t.Fatalf("descriptor missing for %s", service)
        }
        have := map[string]bool{}
        for _, p := range desc.Params {
            have[p.Name] = true
        }
        for _, want := range params {
            if !have[want] {
                t.Fatalf("descriptor %s missing observed runtime param %s", service, want)
            }
        }
    }
}
```

If implementation-time source usage differs, update the test from the fresh source scan and state the reason in the task summary.

- [ ] **Step 2: Add module-help alias/backing test**

In `brutespray/module_help_test.go`, add a test that canonical service help works and alias help resolves only through descriptors backed by registered modules. If no aliases are currently populated, assert the function does not accept unsupported aliases such as `pcanywheredata`.

- [ ] **Step 3: Add beta/stability parity test**

In `brutespray/config_test.go` or a new brutespray test file, compare `BetaServiceList` with descriptors whose `Stability == modules.ServiceBeta`. Assert no beta service is missing from either side. Do not derive `BetaServiceList` from descriptors in this patch unless the test fails and the change is smaller than maintaining duplicates.

- [ ] **Step 4: Implement descriptor param metadata**

In `modules/service_descriptor.go`, add `ParamDescriptor` entries only for params proven by the source scan in Step 1 and already supported at runtime. Keep descriptions short and factual. Do not add descriptors for planned, guessed, or content-discovery-related params.

- [ ] **Step 5: Run descriptor/help tests**

Run:

```bash
go test ./modules -run 'TestServiceDescriptor|TestDescriptor' -count=1
go test ./brutespray -run 'TestFormatModuleHelp|TestBetaServiceList' -count=1
go test ./brute -run 'TestRegistryDescriptor' -count=1
```

Expected: PASS.

---

### Task 5: Scanner Alias Normalization Guardrails

**Files:**
- Test: `modules/parse_stream_test.go`
- Test: `modules/parse_masscan_test.go`
- Test: `modules/target_parser_test.go` or existing parser test file if more appropriate
- Modify if needed: `modules/parse.go`, `modules/parse_stream.go`, `modules/service_lookup.go`

**Interfaces:**
- Consumes: `modules.MapService(service string) string` if exported, or existing parser normalization helper.
- Consumes: existing `ParseStream`/file-parser entry points.
- Produces: Tests proving accepted scanner aliases normalize to registered service names and unsupported services fail closed.

- [ ] **Step 1: Add stream alias tests for existing formats**

In `modules/parse_stream_test.go`, add tests for Nerva/fingerprintx-style inputs that currently carry service names. Use aliases already present in `modules/parse.go` such as `ms-wbt-server` for RDP or `microsoft-ds` for SMB if the parser accepts those service strings. Assert parsed hosts use canonical service names.

- [ ] **Step 2: Add unsupported service guard test**

Add a parser test that feeds an unsupported scanner service string and asserts it is rejected or omitted according to the parser’s current contract. Do not add support for unsupported services.

- [ ] **Step 3: Fix normalization only where tests prove drift**

If stream parser paths pass service strings through raw, normalize through the same existing mapping used by file parsers. Do not add new aliases except aliases already present in the map.

- [ ] **Step 4: Run parser tests**

Run:

```bash
go test ./modules -run 'TestParseStream|TestParseMasscan|TestParseFile|TestMapService' -count=1
```

Expected: PASS.

---

### Task 6: Documentation and Version Patch

**Files:**
- Modify: `docs/output.md`
- Modify: `docs/advanced.md`
- Modify: `docs/services.md`
- Modify: `docs/usage.md`
- Modify: `README.md`
- Modify: `brutespray/config.go`

**Interfaces:**
- Consumes: behavior established by Tasks 1-5.
- Produces: User-facing docs that match actual 2.7.x behavior and a single version bump to `2.7.2`.

- [ ] **Step 1: Update evidence docs**

In `docs/output.md`, document that JSON attempt output honors evidence mode and that credential-bearing operational artifacts may include success files, checkpoints, session logs, summaries, and generated scripts. State that `encrypted` is reserved and currently redacts in JSON output.

- [ ] **Step 2: Update plan/checkpoint docs**

In `docs/advanced.md` and `docs/usage.md`, ensure `--dry-run`, `--plan-out`, `--require-plan-ack`, `--resume`, and `--checkpoint` examples match current behavior. Include that passing `.jsonl` to `-resume` resolves to the checkpoint `.json` path.

- [ ] **Step 3: Update auth-template docs without feature expansion**

In `docs/services.md`, clarify that `http-template` is a fixed-step auth workflow and does not crawl, recurse, discover paths, execute shell commands, or brute-force directories.

- [ ] **Step 4: Bump version once**

In `brutespray/config.go`, change:

```go
var version = "2.7.1"
```

to:

```go
var version = "2.7.2"
```

Update README version/badge text from `2.7.1` to `2.7.2` if present.

- [ ] **Step 5: Run doc/version checks**

Run focused grep with the built-in search tool, not shell grep, for forbidden terms and stale versions:

- Search docs and README for `brutespray content`.
- Search docs and README for `directory brute`.
- Search docs and README for stale `2.7.1` references that should now be `2.7.2`.

Expected: no content-discovery additions; no stale visible release version where the current release is intended.

---

### Task 7: Final Verification, Review, Commit, and Push

**Files:**
- No new production code unless review finds a blocking bug.
- Commit all intended files explicitly.

**Interfaces:**
- Consumes: all previous tasks.
- Produces: pushed `dev` commit for `2.7.2` patch hardening.

- [ ] **Step 1: Run focused tests**

Run:

```bash
go test ./modules -run 'Evidence|Output|Checkpoint|Session|Descriptor|Parse' -count=1
go test ./brutespray -run 'Plan|Engagement|ModuleHelp|Config|Resume' -count=1
go test ./brute -run 'TestRegistryDescriptor' -count=1
```

Expected: PASS.

- [ ] **Step 2: Run full gates**

Run:

```bash
make lint
go test ./... -count=1 -race
go vet ./...
go build ./...
```

Expected: PASS; `make lint` reports `0 issues`.

- [ ] **Step 3: Request read-only review**

Request reviewers to verify:

- no content discovery scope leaked in;
- no feature expansion slipped into the patch;
- evidence/redaction behavior is explicit;
- descriptor/help metadata reflects existing runtime behavior only;
- tests defend behavior.

- [ ] **Step 4: Address review findings with tests first**

For any blocking finding, add or adjust a failing test first, verify it fails, apply the smallest fix, then re-run focused and full gates.

- [ ] **Step 5: Commit intended files explicitly**

Before committing, check status and avoid unrelated untracked files. Stage explicit intended paths only, e.g.:

```bash
git add README.md docs/output.md docs/advanced.md docs/services.md docs/usage.md brutespray/*.go modules/*.go brute/*.go
```

Do not stage unrelated untracked files such as local scan outputs, tool directories, or agent harness folders.

Commit:

```bash
git commit -m "Harden 2.7 patch behavior"
```

- [ ] **Step 6: Push dev**

Run:

```bash
git push origin dev
```

Expected: push succeeds.
