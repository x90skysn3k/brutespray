# BruteSpray 2.7.x Patch Hardening Design

## Goal

Ship a conservative BruteSpray `2.7.x` patch release that hardens behavior already present in `2.7.1` without adding new feature surfaces. The patch improves trust in evidence handling, plan acknowledgement, checkpoint/session behavior, service descriptor metadata, scanner alias normalization, and docs.

## Binding Non-Goals

This patch must not add or scaffold content discovery.

Explicitly excluded:

- No directory brute force.
- No content discovery command.
- No path fuzzing.
- No recursion, extension guessing, soft-404 calibration, or crawler behavior.
- No `brutespray content` command or docs.
- No TUI search/filter implementation.
- No new findings dashboard.
- No auth-template feature expansion such as CSRF extraction, cookie jars, redirect controls, or response variable capture.
- No new planner UI.
- No new redaction CLI mode unless needed for a narrow bug fix.

## Current State

The repository already contains the scaffolding this patch should build on:

- `brutespray/plan.go` and `brutespray/plan_command.go` build deterministic dry-run plans, write plan JSON, and enforce `--require-plan-ack`.
- `brutespray/engagement.go` parses engagement manifests with scope, policy, and evidence defaults.
- `modules/evidence.go` defines evidence modes and secret rendering.
- `modules/output.go` uses evidence rendering for JSON attempt output.
- `modules/checkpoint.go`, `modules/sessionlog.go`, and `brutespray/resume.go` implement checkpoint/resume persistence and replay.
- `modules/service_descriptor.go` defines canonical service metadata.
- `brutespray/module_help.go` renders module metadata in a machine-readable text format.
- `modules/parse.go` and stream parsers normalize scan service names in some paths.

The patch must fill gaps in this existing system rather than adding parallel registries, output systems, or state models.

## Proposed Patch Areas

### Evidence and Redaction Hardening

Evidence modes already exist, but their scope must be made explicit and defended by tests. JSON attempt output should continue to honor evidence mode. Error paths must not echo raw credential records. Operational artifacts that intentionally contain credentials must be documented clearly rather than silently changed in a patch release.

Implementation constraints:

- Preserve intentional plaintext success artifacts unless an existing test or doc contract says otherwise.
- Add or strengthen tests for JSON redaction/hash behavior.
- Add or strengthen tests for write/error paths that could print raw credentials.
- Document credential-bearing artifacts precisely.

Acceptance:

- JSON attempt output redacts or hashes secrets according to configured evidence mode.
- Error paths do not print raw credential records.
- Documentation names artifacts that may contain credentials.

### Plan Acknowledgement Coverage

Dry-run planning and plan acknowledgement already exist. Patch work should add regression coverage for the failure path and keep plan hashes stable.

Implementation constraints:

- Do not perform credential attempts during plan tests.
- Preserve exact-hash acknowledgement semantics.
- Do not change plan schema unless required by a failing test.

Acceptance:

- Matching `--require-plan-ack` succeeds.
- Mismatched `--require-plan-ack` fails closed.
- Plan hashes remain stable across equivalent input ordering.
- Failure output is actionable enough for operators to correct the hash.

### Checkpoint and Session Behavior

Checkpoint and session replay already exist. Patch work should document the current behavior in tests and fix narrow defects only.

Implementation constraints:

- No storage format migration.
- No new database/storage backend.
- Preserve resume cursor semantics.
- Preserve owner-readable file permissions.

Acceptance:

- Passing a `.jsonl` session path to `-resume` resolves to the corresponding `.json` checkpoint path.
- Checkpoint/session permissions remain restrictive.
- Resume skips only the attempted prefix for the host/service.
- Malformed checkpoint/session behavior is explicit in tests.

### Descriptor and Module Help Parity

Service descriptors are the canonical service metadata surface, but some runtime params and alias/stability relationships are under-tested. Patch work should align metadata with existing behavior only.

Implementation constraints:

- Do not invent new module params.
- Do not add new services.
- Do not add content discovery descriptors.
- Keep module help machine-readable.
- Prefer deriving beta/stability surfaces from descriptors where safe, or add parity tests if derivation is too broad for a patch.

Acceptance:

- Every runtime-supported module has descriptor metadata.
- Existing runtime module params used by modules are described where practical.
- Module help accepts canonical services and safe descriptor aliases only when backed by a registered module.
- Stability metadata and beta list do not silently drift.

### Scanner Alias Normalization Guardrails

Scan ingestion already maps some scanner service names to canonical service names. Patch work should test and fix existing intended normalization paths only.

Implementation constraints:

- Do not add support for new scan formats.
- Do not broaden supported services without descriptor/runtime backing.
- Unsupported service names must still fail closed.

Acceptance:

- Existing aliases normalize consistently across file and stream parsers where those parsers already accept service names.
- Unsupported scanner services remain rejected or ignored according to current parser contracts.

### Documentation Patch

Docs should match actual `2.7.x` behavior and avoid future-feature claims.

Implementation constraints:

- No content discovery docs.
- No `brutespray content` docs.
- No directory brute-force examples.
- No claims about unimplemented TUI search, findings dashboards, or auth-template expansion.

Acceptance:

- Evidence/redaction docs clearly identify shareable versus credential-bearing artifacts.
- HTTP auth-template docs describe current fixed-step behavior and limits.
- Plan/checkpoint docs match implementation and tests.
- Version references are updated once if the patch increments the release.

## Versioning

If implementation changes are made and pass verification, bump from `2.7.1` to `2.7.2` exactly once.

## Testing Strategy

Use test-driven development for behavior changes.

Focused suites:

- `go test ./modules -run 'Evidence|Output|Checkpoint|Session|Descriptor|Parse' -count=1`
- `go test ./brutespray -run 'Plan|Engagement|ModuleHelp|Config|Resume' -count=1`
- Parser-specific focused tests as needed.

Final gates:

- `make lint`
- `go test ./... -count=1 -race`
- `go vet ./...`
- `go build ./...`

## Review Strategy

Request review before committing the final implementation. Review focus:

- No content discovery scope leaked in.
- No feature expansion slipped into a patch release.
- Evidence/redaction behavior is explicit and safe.
- Descriptor/help metadata reflects existing runtime behavior only.
- Tests defend real behavior, not implementation trivia.

## Open Decisions

None. The user selected a `2.7.x` patch target and approved this hardening-only scope.
