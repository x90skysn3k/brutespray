# Brutus Feature-Parity Spec

**Date:** 2026-05-29
**Branch:** dev
**Delivery:** single combined release PR (phases A → B → C → D, in order)

## Context

Praetorian shipped Brutus in February 2026 — a Go-based, single-binary credential testing tool positioned explicitly as a Hydra alternative. It overlaps brutespray's domain but introduces a few genuinely new ideas: an embedded SSH bad-keys bundle, pre-auth RDP recon (NLA fingerprinting, sticky-keys backdoor detection), native stdin pipelining with `naabu`/`fingerprintx`/`masscan`, and a handful of databases brutespray doesn't yet cover. Brutespray remains stronger overall (TUI, checkpoint/resume, spray-mode lockout-awareness, SOCKS5 + proxy rotation, per-attempt JSONL, 36 services, Nessus/Nexpose imports) but is missing those four specific capabilities.

This spec borrows the high-value ideas and lands them on `dev` as one release PR. The brutespray-vs-others comparison table on the README is folded in as part of the same release so the marketing surface lines up with the new features.

## Goals

1. Match Brutus's SSH bad-key testing with a vendored Rapid7 ssh-badkeys bundle + Vagrant + vendor keys, automatic per-key username pairing, CVE metadata in output.
2. Add pre-auth RDP recon: NLA fingerprinting and Sticky-Keys backdoor detection. Findings flow through normal output channels (text, JSON, TUI).
3. Make brutespray pipeline-friendly: read targets from stdin with format auto-detection (Nerva URI, naabu line, fingerprintx JSON, masscan JSON, bare `host:port`).
4. Add five database modules (Neo4j, Cassandra, CouchDB, Elasticsearch, InfluxDB) following the existing module pattern.
5. SNMP wordlist tiering (`default` / `extended` / `full`) with SCADA / camera / storage vendor strings.
6. Inline credential pairs via `-c user:pass[,user2:pass2…]`.
7. README comparison table positioning brutespray against Hydra, Medusa, Ncrack, Brutus. Full docs sweep.

## Non-goals

- Claude Vision web fingerprinting (`--experimental-ai`). Out of scope this release; pulls in headless Chrome + external API dependencies. Revisit separately.
- RDP backdoor `--exec` command execution. Legally fraught even on authorized engagements.
- RDP web terminal viewer. Overlaps grdp scope, big surface area.
- Brutus's subcommand structure (`brutus creds` / `web` / `snmp` / `badkeys`). Diverges from brutespray's flat-CLI philosophy.

## Architecture

All four phases follow existing brutespray patterns: `init()`-based module registration via `Register()` in `brute/registry.go`, `brute.ModuleParams` for per-module flags, `ConnectionManager.Dial()` for network I/O with proxy/interface support, `time.NewTimer` + goroutine + `select` for timeouts. Phases are ordered to minimize risk: A is self-contained, B touches the input parser, C is additive modules, D is pure docs.

### Phase A — Pre-auth recon

**SSH bad-keys** — new `brute/badkeys/` package using `go:embed` to vendor a snapshot of [Rapid7/ssh-badkeys](https://github.com/rapid7/ssh-badkeys) plus the HashiCorp Vagrant insecure key plus the per-vendor keys Brutus ships (F5 BIG-IP, ExaGrid, Barracuda, Ceragon FibeAir, Array Networks, Quantum DXi, Loadbalancer.org). Layout:

```
brute/badkeys/
  embed.go              // go:embed keys/*.pem and metadata.yaml
  registry.go           // KeyEntry{Fingerprint, Username, CVE, Vendor, PEM}
  registry_test.go
  keys/                 // vendored .pem files
  metadata.yaml         // fingerprint → {username, CVE, vendor}
```

`brute/ssh.go` extended: when `params["badkeys"] != "false"` (default on), the bad-keys pass runs **before** password attempts and on first match short-circuits (no further passwords for that host). Each key is paired with its default username from metadata. A successful key auth populates a new `BruteResult.KeyMatch *KeyEntry` field; output layer renders `[+] BADKEY ssh root@10.0.0.5 vagrant-insecure-key (CVE-2015-1338)`.

Flags:
- `--no-badkeys` — opt-out (the user instruction). Default behavior: on for SSH.
- `--badkeys-only` — skip password attempts entirely.
- `-m badkeys-bundle:default|extended|full` — wordlist-style tiering, mirrors SNMP tiering in Phase C.

Refresh cadence: monthly `chore(badkeys)` PR mirroring the existing `chore: monthly wordlist update` pattern visible in `git log`.

**RDP NLA fingerprint** — `brute/rdp.go` adds a pre-auth probe that sends the X.224 Connection Request (RDPneg request) and parses the server's RDPneg response. If `PROTOCOL_HYBRID` (NLA) is required, finding is logged as `[INFO] rdp 10.0.0.5:3389 NLA-required`. If `PROTOCOL_RDP` only (no NLA), `[WARN] rdp 10.0.0.5:3389 NLA-not-enforced (CVE-class)`. Runs once per host before any brute attempts.

**RDP Sticky-Keys backdoor scan** — after NLA fingerprint, if the target accepts standard RDP, connect to the logon screen via `x90skysn3k/grdp` (existing dep). Send 5× Shift down/up scancodes (sticky-keys trigger) and capture the resulting bitmap region around the active window. Detection is two-stage: (1) the post-trigger framebuffer must change meaningfully versus the pre-trigger frame (rules out servers ignoring input); (2) the top-left active-window region is OCR'd via a small embedded title-bar font matcher looking for `cmd.exe`, `C:\Windows\system32`, or a black console background. Finding emits as `[CRITICAL] rdp 10.0.0.5:3389 sticky-keys backdoor detected`. If detection is inconclusive (framebuffer changed but no console match), emit `[INFO] rdp 10.0.0.5:3389 sticky-keys inconclusive` so the operator can verify manually. Opt-out via `--no-rdp-scan`.

**Implementation note:** brutespray's `x90skysn3k/grdp` dependency lives at `../grdp/` and is owned by this project. The sticky-keys probe will be implemented by adding `client.RdpClient.CaptureLogonScreen(trigger LogonTrigger) (*image.RGBA, error)` (plus supporting framebuffer plumbing) to grdp, then consuming it from `brute/rdp.go`. Coordinated change across the two repos.

Result type expansion in `brute/run.go`:

```go
type BruteResult struct {
    // ... existing fields ...
    Finding   *Finding      // pre-auth scan result
    KeyMatch  *KeyEntry     // SSH bad-key match
}
type Finding struct {
    Severity string         // INFO|WARN|HIGH|CRITICAL
    Code     string         // ssh-badkey|rdp-nla-missing|rdp-stickykeys
    Message  string
    CVE      string         // optional
}
```

Output layer (`modules/output.go`) renders findings into text and JSONL streams; TUI gets a "Findings" tab alongside the existing tabs (see `tui/` for the existing tabbed Model).

### Phase B — Stdin pipeline + masscan JSON

`modules/parse.go` currently dispatches on file extension / contents for `-f`. Extend with:

1. **Stdin detection** in `brutespray/config.go` / `brutespray.go:Execute`: if `-f` is empty and `os.Stdin` is a pipe (not a TTY — use `term.IsTerminal(int(os.Stdin.Fd()))`), read stdin as the target source.

2. **Format auto-detection** in a new `modules/parse_stream.go`:
   - First non-blank line decides format.
   - Line starts with `{` → JSON. Probe for `nerva` (has `protocol`+`port`+`ip`), `fingerprintx` (has `host`+`service`), or `masscan` (has `ports[]` array). Dispatch to matching parser.
   - Line matches `^[a-z]+://[^:]+:\d+` → Nerva URI.
   - Line matches `^[^\s:]+:\d+$` → bare host:port (naabu `-silent` output).
   - Anything else: pass through existing `-f` parsers (gnmap/etc.) attempting each.

3. **Masscan JSON parser** — new file `modules/parse_masscan.go`. Masscan emits an array of `{ip, ports: [{port, proto, status}]}` objects. Only emit targets where `status="open"`. Port→protocol mapping reuses the existing default-port table.

No new CLI flag. `naabu -silent | brutespray -u root -p rootpass` just works.

### Phase C — New modules + SNMP tiering + inline cred pairs

**Five new modules** in `brute/`:

- `neo4j.go` — Bolt v5 protocol over TCP/7687. Uses `github.com/neo4j/neo4j-go-driver/v5/neo4j` (already widely used, MIT). Test via `docker run -p 7687:7687 neo4j:5`.
- `cassandra.go` — CQL native protocol over TCP/9042. Uses `github.com/gocql/gocql`. `PasswordAuthenticator`. Default-port 9042. Test via `cassandra:4`.
- `couchdb.go` — HTTP basic auth against `_session` endpoint, port 5984. No new dep; reuse existing http auth helpers.
- `elasticsearch.go` — HTTP basic auth against `/_cluster/health`, port 9200. No new dep.
- `influxdb.go` — InfluxDB 2.x token/basic auth against `/api/v2/orgs`, port 8086. No new dep.

Each module follows the standard pattern from `CLAUDE.md`: `BruteXxx(host, port, user, password, timeout, cm, params) *BruteResult`, `cm.Dial()`, deadline set, timer/select timeout, `init()` registers via `Register()`. Add to stable service list in `brutespray/config.go` (couchdb/elasticsearch/influxdb safe to mark stable; neo4j/cassandra start as beta until docker-tested across versions).

**SNMP tiering** — `brute/snmp.go` currently tries a single embedded community list. Split into `wordlist/snmp_default.txt` (~20: public, private, cisco, manager…), `wordlist/snmp_extended.txt` (~50: + Cisco/HP/Juniper enterprise), `wordlist/snmp_full.txt` (~120: + SCADA, IP camera defaults, storage array defaults — sourced from publicly-documented vendor docs). Select via `-m mode:default|extended|full` (default = `default`). Embed via `go:embed` in `modules/wordlist.go` alongside existing embedded lists.

**Inline cred pairs** — `brutespray/dispatch.go` already handles `-C` combo files. Add `-c, --creds` that accepts comma-separated `user:pass` strings: `--creds 'admin:admin,root:toor'`. Splits → builds the same in-memory credential list a combo file would yield. Reuses existing `sanitizeCred` and PwDump auto-detect path off (these are explicit pairs).

### Phase D — Documentation + comparison table

**README** — add a positioning table after the existing feature list. Sketch:

| Feature | brutespray | hydra | medusa | ncrack | brutus |
|---|---|---|---|---|---|
| Single static binary | ✅ | ❌ | ❌ | ❌ | ✅ |
| Interactive TUI | ✅ | ❌ | ❌ | ❌ | ❌ |
| Checkpoint / resume | ✅ | ❌ | ❌ | ✅ | ❌ |
| Spray mode (lockout-aware) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Per-attempt JSONL | ✅ | ⚠️ | ❌ | ❌ | ❌ (success-only) |
| SOCKS5 + proxy rotation | ✅ | ⚠️ | ❌ | ❌ | ❌ |
| Embedded SSH bad-keys | ✅ (new) | ❌ | ❌ | ❌ | ✅ |
| Pipeline stdin (naabu/fingerprintx/masscan) | ✅ (new) | ❌ | ❌ | ❌ | ✅ |
| Pre-auth RDP recon (NLA / sticky-keys) | ✅ (new) | ❌ | ❌ | ❌ | ✅ |
| Nmap gnmap+XML / Nessus / Nexpose import | ✅ | ⚠️ | ❌ | ❌ | ⚠️ (nmap only) |
| Module params (`-m KEY:VAL`) | ✅ | ❌ | ❌ | ❌ | partial |
| Service count | 41 (after this PR) | 50+ | 34 | 14 | 23 |

(Final symbols verified against tool docs at PR time, not from memory.)

**docs/** sweep — following the existing `docs/wordlists.md` / `docs/services.md` style:
- `docs/services.md`: add neo4j, cassandra, couchdb, elasticsearch, influxdb rows.
- `docs/advanced.md`: new sections for SSH bad-keys (with CVE table), RDP pre-auth recon, stdin pipeline integration with `naabu | fingerprintx | brutespray` example.
- `docs/output.md`: document new `Finding` and `KeyMatch` JSONL fields.
- `docs/wordlists.md`: SNMP tiering description.
- `docs/usage.md`: `--no-badkeys`, `--badkeys-only`, `--no-rdp-scan`, `-c/--creds` inline pairs, stdin auto-detect.
- New `docs/pipeline.md` walking through the recon workflow end-to-end.

**CLAUDE.md** — updated locally to reflect new modules, flags, and findings shape. Per memory policy `[[feedback_no_claude_md]]`, **not committed**.

## Critical files to modify

- `brute/ssh.go` — bad-keys integration
- `brute/rdp.go` — pre-auth NLA + sticky-keys recon
- `brute/snmp.go` — tier selection
- `brute/run.go` — `BruteResult` extension with `Finding` and `KeyMatch`
- `brute/registry.go` — register 5 new modules
- `brute/badkeys/` (new package) — embedded ssh-badkeys bundle
- `brute/{neo4j,cassandra,couchdb,elasticsearch,influxdb}.go` (new) — each follows the existing module pattern; tests follow `brute/redis_test.go` / `brute/postgres_test.go` shape. `wordlist/{neo4j,influxdb}` already exist with user+password files; `wordlist/{cassandra,couchdb,elasticsearch}` are empty placeholders that get populated as part of this PR.
- `../grdp/client/` — add `CaptureLogonScreen` and `LogonTrigger` types (sibling repo, owned)
- `brutespray/config.go` — new flags (`--no-badkeys`, `--badkeys-only`, `--no-rdp-scan`, `-c/--creds`); stable/beta service lists
- `brutespray/dispatch.go` — inline-pairs expansion
- `brutespray/brutespray.go` — stdin pipeline detection at `Execute()` entry
- `modules/parse.go` — dispatch to new parsers
- `modules/parse_stream.go` (new) — stdin format auto-detection
- `modules/parse_masscan.go` (new) — masscan JSON parser
- `modules/output.go` — render `Finding` / `KeyMatch` in text and JSONL
- `modules/wordlist.go` — embed snmp_default/extended/full
- `tui/` — new findings tab; reuse existing tab pattern in `tui/view_*.go`
- `README.md` — comparison table
- `docs/*.md` — per-feature documentation

## Reused utilities

- `Register()` in `brute/registry.go` for new modules
- `ConnectionManager.Dial()` in `modules/connections.go` for all network I/O — gets SOCKS5/proxy/iface for free
- `sanitizeCred()` for text-protocol creds (couchdb, elasticsearch, influxdb)
- `time.NewTimer` + goroutine + `select` timeout pattern (CLAUDE.md mandate)
- `go:embed` infrastructure already used in `modules/wordlist.go`
- `x90skysn3k/grdp` already-imported RDP library for sticky-keys probe
- Existing TUI tabbed `Model` in `tui/` — extend, don't refactor

## Verification

**Unit:** new tests for each new module (`brute/neo4j_test.go` etc.) mirroring the docker-based pattern in `brute/redis_test.go`. Bad-keys metadata parsing tested against the vendored YAML. Stdin format auto-detect tested with table-driven fixtures (`modules/parse_stream_test.go`).

**Integration:** spin docker containers for neo4j, cassandra, couchdb, elasticsearch, influxdb and run `brutespray` end-to-end with a known-good credential. Reuse the existing docker harness referenced in commit `f162ae9`.

**Pipeline:** `naabu -host 127.0.0.1 -p 22 -silent | ./brutespray -u root -P wordlist/ssh.txt` against a local SSH container — confirm stdin auto-detect, confirm bad-keys phase fires.

**RDP recon:** stand up a Windows RDP container with NLA off and sticky-keys backdoor (cmd.exe in place of sethc.exe) and confirm both findings emit. Repeat with NLA on / no backdoor — confirm clean output.

**Comparison table:** verify each ✅/❌/⚠️ against the named tool's current documentation (not from memory) at PR time.

**Regression:** `go test ./... -race` clean; existing 106 tests still pass; TUI smoke test (`./brutespray -H 127.0.0.1 -s ssh -u root -p test`).

**Lint:** `golangci-lint run` clean.

## Documentation deliverables

Per the user instruction to update documentation for every new feature:

- README.md — comparison table, mention of new features in feature list, stdin pipeline example near the top
- docs/services.md — 5 new module rows
- docs/usage.md — new flags
- docs/advanced.md — bad-keys CVE table, RDP recon details
- docs/output.md — Finding / KeyMatch JSONL schema
- docs/wordlists.md — SNMP tiering
- docs/pipeline.md (new) — end-to-end recon workflow walk-through
- CLAUDE.md (local only, not committed) — module patterns and flags

## Out of band

The pre-existing `dev` branch has scratch artifacts in the working tree (`brutespray-checkpoint.jsonl`, `brutespray-improved`, `brutespray-intelligent`, `brutespray-test`, `medusa/`, `thc-hydra/`, `test-output/`, etc.) per `git status`. These are ignored for this spec — work proceeds from a clean staging area; nothing in this spec touches them.
