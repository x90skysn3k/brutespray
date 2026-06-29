# Output and Reporting

## Output Directory

Results are saved to `brutespray-output/` by default. Override with `-o`:

```bash
brutespray -f nmap.gnmap -u admin -p password -o engagement-results
```

Successful credentials are written to per-service files in the output directory as they are found.

## Summary Reports

Generate comprehensive reports with `-summary`:

```bash
brutespray -f nmap.gnmap -u admin -p password -summary
```

This produces:

| File | Format | Description |
|------|--------|-------------|
| `brutespray-summary.json` | JSON | Machine-readable full report |
| `brutespray-summary.csv` | CSV | Tabular results for spreadsheets/analysis |
| `brutespray-summary.txt` | Text | Human-readable summary |
| `brutespray-msf.rc` | Metasploit RC | Resource script for `msfconsole -r` |
| `brutespray-nxc.sh` | Shell script | NetExec/CrackMapExec commands |

## Statistics

When statistics tracking is enabled (default), the summary includes:

- Session duration and timing
- Total attempts, successes, and failures
- Connection vs authentication error breakdown
- Success rate percentage
- Attempts per second
- Average response time
- Peak concurrency
- Per-service and per-host breakdown
- Full list of found credentials

## Pentesting Integration

### Metasploit

The `-summary` flag generates a `.rc` resource script with auxiliary modules pre-configured for each found credential:

```bash
msfconsole -r brutespray-msf.rc
```

### NetExec / CrackMapExec

The `-summary` flag also generates a shell script with `nxc` commands:

```bash
chmod +x brutespray-nxc.sh
./brutespray-nxc.sh
```

## Controlling Output Verbosity

| Flag | Effect |
|------|--------|
| `-silent` | Suppress per-attempt logs; successes and summary still recorded |
| `-log-every N` | Print every Nth attempt (e.g., `-log-every 100`) |
| `-no-stats` | Disable statistics tracking entirely |
| `-nc` | Disable colored output |
| `-q` | Suppress the banner |
| `--no-tui` | Use legacy text output instead of interactive TUI |

## Evidence Modes

Machine-readable attempt output now carries proof metadata and can render credential material according to the configured evidence mode.

| Mode | Password field | Correlation field | Intended use |
|---|---|---|---|
| `full` | Raw password | omitted | Legacy local-only output |
| `redacted` | `[REDACTED]` | omitted | Shareable summaries and SIEM logs |
| `hash` | `[REDACTED]` | `secret_hmac_sha256` | Correlating repeated secrets without disclosure; requires secret `evidence.hmac_key` |
| `encrypted` | `[REDACTED]` | omitted | Reserved encrypted evidence mode; currently redacts in JSON output |

JSON attempt records may include:

| Field | Description |
|---|---|
| `secret_redacted` | `true` when the password was not printed directly |
| `secret_hmac_sha256` | HMAC-SHA256 digest when evidence mode is `hash` |
| `confidence` | `confirmed`, `probable`, or `inconclusive` |
| `proof_type` | Evidence source such as `auth_protocol_success`, `preauth_probe`, `badkey_match`, `http_matcher`, or `wrapper_exit` |
| `proof_detail` | Short module/detail string for reports |

## Audit log verification

`brutespray audit verify <audit.jsonl>` validates a hash-chained JSONL audit log. Each event includes `sequence`, `prev_hash`, and `hash`; verification fails if an event is edited, removed, or reordered.

```bash
brutespray audit verify brutespray-audit.jsonl
```

## Finding records (JSONL)

Pre-auth recon results emit one JSON object per line in JSONL mode:

```json
{"type":"finding","severity":"WARN","code":"rdp-nla-missing","service":"rdp","target":"10.0.0.5:3389","message":"NLA not enforced — server accepts standard RDP without pre-auth"}
{"type":"finding","severity":"CRITICAL","code":"rdp-stickykeys","service":"rdp","target":"10.0.0.5:3389","message":"sticky-keys backdoor detected (cmd.exe shell at logon screen)"}
```

| Field | Description |
|---|---|
| `type` | Always `"finding"` |
| `severity` | `INFO`, `WARN`, `HIGH`, `CRITICAL` |
| `code` | Stable machine identifier: `rdp-nla-required`, `rdp-nla-missing`, `rdp-nla-hybridex`, `rdp-stickykeys`, `rdp-stickykeys-inconclusive` |
| `service` / `target` | Target identification |
| `message` | Human-readable description |
| `cve` | Present only when a CVE applies |

## BADKEY records (JSONL)

When SSH authentication succeeds against an embedded bad key, the per-success
output channel emits a distinct `badkey` record alongside the regular `success`
line:

```json
{"type":"badkey","service":"ssh","target":"10.0.0.5:22","username":"vagrant","vendor":"HashiCorp Vagrant","description":"Vagrant insecure default key (any Vagrant VM pre-2014)"}
{"type":"badkey","service":"ssh","target":"10.0.0.6:22","username":"root","vendor":"F5 BIG-IP","cve":"CVE-2012-1493","description":"F5 BIG-IP 9.x-11.x default root SSH key"}
```
