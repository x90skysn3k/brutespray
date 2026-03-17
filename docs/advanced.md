# Advanced Features

## Password Spray Mode

Spray mode tries each password across all users before moving to the next password. This avoids account lockout policies that trigger on consecutive failed attempts per user.

```bash
brutespray -f nmap.gnmap -u userlist.txt -p passlist.txt -spray -spray-delay 15m
```

| Flag | Description | Default |
|------|-------------|---------|
| `-spray` | Enable spray mode | disabled |
| `-spray-delay` | Delay between password rounds | 30m |

**How it works:**
1. Try `password1` against all users on all hosts
2. Wait for the spray delay
3. Try `password2` against all users on all hosts
4. Repeat until all passwords are exhausted

The circuit breaker is automatically enabled in spray mode to skip hosts that become unreachable after 5 consecutive connection failures.

## SOCKS5 Proxy

All services support SOCKS5 proxies. Supported formats:

```bash
# Basic
brutespray -H ssh://target:22 -socks5 127.0.0.1:1080

# With authentication
brutespray -H ssh://target:22 -socks5 socks5://user:pass@proxy:1080

# Remote DNS resolution (socks5h)
brutespray -H ssh://target:22 -socks5 socks5h://user:pass@proxy:1080
```

Features:
- Username/password authentication
- Local (`socks5://`) and remote (`socks5h://`) hostname resolution
- Works with all 24 supported services
- Compatible with interface binding

## Network Interface Binding

Bind all connections to a specific network interface:

```bash
brutespray -H ssh://target:22 -iface tun0
```

When omitted, the kernel selects the source address per destination, which works correctly with VPNs and dual-homed setups.

## Rate Limiting

Throttle attempts per host to avoid detection or server overload:

```bash
brutespray -f nmap.gnmap -u admin -p passlist.txt -rate 10
```

The rate is in attempts per second per host. Set to `0` (default) for unlimited.

## Resume and Checkpoints

Brutespray automatically saves progress during execution. If interrupted with Ctrl+C, resume later:

```bash
brutespray -f nmap.gnmap -u admin -p passlist.txt -resume brutespray-checkpoint.json
```

**How it works:**
- **Checkpoint file** (`.json`) — Tracks which hosts are fully completed. On resume, completed hosts are skipped entirely.
- **Session log** (`.jsonl`) — Records every attempt result. On resume, the full session history is replayed into the TUI so it appears as if the scan never stopped.
- Auto-saves every 30 seconds and on interrupt
- Pass either file to `-resume` — brutespray resolves both automatically

Custom checkpoint path:
```bash
brutespray -f nmap.gnmap -u admin -p passlist.txt -checkpoint engagement1.json
```

## Embedded Wordlists

Brutespray ships with curated default wordlists compiled into the binary. No external files are needed for basic operation.

Wordlists are organized via a manifest system with shared base lists and per-service overrides. Override with your own using `-u` and `-p`.

### Wordlist Subcommand

```bash
brutespray wordlist seasonal     # Generate seasonal passwords (current year/month)
brutespray wordlist validate     # Validate wordlists and manifest
brutespray wordlist build        # Build flat wordlists from manifest
brutespray wordlist research     # AI-powered research via Ollama
brutespray wordlist merge        # Merge research candidates into wordlists
brutespray wordlist download -o path  # Download rockyou.txt
```

## Stop on Success

Stop testing a host after finding the first valid credential:

```bash
brutespray -f nmap.gnmap -u admin -p passlist.txt -stop-on-success
```

This is per-host — other hosts continue normally. Useful for reducing noise when you only need proof of access.

## Performance Tuning

### Threading Model

| Flag | Description | Default |
|------|-------------|---------|
| `-t` | Threads per host | 10 |
| `-T` | Concurrent hosts | 5 |

Each host gets its own worker pool. Total concurrent workers = `-t` × `-T`.

### Dynamic Thread Scaling

The worker pool monitors per-host performance and adjusts thread counts:
- Fast responses (<200ms) → scales up to 2x threads
- Slow responses (>2s) → scales down to half
- High success rate → modest thread increase

### Circuit Breaker

In spray mode, the circuit breaker tracks consecutive connection failures per host. After 5 failures, the host is skipped for remaining credentials. Resets on successful connection.

### Adaptive Backoff

When a host has consecutive connection failures, workers apply exponential backoff: 2s, 4s, 8s, 16s, capped at 30s. This prevents hammering unreachable hosts.

### Connection Pooling

Connections are pooled per service with a 30-second max age. Reused connections reduce handshake overhead.

### Disabling Statistics

For very large scans, disable metrics tracking to reduce overhead:

```bash
brutespray -f nmap.gnmap -u admin -p password -no-stats
```

## Password Generation (`-x`)

Generate passwords on-the-fly instead of using a wordlist file. Format: `MIN:MAX:CHARSET`

| Charset | Characters |
|---------|-----------|
| `a` | lowercase letters (a-z) |
| `A` | uppercase letters (A-Z) |
| `1` | digits (0-9) |
| `!` | symbols (!@#$%^&*()_+-=[]{}|;:',.<>?/`~") |

Combine charsets: `-x 2:4:aA1` generates 2-4 character alphanumeric passwords.

**Examples:**
```bash
# All 4-digit PINs (10,000 combinations)
brutespray -H ssh://target:22 -u admin -x 4:4:1

# Short lowercase passwords (26 + 676 + 17,576 = 18,278 combinations)
brutespray -H ssh://target:22 -u admin -x 1:3:a
```

Max length is capped at 8 to prevent accidental generation of billions of passwords.

## Extra Credential Checks (`-e`)

Add extra password attempts alongside the wordlist:

| Flag | Description |
|------|-------------|
| `n` | Blank/empty password |
| `s` | Username as password (e.g., user `admin` → password `admin`) |
| `r` | Reversed username as password (e.g., user `admin` → password `nimda`) |

Combine: `-e nsr` tries all three. Extra checks are always attempted before the wordlist.

## PwDump Format Support

When the `-p` flag points to a file in PwDump format (`username:uid:LM_hash:NTLM_hash:::`), brutespray auto-detects it and extracts user+NTLM hash pairs. This enables pass-the-hash attacks against SMB/NTLM services.

```bash
brutespray -H smbnt://10.0.0.1:445 -p hashdump.txt
```

## JSON Output Format

Use `--output-format json` for machine-readable JSONL (one JSON object per line) output. Each attempt produces a line like:

```json
{"timestamp":"2024-01-15T10:30:00Z","service":"ssh","host":"10.0.0.1","port":22,"user":"admin","password":"secret","success":true,"connected":true,"status":"SUCCESS"}
```

Useful for piping into `jq`, log aggregators, or SIEM systems.

## SSH Key Authentication

Test SSH private keys instead of passwords. Set `-m key:true` and use `-p` to specify the key file path:

```bash
# Test a specific key
brutespray -H ssh://target:22 -u root -p /path/to/id_rsa -m key:true
```

## Wrapper Module

The wrapper module executes an arbitrary external command for each credential attempt. Placeholders:
- `%H` — host
- `%P` — port
- `%U` — username
- `%W` — password

Exit code 0 = authentication success, non-zero = failure.

**Security:** The `--allow-wrapper` flag is required to use this module, since it executes arbitrary shell commands.

```bash
brutespray -H wrapper://target:8080 -u admin -p passlist.txt \
  -m "cmd:python3 check_login.py %H %P %U %W" --allow-wrapper
```

## Proxy List Rotation

Rotate through multiple SOCKS5 proxies for load distribution and anonymity:

```bash
brutespray -f nmap.gnmap -u admin -p passlist.txt --proxy-list proxies.txt
```

The proxy list file contains one proxy per line:
```
socks5://proxy1.example.com:1080
socks5://user:pass@proxy2.example.com:1080
127.0.0.1:9050
```

Proxies are rotated round-robin across connections. This is separate from the single `--socks5` flag.

## SNMPv3 Authentication

SNMPv3 provides user-based authentication with optional encryption, replacing community-string-based v2c:

```bash
# Basic SNMPv3 with MD5 auth
brutespray -H snmp://10.0.0.1:161 -u snmpuser -p authpass -m version:3

# SHA auth with AES privacy
brutespray -H snmp://10.0.0.1:161 -u snmpuser -p authpass \
  -m version:3 -m auth:SHA -m priv:AES -m privpass:privpass123
```

Without `-m version:3`, SNMP defaults to v2c with community strings.

## HTTP-Form CSRF Token Extraction

For forms protected by CSRF tokens, use `-m csrf:FIELD_NAME` to automatically extract the token:

```bash
brutespray -H "http-form://10.0.0.1:8080" -u admin -p passlist.txt \
  -m "url:/login" -m "body:user=%U&pass=%W&token=%C" \
  -m "fail:Invalid" -m "csrf:csrf_token"
```

How it works:
1. GET request to the form URL extracts the token from `<input name="csrf_token" value="...">`
2. The `%C` placeholder in the body is replaced with the extracted token
3. If the token is not found, the request proceeds without it

Use `-m form-url:/path` if the CSRF form page differs from the login URL.

## Module Parameter Reference

| Service | Parameter | Values | Description |
|---------|-----------|--------|-------------|
| http/https | `auth` | BASIC, DIGEST, NTLM, AUTO | Authentication method |
| http/https | `dir` | path | Target path (default: /) |
| http/https | `method` | GET, POST, etc. | HTTP method |
| http/https | `custom-header` | Header:Value | Custom HTTP header |
| http/https | `user-agent` | string | Custom User-Agent |
| http/https | `domain` | string | NTLM domain |
| http-form | `url` | path | Login form path (required) |
| http-form | `body` | template | POST body with %U/%W/%U64/%W64/%C placeholders |
| http-form | `fail` | string | Failure string in response |
| http-form | `success` | string | Success string in response |
| http-form | `method` | GET, POST | HTTP method (default: POST) |
| http-form | `follow` | true/false | Follow redirects |
| http-form | `cookie` | string | Custom cookie |
| http-form | `content-type` | string | Content-Type header |
| http-form | `csrf` | field name | CSRF token hidden field name |
| http-form | `form-url` | path | URL to GET for CSRF token (default: same as `url`) |
| snmp | `version` | 2c, 3 | SNMP version (default: 2c) |
| snmp | `auth` | MD5, SHA | SNMPv3 authentication protocol |
| snmp | `priv` | NONE, DES, AES | SNMPv3 privacy protocol |
| snmp | `privpass` | string | SNMPv3 privacy passphrase |
| pop3 | `auth` | USER, PLAIN, LOGIN, APOP | Auth method (default: auto) |
| imap | `auth` | LOGIN, PLAIN, CRAM-MD5 | Auth method (default: auto) |
| ssh | `auth` | password, keyboard-interactive | Auth method (default: password + kbd-interactive fallback) |
| ssh | `key` | true/path | Use SSH key authentication |
| smtp | `auth` | PLAIN, LOGIN, NTLM | SMTP auth method |
| smtp | `ehlo` | hostname | EHLO hostname |
| svn | `path` | path | SVN repository path |
| mysql | `dbname` | string | Target database (default: server default) |
| postgres | `dbname` | string | Target database (default: postgres) |
| mssql | `domain` | string | Windows domain for domain auth |
| redis | `db` | integer | Redis database number (default: 0) |
| telnet | `success` | string | Custom success string match |
| wrapper | `cmd` | command | Command template with %H/%P/%U/%W |
| smbnt | `domain` | string | SMB domain |
| rdp | `domain` | string | RDP domain |
