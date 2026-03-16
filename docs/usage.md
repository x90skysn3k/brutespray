# Usage

## Command Line Options

| Flag | Description | Example |
|------|-------------|---------|
| `-f` | Input file (Nmap, Nessus, Nexpose, JSON, lists) | `-f nmap.gnmap` |
| `-H` | Target as service://host:port (CIDR supported, repeatable) | `-H ssh://10.1.1.0/24:22` |
| `-u` | Username or user list | `-u admin` or `-u users.txt` |
| `-p` | Password or password list | `-p password` or `-p pass.txt` |
| `-C` | Combo wordlist (user:pass per line) | `-C combos.txt` |
| `-s` | Service filter (comma-separated) | `-s ssh,ftp` |
| `-S` | List all supported services and exit | `-S` |
| `-t` | Threads per host (default: 10) | `-t 20` |
| `-T` | Concurrent hosts (default: 5) | `-T 10` |
| `-w` | Connection timeout (default: 5s) | `-w 10s` |
| `-r` | Retry count on connection failure (default: 3) | `-r 5` |
| `-o` | Output directory (default: brutespray-output) | `-o results` |
| `-d` | Domain for RDP/SMB authentication | `-d CORP` |
| `-socks5` | SOCKS5 proxy | `-socks5 127.0.0.1:1080` |
| `-iface` | Bind to network interface | `-iface tun0` |
| `-rate` | Per-host rate limit (attempts/sec, 0 = unlimited) | `-rate 10` |
| `-spray` | Password spray mode (avoids lockouts) | `-spray` |
| `-spray-delay` | Delay between spray rounds (default: 30m) | `-spray-delay 15m` |
| `-stop-on-success` | Stop testing host after first valid credential | `-stop-on-success` |
| `-resume` | Resume from checkpoint file | `-resume brutespray-checkpoint.json` |
| `-checkpoint` | Checkpoint file path (default: brutespray-checkpoint.json) | `-checkpoint myrun.json` |
| `-config` | YAML config file (CLI flags override) | `-config engagement.yaml` |
| `-summary` | Generate summary reports (JSON, CSV, TXT, MSF, NXC) | `-summary` |
| `-silent` | Suppress per-attempt logs (successes still recorded) | `-silent` |
| `-log-every` | Print every N attempts (default: 1) | `-log-every 100` |
| `-no-stats` | Disable statistics tracking for performance | `-no-stats` |
| `-nc` | Disable colored output | `-nc` |
| `-q` | Suppress banner | `-q` |
| `-P` | Print parsed hosts before execution | `-P` |
| `--no-tui` | Disable interactive TUI, use legacy output | `--no-tui` |
| `-m` | Module parameter in KEY:VALUE format (repeatable) | `-m auth:NTLM` |
| `-e` | Extra credential checks: n=blank, s=user-as-pass, r=reversed | `-e nsr` |
| `-x` | Generate passwords: MIN:MAX:CHARSET | `-x 4:4:1` |
| `--allow-wrapper` | Allow wrapper module to execute commands | `--allow-wrapper` |
| `--output-format` | Per-attempt output format: text (default) or json | `--output-format json` |
| `--proxy-list` | File with proxy list for rotation (one per line) | `--proxy-list proxies.txt` |

## YAML Config File

Use `-config` to load per-engagement settings. CLI flags always override config values.

```yaml
# engagement.yaml
user: "admin"
password: "passlist.txt"
output: "results"
threads: 20
host_parallelism: 10
timeout: "10s"
retry: 5
socks5: "socks5://127.0.0.1:9050"
stop_on_success: true
summary: true
spray: true
spray_delay: "30m"
hosts:
  - "ssh://10.0.0.0/24:22"
  - "rdp://10.0.0.0/24:3389"
```

All fields are optional. Any CLI flag takes precedence over the config file value.

## Module Parameters (`-m`)

Pass service-specific parameters using `-m KEY:VALUE` (repeatable):

```bash
# HTTP Digest auth
brutespray -H http://10.0.0.1:8080 -u admin -p passlist.txt -m auth:DIGEST

# HTTP NTLM auth
brutespray -H http://10.0.0.1:8080 -u admin -p passlist.txt -m auth:NTLM

# SMTP NTLM auth
brutespray -H smtp://10.0.0.1:25 -u admin -p passlist.txt -m auth:NTLM

# HTTP Form brute forcing
brutespray -H "http-form://10.0.0.1:8080" -u admin -p passlist.txt \
  -m "url:/login" -m "body:username=%U&password=%W" -m "fail:Invalid"

# SSH key authentication
brutespray -H ssh://10.0.0.1:22 -u admin -p /path/to/key -m key:true

# Wrapper module (requires --allow-wrapper)
brutespray -H wrapper://10.0.0.1 -u admin -p passlist.txt \
  -m "cmd:sshpass -p %W ssh %U@%H -p %P" --allow-wrapper
```

Module params can also be set in YAML config:
```yaml
module_params:
  auth: NTLM
  dir: /admin
```

## Extra Credential Checks (`-e`)

| Flag | Description |
|------|-------------|
| `-e n` | Try blank/empty password |
| `-e s` | Try username as password |
| `-e r` | Try reversed username as password |
| `-e ns` | Try both blank and username-as-password |
| `-e nsr` | Try all three extra checks |

## Password Generation (`-x`)

Generate passwords on-the-fly without a wordlist:

```bash
# All 4-digit PINs (0000-9999)
brutespray -H ssh://10.0.0.1:22 -u admin -x 4:4:1

# 1-6 char lowercase + digits
brutespray -H ssh://10.0.0.1:22 -u admin -x 1:6:a1

# 2-4 char all charsets
brutespray -H ssh://10.0.0.1:22 -u admin -x 2:4:aA1!
```

| Charset | Characters |
|---------|-----------|
| `a` | lowercase (a-z) |
| `A` | uppercase (A-Z) |
| `1` | digits (0-9) |
| `!` | symbols |

Max length is capped at 8 to prevent excessive generation.

## PwDump File Support

Password files in PwDump format (`username:uid:LM_hash:NTLM_hash:::`) are auto-detected. Users and NTLM hashes are extracted automatically for pass-the-hash attacks:

```bash
brutespray -H smbnt://10.0.0.1:445 -p hashdump.txt
```

## Input File Formats

Brutespray auto-detects the format from file contents.

### Nmap

Scan with `-oA` or `-oG` / `-oX`:

```bash
nmap -sV -oA scan_results 10.0.0.0/24
```

Both GNMAP (`.gnmap`) and XML (`.xml`) formats are supported.

### Nessus

Export your scan as a `.nessus` file from the Nessus web interface.

### Nexpose

Use the **XML Export** template when exporting from Nexpose.

### JSON Lines

One JSON object per line:

```json
{"host":"127.0.0.1","port":"3306","service":"mysql"}
{"host":"127.0.0.10","port":"22","service":"ssh"}
```

### Plain List

```
ssh:127.0.0.1:22
ftp:192.168.1.1:21
mysql:10.0.0.5:3306
```

### Combo Wordlist

For use with `-C`:

```
root:root
admin:admin
user1:password123
```
