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
