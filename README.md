# Brutespray

![Version](https://img.shields.io/badge/Version-2.5.4-red)[![goreleaser](https://github.com/x90skysn3k/brutespray/actions/workflows/release.yml/badge.svg)](https://github.com/x90skysn3k/brutespray/actions/workflows/release.yml)[![Go Report Card](https://goreportcard.com/badge/github.com/x90skysn3k/brutespray/v2)](https://goreportcard.com/report/github.com/x90skysn3k/brutespray/v2)

Created by: Shane Young/@t1d3nio && Jacob Robles/@shellfail 

Inspired by: Leon Johnson/@sho-luv

# Description
Brutespray has been re-written in Golang, eliminating the requirement for additional tools. This enhanced version is more extensive and operates at a significantly faster pace than its Python counterpart. As of now, Brutespray accepts input from Nmap's GNMAP/XML output, newline-separated JSON files, Nexpose's XML Export feature, Nessus exports in .nessus format, and various lists. Its intended purpose is for educational and ethical hacking research only; do not use it for illegal activities.

<img src="https://i.imgur.com/6fQI6Qs.png" width="500">

# Interactive Terminal UI

Brutespray now features an interactive terminal UI built with [Bubble Tea](https://github.com/charmbracelet/bubbletea). The TUI is **enabled by default** on interactive terminals.

**Features:**
- **Tabbed views** — All, By Host, By Service, Completed, Successes, Errors, Settings
- **Live settings** — Adjust threads per host and parallel hosts on the fly during a scan
- **Focus navigation** — Left/right to switch tabs, down to enter content, up to return to tabs
- **Error routing** — All errors display cleanly in the Errors tab instead of corrupting the screen
- **Real-time stats** — Elapsed time, attempts/sec, success rate, and error counts

To disable the TUI and use legacy console output:
```
brutespray -f nmap.gnmap -u admin -p password --no-tui
```

# Install

```
go install github.com/x90skysn3k/brutespray/v2@latest
```

[Release Binaries](https://github.com/x90skysn3k/brutespray/releases)

To Build:

```
go build -o brutespray main.go
```

# Usage

If using Nmap, scan with `-oA nmap_out`.
If using Nexpose, export the template `XML Export`. 

If using Nessus, export your `.nessus` file.

Command: ```brutespray -h```

Command: ```brutespray -f nmap.gnmap -u userlist -p passlist```

Command: ```brutespray -f nmap.xml -u userlist -p passlist```

Command: ```brutespray -H ssh://127.0.0.1:22 -u userlist -p passlist```

Command: ```brutespray -H ssh://127.0.0.1 -C root:root```

# Command Line Options

| Flag | Description | Example |
|------|-------------|---------|
| `-u` | Username or user list to bruteforce. For SMBNT and RDP, use domain\\username format (e.g., CORP\\jdoe) | `-u admin` or `-u userlist.txt` |
| `-p` | Password or password file to use for bruteforce | `-p password` or `-p passlist.txt` |
| `-C` | Specify a combo wordlist delimited by ':', example: user1:password | `-C root:root` |
| `-o` | Directory containing successful attempts (default: brutespray-output) | `-o results` |
| `-t` | Number of threads per host (default: 10) | `-t 20` |
| `-T` | Number of hosts to bruteforce at the same time (default: 5) | `-T 10` |
| `-socks5` | SOCKS5 proxy to use for bruteforce | `-socks5 socks5://user:pass@host:port` |
| `-iface` | Bind to this interface's IP for all connections; if omitted, the kernel chooses the source per destination | `-iface tun0` |
| `-s` | Service type: ssh, ftp, smtp, etc; Default all | `-s ssh,ftp` |
| `-S` | List all supported services | `-S` |
| `-f` | File to parse; Supported: Nmap, Nessus, Nexpose, Lists, etc | `-f nmap.gnmap` |
| `-H` | Target in the format service://host:port, CIDR ranges supported, default port will be used if not specified | `-H ssh://192.168.1.1:22` |
| `-q` | Suppress the banner | `-q` |
| `-w` | Set timeout delay of bruteforce attempts (default: 5s) | `-w 10s` |
| `-r` | Amount of times to retry after receiving connection failed (default: 3) | `-r 5` |
| `-P` | Print found hosts parsed from provided host and file arguments | `-P` |
| `-d` | Domain to use for RDP authentication (optional) | `-d CORP` |
| `-nc` | Disable colored output | `-nc` |
| `-summary` | Generate comprehensive summary report with statistics | `-summary` |
| `-no-stats` | Disable statistics tracking for better performance | `-no-stats` |
| `-stop-on-success` | Stop testing a host after finding valid credentials | `-stop-on-success` |
| `-silent` | Suppress per-attempt console logs (still records successes and summary) | `-silent` |
| `-log-every` | Print every N attempts when not in silent mode (default: 1) | `-log-every 100` |
| `-rate` | Per-host rate limit in attempts/second (0 = unlimited) | `-rate 10` |
| `-spray` | Spray mode: try each password across all users before next password (avoids lockouts) | `-spray` |
| `-spray-delay` | Delay between password rounds in spray mode (default: 30m) | `-spray-delay 15m` |
| `-resume` | Resume from a checkpoint file (saved automatically on interrupt) | `-resume brutespray-checkpoint.json` |
| `-checkpoint` | Checkpoint file path for resume capability (default: brutespray-checkpoint.json) | `-checkpoint myrun.json` |
| `-config` | YAML config file (CLI flags override config values) | `-config engagement.yaml` |
| `--no-tui` | Disable interactive terminal UI, use legacy output mode | `--no-tui` |

# Examples

<img src="brutespray.gif" width="512">

#### Using Custom Wordlists:

```brutespray -f nmap.gnmap -u /usr/share/wordlist/user.txt -p /usr/share/wordlist/pass.txt -t 5 ```

#### Brute-Forcing Specific Services:

```brutespray -f nmap.gnmap -u admin -p password -s ftp,ssh,telnet -t 5 ```

#### Specific Credentials:
   
```brutespray -f nmap.gnmap -u admin -p password -t 5 ```

#### Use Nmap XML Output

```brutespray -f nmap.xml -u admin -p password -t 5 ```

#### Use JSON Output

```brutespray -f out.json -u admin -p password -t 5 ```

#### Bruteforce a CIDR range

```brutespray -H ssh://10.1.1.0/24:22 -t 1000```

#### Enhanced Output and Statistics

Brutespray now includes comprehensive output and statistics tracking:

**Summary Report:**
```bash
brutespray -f nmap.gnmap -u admin -p password -summary
```

This generates:
- `brutespray-summary.json` - Machine-readable JSON report
- `brutespray-summary.csv` - CSV format for analysis
- `brutespray-summary.txt` - Human-readable summary
- `brutespray-msf.rc` - Metasploit resource script for found credentials
- `brutespray-nxc.sh` - NetExec (CrackMapExec) commands for found credentials
- Console output with key statistics

**Disable Statistics (for performance):**
```bash
brutespray -f nmap.gnmap -u admin -p password -no-stats
```

**Output Statistics Include:**
- Session duration and timing
- Total attempts and success rates
- Connection vs authentication errors
- Performance metrics (attempts/second, response times)
- Service and host breakdown
- Successful credentials list
- Peak concurrency levels

#### SOCKS5 Proxy Support

Brutespray supports SOCKS5 proxies for all services. You can use different formats:

**Basic SOCKS5 proxy:**
```brutespray -H ssh://10.1.1.0/24:22 -socks5 127.0.0.1:1080```

**SOCKS5 with authentication:**
```brutespray -H ssh://10.1.1.0/24:22 -socks5 socks5://user:pass@127.0.0.1:1080```

**SOCKS5 with hostname resolution (socks5h):**
```brutespray -H ssh://10.1.1.0/24:22 -socks5 socks5h://user:pass@proxy.example.com:1080```

**Full URL format:**
```brutespray -H ssh://10.1.1.0/24:22 -socks5 socks5://user:pass@proxy.example.com:1080```

#### Network Interface Support

Specify a specific network interface for all connections:

```brutespray -H ssh://10.1.1.0/24:22 -iface tun0```

#### Print Found Services

```brutespray -f nessus.nessus -P -q```

<img src="https://i.imgur.com/97ENS23.png" width="500">

#### Advanced Threading and Performance

**High-performance bruteforce with custom threading:**
```brutespray -f nmap.gnmap -u admin -p password -t 50 -T 10```

**Conservative approach with lower resource usage:**
```brutespray -f nmap.gnmap -u admin -p password -t 5 -T 2```

#### RDP with Domain Authentication

```brutespray -H rdp://192.168.1.100:3389 -u admin -p password -d CORP```

#### Timeout and Retry Configuration

**Custom timeout and retry settings:**
```brutespray -f nmap.gnmap -u admin -p password -w 10s -r 5```

#### Disable Color Output

```brutespray -f nmap.gnmap -u admin -p password -nc```

#### Credential Spray Mode

Spray mode tries each password across all users before moving to the next password, with a configurable delay between rounds. This avoids account lockout policies that trigger on consecutive failed attempts per user.

```brutespray -f nmap.gnmap -u userlist.txt -p passlist.txt -spray -spray-delay 15m```

#### Resume Interrupted Scans

Brutespray automatically saves a checkpoint file during execution. If interrupted (Ctrl+C), resume from where you left off:

```brutespray -f nmap.gnmap -u admin -p passlist.txt -resume brutespray-checkpoint.json```

#### Config File

Use a YAML config file for per-engagement settings. CLI flags always override config values:

```brutespray -config engagement.yaml -t 20```

Example `engagement.yaml`:
```yaml
threads: 20
host_parallelism: 10
timeout: 10s
retry: 5
socks5: "socks5://127.0.0.1:9050"
stop_on_success: true
summary: true
spray: true
spray_delay: 30m
hosts:
  - "ssh://10.0.0.0/24:22"
  - "rdp://10.0.0.0/24:3389"
```

#### LDAP Bruteforce

```brutespray -H ldap://10.0.0.1:389 -u "cn=admin,dc=example,dc=com" -p passlist.txt```

```brutespray -H ldaps://10.0.0.1:636 -u "cn=admin,dc=example,dc=com" -p passlist.txt```

#### WinRM Bruteforce

```brutespray -H winrm://10.0.0.1:5985 -u administrator -p passlist.txt```

# Supported Services

* ssh
* ftp
* telnet
* mssql
* postgresql
* imap
* pop3
* smbnt
* smtp
* snmp
* mysql
* vmauthd
* vnc
* mongodb
* nntp
* asterisk
* teamspeak
* oracle
* xmpp
* rdp
* redis
* ldap
* ldaps
* winrm
* http (basic auth) - *manual targeting only*
* https (basic auth) - *manual targeting only*

# Services in Beta
* asterisk
* nntp
* oracle
* xmpp
* rdp
* ldap / ldaps
* winrm

Feel free to open an issue if these work, or if you have any issues

# SOCKS5 Proxy Features

Brutespray includes comprehensive SOCKS5 proxy support with the following features:

- **Authentication Support**: Username/password authentication for SOCKS5 proxies
- **Hostname Resolution**: Support for both local (socks5://) and remote (socks5h://) hostname resolution
- **Interface Binding**: All proxy connections bind to the specified network interface
- **Connection Pooling**: Optimized connection management for better performance
- **Error Handling**: Comprehensive error handling and reporting for proxy connections
- **All Services**: SOCKS5 proxy support works across all supported services

# Network Interface Features

- **Interface Selection**: Use `-iface <name>` to bind all connections to that interface's IPv4 address
- **No binding when omitted**: If `-iface` is not set, no local address is bound; the kernel picks the source based on the route to each target (so VPN/tun0 and dual-homed setups work without specifying an interface)
- **Proxy Integration**: Network interface binding works seamlessly with SOCKS5 proxies

# Data Specs
```json
{"host":"127.0.0.1","port":"3306","service":"mysql"}
{"host":"127.0.0.10","port":"3306","service":"mysql"}
```
If using Nexpose, export the template `XML Export`. 

If using Nessus, export your `.nessus` file.

List example
```
ssh:127.0.0.1:22
ftp:127.0.0.1:21
...
```
Combo wordlist example
```
user:pass
user1:pass1
user2:pass2
user3:pass
user4:pass1
...
```

# Embedded Wordlists

Brutespray ships with curated default wordlists embedded directly in the binary — no external downloads needed. Wordlists are organized via a manifest system with shared base lists and per-service overrides, keeping the binary compact while covering all supported protocols. You can still override with your own wordlists using `-u` and `-p`.

# Performance Features

- **Per-Host Threading**: Each host gets its own thread pool for optimal performance
- **Host Parallelism**: Control how many hosts are processed simultaneously
- **Connection Pooling**: Reuses connections for better performance
- **Dynamic Performance Tracking**: Monitors response times and success rates
- **Circuit Breaker**: Automatically skips hosts after consecutive connection failures
- **Rate Limiting**: Per-host throttling to avoid detection or server overload
- **Graceful Shutdown**: Proper cleanup, checkpoint save, and resource management
- **Progress Tracking**: Real-time progress bars and status updates
- **Resume/Checkpoint**: Save progress on interrupt and resume later

# Pentesting Integration

- **Metasploit**: `--summary` generates `.rc` resource scripts you can load directly with `msfconsole -r`
- **NetExec/CrackMapExec**: `--summary` generates shell scripts with `nxc` commands for found credentials
- **Credential Spraying**: `--spray` mode with configurable delays to avoid account lockouts
- **Config Files**: YAML configs for repeatable per-engagement settings

# Planned Features

* ~~Add domain option for RDP, SMB~~
* ~~Ability to set proxy~~
* ~~Ability to select interface~~
* ~~More modules~~
* ~~Better connection handling~~
* ~~Interactive Terminal UI~~
* ~~Embedded wordlists~~
* HTTP form-based and digest authentication
* SNMP v1/v3 support

# Star History

[![Star History Chart](https://api.star-history.com/svg?repos=x90skysn3k/brutespray&type=Date)](https://star-history.com/#x90skysn3k/brutespray&Date)
