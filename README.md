# Brutespray

![Version](https://img.shields.io/badge/Version-2.4.0-red)[![goreleaser](https://github.com/x90skysn3k/brutespray/actions/workflows/release.yml/badge.svg)](https://github.com/x90skysn3k/brutespray/actions/workflows/release.yml)[![Go Report Card](https://goreportcard.com/badge/github.com/x90skysn3k/brutespray)](https://goreportcard.com/report/github.com/x90skysn3k/brutespray)

Created by: Shane Young/@t1d3nio && Jacob Robles/@shellfail 

Inspired by: Leon Johnson/@sho-luv

# Description
Brutespray has been re-written in Golang, eliminating the requirement for additional tools. This enhanced version is more extensive and operates at a significantly faster pace than its Python counterpart. As of now, Brutespray accepts input from Nmap's GNMAP/XML output, newline-separated JSON files, Nexpose's XML Export feature, Nessus exports in .nessus format, and various lists. Its intended purpose is for educational and ethical hacking research only; do not use it for illegal activities.

<img src="https://i.imgur.com/6fQI6Qs.png" width="500">

# Install

```
go install github.com/x90skysn3k/brutespray@latest
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
| `-iface` | Specific network interface to use for bruteforce traffic | `-iface tun0` |
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
* http (basic auth) - *manual targeting only*
* https (basic auth) - *manual targeting only*

# Services in Beta
* asterisk
* nntp
* oracle
* xmpp
* rdp

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

- **Interface Selection**: Specify any network interface for all connections
- **Automatic Detection**: Falls back to default interface if specified interface is unavailable
- **IPv4 Address Binding**: All connections bind to the IPv4 address of the specified interface
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

# Performance Features

- **Per-Host Threading**: Each host gets its own thread pool for optimal performance
- **Host Parallelism**: Control how many hosts are processed simultaneously
- **Connection Pooling**: Reuses connections for better performance
- **Dynamic Performance Tracking**: Monitors response times and success rates
- **Graceful Shutdown**: Proper cleanup and resource management
- **Progress Tracking**: Real-time progress bars and status updates

# Planned Features

* ~~Add domain option for RDP, SMB~~
* ~~Ability to set proxy~~
* ~~Ability to select interface~~
* More modules
* ~~Better connection handling~~

# Star History

[![Star History Chart](https://api.star-history.com/svg?repos=x90skysn3k/brutespray&type=Date)](https://star-history.com/#x90skysn3k/brutespray&Date)
