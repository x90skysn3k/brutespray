# Brutespray

![Version](https://img.shields.io/badge/Version-2.5.5-red)[![goreleaser](https://github.com/x90skysn3k/brutespray/actions/workflows/release.yml/badge.svg)](https://github.com/x90skysn3k/brutespray/actions/workflows/release.yml)[![Go Report Card](https://goreportcard.com/badge/github.com/x90skysn3k/brutespray/v2)](https://goreportcard.com/report/github.com/x90skysn3k/brutespray/v2)

Created by: Shane Young/@t1d3nio && Jacob Robles/@shellfail

Inspired by: Leon Johnson/@sho-luv

## Description

Brutespray automatically attempts default credentials on discovered services. It takes scan output from Nmap (GNMAP/XML), Nessus, Nexpose, JSON, and lists, then brute-forces credentials across 24+ protocols in parallel. Built in Go with an interactive terminal UI, embedded wordlists, and resume capability.

<img src="https://i.imgur.com/6fQI6Qs.png" width="500">

## Quick Install

```bash
go install github.com/x90skysn3k/brutespray/v2@latest
```

[Release Binaries](https://github.com/x90skysn3k/brutespray/releases) | [Build from Source](docs/installation.md) | [Docker](docs/installation.md#docker)

## Quick Start

```bash
# From Nmap scan output
brutespray -f nmap.gnmap -u admin -p password

# Target a specific host
brutespray -H ssh://192.168.1.1:22 -u admin -p passlist.txt

# CIDR range
brutespray -H ssh://10.1.1.0/24:22 -u root -p passlist.txt

# Combo credentials
brutespray -H ssh://10.0.0.1:22 -C root:root
```

See [all examples](docs/examples.md) for more usage patterns.

## Demo

<img src="brutespray.gif" width="512">

## Features

- **24+ protocols** — SSH, FTP, RDP, SMB, MySQL, PostgreSQL, Redis, LDAP, WinRM, and [more](docs/services.md)
- **Interactive TUI** — Tabbed views, live settings, pause/resume hosts ([details](docs/tui.md))
- **Multiple input formats** — Nmap GNMAP/XML, Nessus, Nexpose, JSON, lists ([details](docs/usage.md))
- **Password spray mode** — Lockout-aware spraying with configurable delays ([details](docs/advanced.md#password-spray-mode))
- **SOCKS5 proxy** — Full proxy support with authentication ([details](docs/advanced.md#socks5-proxy))
- **Resume & checkpoint** — Interrupt with Ctrl+C, resume later ([details](docs/advanced.md#resume-and-checkpoints))
- **Embedded wordlists** — Curated defaults compiled into the binary ([details](docs/advanced.md#embedded-wordlists))
- **Summary reports** — JSON, CSV, Metasploit RC, NetExec scripts ([details](docs/output.md))
- **Performance tuning** — Dynamic threading, circuit breaker, rate limiting ([details](docs/advanced.md#performance-tuning))
- **YAML config files** — Per-engagement settings ([details](docs/usage.md#config-file))

## Supported Services

`ssh` `ftp` `telnet` `smtp` `imap` `pop3` `mysql` `postgres` `mssql` `mongodb` `redis` `vnc` `snmp` `smbnt` `rdp` `http` `https` `vmauthd` `teamspeak` `asterisk` `nntp` `oracle` `xmpp` `ldap` `ldaps` `winrm`

Full details and service-specific notes: [docs/services.md](docs/services.md)

Print discovered services from a scan file with `-P -q`:

<img src="https://i.imgur.com/97ENS23.png" width="500">

## Documentation

| Guide | Description |
|-------|-------------|
| [Installation](docs/installation.md) | Go install, release binaries, build from source, Docker |
| [Usage](docs/usage.md) | CLI flags, config files, input formats |
| [Services](docs/services.md) | All 24 protocols with ports, status, and notes |
| [Examples](docs/examples.md) | Common usage patterns and recipes |
| [Interactive TUI](docs/tui.md) | Keybindings, tabs, live settings |
| [Advanced](docs/advanced.md) | Spray mode, proxy, resume, performance tuning |
| [Output & Reporting](docs/output.md) | Summary reports, Metasploit/NetExec integration |

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=x90skysn3k/brutespray&type=Date)](https://star-history.com/#x90skysn3k/brutespray&Date)
