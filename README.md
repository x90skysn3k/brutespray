# BruteSpray

![Version](https://img.shields.io/badge/Version-2.2.4-red)[![goreleaser](https://github.com/x90skysn3k/brutespray/actions/workflows/release.yml/badge.svg)](https://github.com/x90skysn3k/brutespray/actions/workflows/release.yml)[![Go Report Card](https://goreportcard.com/badge/github.com/x90skysn3k/brutespray)](https://goreportcard.com/report/github.com/x90skysn3k/brutespray)

Created by: Shane Young/@t1d3nio && Jacob Robles/@shellfail 

Inspired by: Leon Johnson/@sho-luv

# Description
Brutespray has been re-written in Golang, eliminating the requirement for additional tools. This enhanced version is more extensive and operates at a significantly faster pace than its Python counterpart. As of now, Brutespray accepts input from Nmap's GNMAP/XML output, newline-separated JSON files, Nexpose's XML Export feature, Nessus exports in .nessus format, and various lists. Its intended purpose is for educational and ethical hacking research only; do not use it for illegal activities.

<img src="https://i.imgur.com/6fQI6Qs.png" width="500">

# Installation

[Release Binaries](https://github.com/x90skysn3k/brutespray/releases)

To Build:

```go build -o brutespray main.go```

# Usage

If using Nmap, scan with `-oA nmap_out`.
If using Nexpose, export the template `XML Export`. 

If using Nessus, export your `.nessus` file.

Command: ```brutespray -h```

Command: ```brutespray -f nmap.gnmap -u userlist -p passlist```

Command: ```brutespray -f nmap.xml -u userlist -p passlist```

Command: ```brutespray -H ssh://127.0.0.1:22 -u userlist -p passlist```

Command: ```brutespray -H ssh://127.0.0.1 -C root:root```

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

#### Print Found Services

```brutespray -f nessus.nessus -P -q```

<img src="https://i.imgur.com/97ENS23.png" width="500">

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

# Services in Beta
* asterisk
* nntp
* oracle
* xmpp
* rdp (currently local domain is supported)

Feel free to open an issue if these work, or if you have any issues

# Services in Progress

* rdp - the issue is no one has written a good library for NLA

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

# Planned Features

* Add domain option for RDP, SMB
* Ability to set proxy
* Ability to select interface
* More modules
* Better connection handling

# Star History

[![Star History Chart](https://api.star-history.com/svg?repos=x90skysn3k/brutespray&type=Date)](https://star-history.com/#x90skysn3k/brutespray&Date)
