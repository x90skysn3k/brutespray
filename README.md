# BruteSpray

![Version](https://img.shields.io/badge/Version-2.1.7-red)[![goreleaser](https://github.com/x90skysn3k/brutespray/actions/workflows/release.yml/badge.svg)](https://github.com/x90skysn3k/brutespray/actions/workflows/release.yml)[![Go Report Card](https://goreportcard.com/badge/github.com/x90skysn3k/brutespray)](https://goreportcard.com/report/github.com/x90skysn3k/brutespray)

Created by: Shane Young/@t1d3nio && Jacob Robles/@shellfail 

Inspired by: Leon Johnson/@sho-luv

# Description
Brutespray has been updated to golang. Without needing to rely on other tools this version will be extensible to bruteforce many different services and is way faster than it's Python counterpart. Currently Brutespray takes Nmap GNMAP/XML output, newline separated JSON, Nexpose `XML Export` output, Nessus `.nessus` exports, and lists. It will bruteforce supported servics found in those files. This tool is for research purposes and not intended for illegal use. 

<img src="https://i.imgur.com/6fQI6Qs.png" width="500">

# Installation

[Release Binaries](https://github.com/x90skysn3k/brutespray/releases)

To Build:

```go build -o brutespray main.go```

# Usage

If using Nmap, scan with ```-oG nmap.gnmap``` or ```-oX nmap.xml```.

If using Nexpose, export the template `XML Export`. 

If using Nessus, export your `.nessus` file.

Command: ```brutespray -h```

Command: ```brutespray -f nmap.gnmap -u userlist -p passlist```

Command: ```brutespray -f nmap.xml -u userlist -p passlist```

Command: ```brutespray -H ssh://127.0.0.1:22 -u userlist -p passlist```

## Examples

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

# Services in Progress

* rdp
* asterisk

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
```
## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=x90skysn3k/brutespray&type=Date)](https://star-history.com/#x90skysn3k/brutespray&Date)
