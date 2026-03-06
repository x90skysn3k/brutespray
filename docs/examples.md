# Examples

## Basic Usage

**Nmap GNMAP input:**
```bash
brutespray -f nmap.gnmap -u admin -p password
```

**Nmap XML input:**
```bash
brutespray -f nmap.xml -u admin -p password
```

**Nessus input:**
```bash
brutespray -f scan.nessus -u admin -p password
```

**JSON input:**
```bash
brutespray -f hosts.json -u admin -p password
```

## Targeting

**Single host:**
```bash
brutespray -H ssh://192.168.1.1:22 -u admin -p passlist.txt
```

**CIDR range:**
```bash
brutespray -H ssh://10.1.1.0/24:22 -u root -p passlist.txt
```

**Multiple targets:**
```bash
brutespray -H ssh://10.0.0.1:22 -H rdp://10.0.0.2:3389 -u admin -p passlist.txt
```

**Combo credentials:**
```bash
brutespray -H ssh://10.0.0.1:22 -C root:root
```

## Wordlists

**Custom user and password lists:**
```bash
brutespray -f nmap.gnmap -u /usr/share/wordlists/users.txt -p /usr/share/wordlists/pass.txt
```

**Combo wordlist (user:pass per line):**
```bash
brutespray -f nmap.gnmap -C combos.txt
```

## Service Filtering

**Specific services only:**
```bash
brutespray -f nmap.gnmap -u admin -p password -s ftp,ssh,telnet
```

**Print discovered services before attacking:**
```bash
brutespray -f nmap.gnmap -P -q
```

## Threading and Performance

**High-performance (50 threads/host, 10 hosts):**
```bash
brutespray -f nmap.gnmap -u admin -p password -t 50 -T 10
```

**Conservative (5 threads/host, 2 hosts):**
```bash
brutespray -f nmap.gnmap -u admin -p password -t 5 -T 2
```

**Rate-limited (10 attempts/sec per host):**
```bash
brutespray -f nmap.gnmap -u admin -p password -rate 10
```

## Password Spraying

**Spray with 15-minute delay between rounds:**
```bash
brutespray -f nmap.gnmap -u userlist.txt -p passlist.txt -spray -spray-delay 15m
```

## Proxy and Network

**SOCKS5 proxy:**
```bash
brutespray -H ssh://10.1.1.0/24:22 -socks5 127.0.0.1:1080
```

**SOCKS5 with authentication:**
```bash
brutespray -H ssh://10.1.1.0/24:22 -socks5 socks5://user:pass@proxy:1080
```

**Bind to specific interface:**
```bash
brutespray -H ssh://10.1.1.0/24:22 -iface tun0
```

## Resume and Checkpoints

**Resume an interrupted scan:**
```bash
brutespray -f nmap.gnmap -u admin -p passlist.txt -resume brutespray-checkpoint.json
```

**Custom checkpoint path:**
```bash
brutespray -f nmap.gnmap -u admin -p passlist.txt -checkpoint myengagement.json
```

## Domain Authentication

**RDP with domain:**
```bash
brutespray -H rdp://192.168.1.100:3389 -u admin -p passlist.txt -d CORP
```

**LDAP with DN:**
```bash
brutespray -H ldap://10.0.0.1:389 -u "cn=admin,dc=example,dc=com" -p passlist.txt
```

## Output and Reporting

**Generate summary reports:**
```bash
brutespray -f nmap.gnmap -u admin -p password -summary
```

**Silent mode (successes only):**
```bash
brutespray -f nmap.gnmap -u admin -p password -silent
```

**Log every 100th attempt:**
```bash
brutespray -f nmap.gnmap -u admin -p password -log-every 100
```

## Config File

**Use a YAML config:**
```bash
brutespray -config engagement.yaml
```

**Override config values with flags:**
```bash
brutespray -config engagement.yaml -t 50 -T 20
```

## Stop on Success

**Stop testing a host after finding valid credentials:**
```bash
brutespray -f nmap.gnmap -u admin -p passlist.txt -stop-on-success
```
