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

## HTTP Form Brute Forcing

**Login form with failure detection:**
```bash
brutespray -H "http-form://10.0.0.1:8080" -u admin -p passlist.txt \
  -m "url:/login" -m "body:username=%U&password=%W" -m "fail:Invalid credentials"
```

**Login form with success detection:**
```bash
brutespray -H "http-form://10.0.0.1:8080" -u admin -p passlist.txt \
  -m "url:/login" -m "body:user=%U&pass=%W" -m "success:Dashboard"
```

**GET-based login with redirect following:**
```bash
brutespray -H "http-form://10.0.0.1:8080" -u admin -p passlist.txt \
  -m "url:/login" -m "body:user=%U&pass=%W" -m "method:GET" \
  -m "follow:true" -m "success:Welcome"
```

**With custom cookie:**
```bash
brutespray -H "http-form://10.0.0.1:8080" -u admin -p passlist.txt \
  -m "url:/login" -m "body:user=%U&pass=%W" -m "fail:Invalid" \
  -m "cookie:PHPSESSID=abc123"
```

## HTTP Authentication Methods

**Digest auth:**
```bash
brutespray -H http://10.0.0.1:8080 -u admin -p passlist.txt -m auth:DIGEST
```

**NTLM auth:**
```bash
brutespray -H http://10.0.0.1:8080 -u admin -p passlist.txt -m auth:NTLM
```

## SMTP NTLM Authentication

```bash
brutespray -H smtp://10.0.0.1:25 -u admin -p passlist.txt -m auth:NTLM
```

## Password Generation

**All 4-digit PINs (0000-9999):**
```bash
brutespray -H ssh://10.0.0.1:22 -u admin -x 4:4:1
```

**1-4 character lowercase passwords:**
```bash
brutespray -H ssh://10.0.0.1:22 -u admin -x 1:4:a
```

**3-6 character alphanumeric:**
```bash
brutespray -H ssh://10.0.0.1:22 -u admin -x 3:6:aA1
```

## Extra Credential Checks

**Try blank password, username-as-password, and reversed username:**
```bash
brutespray -f nmap.gnmap -u admin -p passlist.txt -e nsr
```

## Pass-the-Hash with PwDump

**Auto-detected PwDump format:**
```bash
brutespray -H smbnt://10.0.0.1:445 -p hashdump.txt
```

## SSH Key Authentication

**Test SSH keys:**
```bash
brutespray -H ssh://10.0.0.1:22 -u root -p /path/to/id_rsa -m key:true
```

## SVN Repository

```bash
brutespray -H svn://10.0.0.1:3690 -u admin -p passlist.txt -m path:/svn/repo
```

## Wrapper Module

**Custom command execution:**
```bash
brutespray -H wrapper://10.0.0.1:8080 -u admin -p passlist.txt \
  -m "cmd:curl -s -o /dev/null -w '%{http_code}' -u %U:%W http://%H:%P/" \
  --allow-wrapper
```

## JSON Output

**Per-attempt JSONL output for tool integration:**
```bash
brutespray -f nmap.gnmap -u admin -p passlist.txt --output-format json --no-tui
```

## Proxy List Rotation

**Rotate through multiple SOCKS5 proxies:**
```bash
brutespray -f nmap.gnmap -u admin -p passlist.txt --proxy-list proxies.txt
```

Where `proxies.txt` contains one proxy per line:
```
socks5://proxy1:1080
socks5://user:pass@proxy2:1080
proxy3:1080
```

## FTPS (FTP over TLS)

```bash
brutespray -H ftps://10.0.0.1:990 -u admin -p passlist.txt
```
