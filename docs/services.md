# Supported Services

Brutespray supports 35+ protocols. Services marked as **beta** may have edge cases — please [open an issue](https://github.com/x90skysn3k/brutespray/issues) if you encounter problems.

| Service | Default Port | Status | Notes |
|---------|-------------|--------|-------|
| ssh | 22 | Stable | Supports password and key auth (`-m key:true`) |
| ftp | 21 | Stable | |
| ftps | 990 | Beta | FTP over TLS |
| telnet | 23 | Stable | |
| smtp | 25, 587 | Stable | AUTH PLAIN, LOGIN, NTLM (`-m auth:NTLM`) |
| smtp-vrfy | 25 | Beta | SMTP VRFY user enumeration |
| imap | 143 | Stable | |
| pop3 | 110 | Stable | |
| mysql | 3306 | Stable | |
| postgres | 5432 | Stable | |
| mssql | 1433 | Stable | |
| mongodb | 27017 | Stable | |
| redis | 6379 | Stable | Password-only auth |
| vnc | 5900 | Stable | Password-only auth (no username) |
| snmp | 161 | Stable | Community string as password |
| smbnt | 445 | Stable | Use `-d DOMAIN` for domain auth |
| rdp | 3389 | Beta | Use `-d DOMAIN` for domain auth |
| http | 80 | Stable | Basic, Digest, NTLM auth (`-m auth:DIGEST`) |
| https | 443 | Stable | Same as HTTP over TLS |
| http-form | 80 | Beta | HTML form brute-forcing with `%U`/`%W` placeholders |
| https-form | 443 | Beta | HTTPS form brute-forcing |
| svn | 3690 | Beta | SVN repository HTTP Basic auth |
| vmauthd | 902 | Stable | VMware authentication daemon |
| teamspeak | 10011 | Stable | ServerQuery interface |
| asterisk | 5038 | Beta | AMI (Asterisk Manager Interface) |
| nntp | 119 | Beta | News server auth |
| oracle | 1521 | Beta | TNS listener |
| xmpp | 5222 | Beta | Jabber/XMPP chat |
| ldap | 389 | Beta | Use full DN: `cn=admin,dc=example,dc=com` |
| ldaps | 636 | Beta | LDAP over TLS, same DN format |
| winrm | 5985 | Beta | Windows Remote Management |
| rexec | 512 | Beta | Remote execution |
| rlogin | 513 | Beta | Remote login |
| rsh | 514 | Beta | Remote shell |
| wrapper | 0 | Beta | External command wrapper (requires `--allow-wrapper`) |

## Service-Specific Notes

### LDAP / LDAPS
The username must be a full Distinguished Name:
```bash
brutespray -H ldap://10.0.0.1:389 -u "cn=admin,dc=example,dc=com" -p passlist.txt
```

### RDP / SMB
Use `-d` for domain authentication:
```bash
brutespray -H rdp://10.0.0.1:3389 -u admin -p passlist.txt -d CORP
```

Or use `DOMAIN\user` format with `-u`:
```bash
brutespray -H smbnt://10.0.0.1:445 -u "CORP\admin" -p passlist.txt
```

### VNC / SNMP
These are password-only protocols. The `-u` flag is ignored:
```bash
brutespray -H vnc://10.0.0.1:5900 -p passlist.txt
brutespray -H snmp://10.0.0.1:161 -p communities.txt
```

### HTTP / HTTPS
Supports Basic, Digest, and NTLM authentication:
```bash
# Basic (auto-detected)
brutespray -H http://10.0.0.1:8080 -u admin -p passlist.txt

# Force Digest auth
brutespray -H http://10.0.0.1:8080 -u admin -p passlist.txt -m auth:DIGEST

# NTLM auth
brutespray -H http://10.0.0.1:8080 -u admin -p passlist.txt -m auth:NTLM
```

### HTTP Form / HTTPS Form
Brute-force HTML login forms with customizable requests:
```bash
brutespray -H "http-form://10.0.0.1:8080" -u admin -p passlist.txt \
  -m "url:/login" -m "body:username=%U&password=%W" -m "fail:Invalid credentials"
```

Parameters:
| Param | Description | Required |
|-------|-------------|----------|
| `url` | Login form path | Yes |
| `body` | POST body with `%U`/`%W` placeholders | Yes |
| `fail` | Failure string in response (absence = success) | One of fail/success |
| `success` | Success string in response | One of fail/success |
| `method` | HTTP method (default: POST) | No |
| `follow` | Follow redirects (true/false) | No |
| `cookie` | Custom cookie header | No |
| `content-type` | Content-Type (default: application/x-www-form-urlencoded) | No |

### SSH Key Authentication
Use private keys instead of passwords:
```bash
brutespray -H ssh://10.0.0.1:22 -u root -p /path/to/id_rsa -m key:true
```

### SVN
Brute-force SVN repositories over HTTP:
```bash
brutespray -H svn://10.0.0.1:3690 -u admin -p passlist.txt
```

### SMTP NTLM Authentication
```bash
brutespray -H smtp://10.0.0.1:25 -u admin -p passlist.txt -m auth:NTLM
```

### Wrapper Module
Execute arbitrary external commands with credential placeholders:
```bash
brutespray -H wrapper://10.0.0.1:8080 -u admin -p passlist.txt \
  -m "cmd:curl -s -o /dev/null -w '%{http_code}' -u %U:%W http://%H:%P/" \
  --allow-wrapper
```
Placeholders: `%H` (host), `%P` (port), `%U` (user), `%W` (password).
Exit code 0 = success, non-zero = failure.

**Security:** Requires `--allow-wrapper` flag since it executes arbitrary commands.

List all available services:
```bash
brutespray -S
```
