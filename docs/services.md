# Supported Services

Brutespray supports 24 protocols. Services marked as **beta** may have edge cases — please [open an issue](https://github.com/x90skysn3k/brutespray/issues) if you encounter problems.

| Service | Default Port | Status | Notes |
|---------|-------------|--------|-------|
| ssh | 22 | Stable | |
| ftp | 21 | Stable | |
| telnet | 23 | Stable | |
| smtp | 25, 587 | Stable | |
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
| rdp | 3389 | Stable | Use `-d DOMAIN` for domain auth |
| http | 80 | Stable | Basic auth only, manual targeting (`-H`) |
| https | 443 | Stable | Basic auth only, manual targeting (`-H`) |
| vmauthd | 902 | Stable | VMware authentication daemon |
| teamspeak | 10011 | Stable | ServerQuery interface |
| asterisk | 5038 | Beta | AMI (Asterisk Manager Interface) |
| nntp | 119 | Beta | News server auth |
| oracle | 1521 | Beta | TNS listener |
| xmpp | 5222 | Beta | Jabber/XMPP chat |
| ldap | 389 | Beta | Use full DN: `cn=admin,dc=example,dc=com` |
| ldaps | 636 | Beta | LDAP over TLS, same DN format |
| winrm | 5985 | Beta | Windows Remote Management |

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
Only basic authentication is supported. Must use manual targeting:
```bash
brutespray -H http://10.0.0.1:8080 -u admin -p passlist.txt
```

List all available services:
```bash
brutespray -S
```
