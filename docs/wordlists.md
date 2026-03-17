# Wordlist System

## Overview

Brutespray ships with curated credential wordlists compiled directly into the binary via `//go:embed`. No external files are needed — the binary is self-contained and works out of the box. When you supply `-u`, `-p`, or `-C`, your files take precedence and the embedded wordlists are not used.

## Architecture: Three Layers

Wordlists are organized into three tiers that compose together per service:

```
Base lists        → shared across many services  (wordlist/_base/)
Layer lists       → category-specific additions  (wordlist/_layers/)
Service overrides → per-service exact tuning     (wordlist/overrides/<service>/)
```

**Base lists** — broadly applicable credentials used by most services:
- `users-sysadmin.txt` — common sysadmin/infrastructure usernames
- `users-email.txt` — email-style usernames for mail services
- `passwords-common.txt` — universal common passwords
- `passwords-seasonal.txt` — year/season-aware passwords (e.g. `Spring2024!`)

**Layer lists** — category additions layered on top of base passwords:
- `passwords-os-infra.txt` — OS and infrastructure default passwords
- `passwords-network.txt` — networking device defaults
- `passwords-web.txt` — web application defaults
- `passwords-sql.txt` — database-specific passwords

**Service overrides** — per-service `user.txt` / `password.txt` files in `wordlist/overrides/<service>/` for services that need exact tuning (e.g. MySQL, MongoDB, LDAP).

## The Manifest

`wordlist/manifest.yaml` is the central configuration file that wires the layers together. It defines named references to base/layer files, then composes them per service.

```yaml
generated: "2026-03-05T00:00:00Z"
seasonal_range: [2023, 2027]   # years used for seasonal password generation

bases:
  common_passwords: "_base/passwords-common.txt"
  seasonal_passwords: "_base/passwords-seasonal.txt"
  sysadmin_users: "_base/users-sysadmin.txt"
  email_users: "_base/users-email.txt"

layers:
  os_infra: "_layers/passwords-os-infra.txt"
  network:  "_layers/passwords-network.txt"
  web:      "_layers/passwords-web.txt"
  sql:      "_layers/passwords-sql.txt"

services:
  # SSH: base users + common/seasonal passwords + OS-infra layer
  ssh:
    users:     [sysadmin_users]
    passwords: [common_passwords, seasonal_passwords, os_infra]

  # MySQL: full service-specific override lists
  mysql:
    users:     ["overrides/mysql/user.txt"]
    passwords: ["overrides/mysql/password.txt"]

  # IMAP: email users + common/seasonal (no layer)
  imap:
    users:     [email_users]
    passwords: [common_passwords, seasonal_passwords]

  # POP3: alias to imap — no duplication
  pop3:
    alias: imap

  # HTTPS: alias to http
  https:
    alias: http
```

**Aliases** (`https → http`, `ldaps → ldap`, `ftps → ftp`, `pop3 → imap`) share wordlists without duplicating definitions.

**`seasonal_range`** drives the `brutespray wordlist seasonal` subcommand, which generates year-aware passwords (e.g. `Winter2025!`, `2025@jan`) for the specified range.

## How a Service Gets Its Wordlist

When no `-u` / `-p` flags are supplied, brutespray resolves wordlists at runtime:

```
CLI: no -u / -p flags
  → GetUsersAndPasswords() [modules/calc.go]
    → GetUsersFromDefaultWordlist(version, service) [modules/wordlist.go]
        1. Try local manifest.yaml on disk
           (~/.config/brutespray/wordlist/, /usr/share/brutespray/wordlist/, etc.)
        2. Fall back to embedded manifest.yaml (//go:embed)
        3. Fall back to flat file / GitHub download
        → Result cached in WordlistCache
```

The local manifest path is checked first, allowing advanced users to override wordlists without rebuilding the binary. If not found, the embedded copy (compiled into the binary at build time) is used.

Results are cached in `WordlistCache` so repeated calls for the same service within a run pay no disk or embed I/O cost.

## Deduplication and Merge Order

`LoadWordlist` merges multiple source lists in the order they are declared in the manifest, deduplicating by insertion order. If a password appears in both `common_passwords` and a service override, it appears exactly once at the position of its first occurrence.

For example, `passwords: [common_passwords, seasonal_passwords, os_infra]` produces a single deduplicated list: common passwords first, then any seasonal entries not already present, then any OS-infra entries not already present.

## Overriding Defaults

Override wordlists at the CLI level without changing anything else:

```bash
# Fully custom usernames and passwords
brutespray -H ssh://target:22 -u users.txt -p rockyou.txt

# Custom username, default embedded passwords
brutespray -H mysql://target:3306 -u root

# Combo file — wordlist resolution is skipped entirely
brutespray -H smtp://target:25 -C combo.txt
```

When `-u` or `-p` is supplied, the embedded wordlist for that component is not loaded. When `-C` is used, both are skipped.

## Customizing the Manifest

For contributors or power users who want to tune or extend wordlists:

1. Clone the repository
2. Edit `wordlist/manifest.yaml` — add or modify service definitions
3. Add new credential files to `wordlist/overrides/<service>/` or `wordlist/_base/`
4. Rebuild the binary: `go build -o brutespray .`

The `//go:embed wordlist/` directive in `wordlist/embed.go` re-embeds all files at build time.

### Wordlist Subcommands

```bash
brutespray wordlist seasonal     # Generate seasonal passwords for the configured year range
brutespray wordlist validate     # Validate wordlists and check manifest integrity
brutespray wordlist build        # Build flat wordlists from the manifest
brutespray wordlist research     # AI-powered wordlist research via Ollama
brutespray wordlist merge        # Merge research candidates into wordlists
brutespray wordlist download -o path  # Download rockyou.txt
```
