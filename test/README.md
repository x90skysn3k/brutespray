# BruteSpray Integration Test Environment

Docker Compose environment with services that have known credentials, used for end-to-end testing of brutespray modules.

## Prerequisites

- Docker and Docker Compose v2
- `nc` (netcat) for port checks
- Go toolchain (only if brutespray binary is not already built)

## Services and Credentials

| Service        | Module   | Host Port | Username          | Password  |
|----------------|----------|-----------|-------------------|-----------|
| SSH            | ssh      | 20022     | testuser          | testpass  |
| FTP            | ftp      | 20021     | ftpuser           | ftppass   |
| SMTP           | smtp     | 20025     | test@test.local   | testpass  |
| POP3           | pop3     | 20110     | test@test.local   | testpass  |
| IMAP           | imap     | 20143     | test@test.local   | testpass  |
| HTTP Basic     | http     | 20080     | admin             | secret    |
| HTTP Digest    | http     | 20081     | admin             | secret    |
| Samba/SMB      | smbnt    | 20445     | smbuser           | smbpass   |
| MySQL          | mysql    | 23306     | root              | rootpass  |
| PostgreSQL     | postgres | 25432     | postgres          | pgpass    |
| Redis          | redis    | 26379     | default           | testpass  |
| MongoDB        | mongodb  | 27018     | admin             | mongopass |
| VNC            | vnc      | 25900     | (none)            | vncpass   |
| Telnet         | telnet   | 20023     | testuser          | testpass  |

## Quick Start

### Start the environment

```bash
cd test/
docker compose up -d
```

Wait for all health checks to pass:

```bash
docker compose ps
```

### Run all integration tests automatically

```bash
./run-integration.sh
```

This script will:
1. Start the Docker Compose environment
2. Wait for each service to become healthy
3. Run brutespray against every service with the known credentials
4. Report pass/fail for each module
5. Tear down all containers on exit

### Run brutespray manually against individual services

```bash
# SSH
brutespray -H ssh://127.0.0.1:20022 -u testuser -p testpass -nc -no-tui

# FTP
brutespray -H ftp://127.0.0.1:20021 -u ftpuser -p ftppass -nc -no-tui

# SMTP
brutespray -H smtp://127.0.0.1:20025 -u "test@test.local" -p testpass -nc -no-tui

# POP3
brutespray -H pop3://127.0.0.1:20110 -u "test@test.local" -p testpass -nc -no-tui

# IMAP
brutespray -H imap://127.0.0.1:20143 -u "test@test.local" -p testpass -nc -no-tui

# HTTP Basic Auth
brutespray -H http://127.0.0.1:20080 -u admin -p secret -m auth:BASIC -nc -no-tui

# HTTP Digest Auth
brutespray -H http://127.0.0.1:20081 -u admin -p secret -m auth:DIGEST -nc -no-tui

# Samba / SMB
brutespray -H smbnt://127.0.0.1:20445 -u smbuser -p smbpass -nc -no-tui

# MySQL
brutespray -H mysql://127.0.0.1:23306 -u root -p rootpass -nc -no-tui

# PostgreSQL
brutespray -H postgres://127.0.0.1:25432 -u postgres -p pgpass -nc -no-tui

# Redis
brutespray -H redis://127.0.0.1:26379 -u default -p testpass -nc -no-tui

# MongoDB
brutespray -H mongodb://127.0.0.1:27018 -u admin -p mongopass -nc -no-tui

# VNC
brutespray -H vnc://127.0.0.1:25900 -p vncpass -nc -no-tui

# Telnet
brutespray -H telnet://127.0.0.1:20023 -u testuser -p testpass -nc -no-tui
```

### Tear down

```bash
docker compose down -v
```

## Config Files

The `config/` directory contains configuration files mounted into the containers:

- `htpasswd` -- Apache Basic Auth password file (admin:secret)
- `htdigest` -- Apache Digest Auth password file (admin:secret, realm "Protected")
- `httpd-basic.conf` -- Apache config for Basic Auth
- `httpd-digest.conf` -- Apache config for Digest Auth
- `redis.conf` -- Redis config with `requirepass`
- `smb.conf` -- Samba configuration (reference; dperson/samba uses command-line args)

## Notes

- All host ports are in the 20000+ range to avoid conflicts with local services.
- The GreenMail image provides SMTP, POP3, and IMAP in a single container. Users are created on first login attempt, so the configured credentials work immediately.
- The telnet service uses a minimal Alpine container running busybox telnetd with a user created at startup.
- MySQL may take 20-30 seconds to initialise on first run.
- The VNC service uses theasp/novnc which provides both VNC (5900) and a web interface (8080).

## Local RDP CLI/TUI regression smoke (issue #378)

This smoke drives the actual binary, not module mocks. It requires Python 3.11+
and `openssl`; Docker, external RDP servers, and Python packages are not needed.
Every fixture listens only on `127.0.0.1`, using an ephemeral port.

```bash
go build -o /tmp/brutespray-rdp-smoke .
python3 test/smoke-rdp.py --binary /tmp/brutespray-rdp-smoke \
  --artifacts /tmp/brutespray-rdp-proof
```

Use `--help` for options, or repeat `--case NAME` to select individual cases.
The default matrix is:

| Case | Output | Hosts / concurrency | Fixture / credentials per host |
|------|--------|---------------------|--------------------------------|
| `garbage-legacy-t5` | Legacy CLI | 64 / 5 | `{0,1}` response; 1,000 × 1,000 |
| `garbage-json-t50` | JSON CLI | 64 / 50 | `{0,1}` response; 1,000 × 1,000 |
| `silent-json-t50` | JSON CLI | 64 / 50 | Accept without replying; 1,000 × 1,000 |
| `malformed-json` | JSON CLI | 64 / 50 | TLS/NLA malformed NTLM challenge; 16 |
| `healthy-json` | JSON CLI | 64 / 50 | Alternating valid versioned/unversioned NTLM challenges and explicit CredSSP rejection; 16 |
| `silent-tui-t50` | Default TUI in PTY | 64 / 50 | Accept without replying; 1,000 × 1,000 |

All cases request 30 workers per host, zero retries, the aggressive skip policy,
an explicit ten-connection-failure threshold, and disabled pre-auth RDP recon.
Dead hosts must produce **exactly ten actual TCP connections**, not merely ten
reported attempts. The fixture socket counts, session attempt events,
host-completed totals, and final checkpoint counts must agree, and every target
must complete. The five-host-concurrency case additionally proves that a queued
host starts after an earlier host completes. Large cases write only 1,000-line
username/password files, while presenting one million combinations per host.

The malformed challenge has the VERSION flag, target-name length 12 and absolute
offset 48, a 56-byte header, and only four payload bytes: the reporter's
`uint32(48 - 56) == 4294967288` case. It must fail as a connection/protocol
failure without a process panic or a recovered module panic. Healthy fixtures
must reach NTLM AUTHENTICATE and receive a real TSRequest `errorCode`
`STATUS_LOGON_FAILURE` (`0xc000006d`); all sixteen attempts must remain
authentication failures, proving the connection breaker does not trip after ten.
They are rejecting protocol peers, not successful Windows login/session tests.

The PTY case supplies a terminal size, continuously drains output, answers
terminal queries, visits By Host/Completed/Settings, changes and restores live
host parallelism, resizes twice, and pauses/resumes while sockets are active.
It waits for the rendered **All hosts completed** status and the Completed
table, then sends the documented double Ctrl+C and requires a clean exit.

Each successful case prints one JSON summary with measurable counts. A final
JSON record reports `PASS` and totals. `--timeout` defaults to 90 seconds per
case; protocol attempt deadlines are 500 ms, 2 seconds for TLS/NLA, and 3 seconds
for the interactive case. Failures exit nonzero with counts and an output suffix;
a still-running binary receives SIGQUIT to capture Go stacks before forced
cleanup. `--artifacts` preserves raw terminal/CLI transcripts, rendered completion
screens, command arguments, session logs, checkpoints, and JSON summaries. Use a
fresh artifact directory for each run. Temporary listeners, processes, TLS keys,
wordlists, and working directories are cleaned up on success or failure.
