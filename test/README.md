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
