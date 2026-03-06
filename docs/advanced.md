# Advanced Features

## Password Spray Mode

Spray mode tries each password across all users before moving to the next password. This avoids account lockout policies that trigger on consecutive failed attempts per user.

```bash
brutespray -f nmap.gnmap -u userlist.txt -p passlist.txt -spray -spray-delay 15m
```

| Flag | Description | Default |
|------|-------------|---------|
| `-spray` | Enable spray mode | disabled |
| `-spray-delay` | Delay between password rounds | 30m |

**How it works:**
1. Try `password1` against all users on all hosts
2. Wait for the spray delay
3. Try `password2` against all users on all hosts
4. Repeat until all passwords are exhausted

The circuit breaker is automatically enabled in spray mode to skip hosts that become unreachable after 5 consecutive connection failures.

## SOCKS5 Proxy

All services support SOCKS5 proxies. Supported formats:

```bash
# Basic
brutespray -H ssh://target:22 -socks5 127.0.0.1:1080

# With authentication
brutespray -H ssh://target:22 -socks5 socks5://user:pass@proxy:1080

# Remote DNS resolution (socks5h)
brutespray -H ssh://target:22 -socks5 socks5h://user:pass@proxy:1080
```

Features:
- Username/password authentication
- Local (`socks5://`) and remote (`socks5h://`) hostname resolution
- Works with all 24 supported services
- Compatible with interface binding

## Network Interface Binding

Bind all connections to a specific network interface:

```bash
brutespray -H ssh://target:22 -iface tun0
```

When omitted, the kernel selects the source address per destination, which works correctly with VPNs and dual-homed setups.

## Rate Limiting

Throttle attempts per host to avoid detection or server overload:

```bash
brutespray -f nmap.gnmap -u admin -p passlist.txt -rate 10
```

The rate is in attempts per second per host. Set to `0` (default) for unlimited.

## Resume and Checkpoints

Brutespray automatically saves progress during execution. If interrupted with Ctrl+C, resume later:

```bash
brutespray -f nmap.gnmap -u admin -p passlist.txt -resume brutespray-checkpoint.json
```

**How it works:**
- **Checkpoint file** (`.json`) — Tracks which hosts are fully completed. On resume, completed hosts are skipped entirely.
- **Session log** (`.jsonl`) — Records every attempt result. On resume, the full session history is replayed into the TUI so it appears as if the scan never stopped.
- Auto-saves every 30 seconds and on interrupt
- Pass either file to `-resume` — brutespray resolves both automatically

Custom checkpoint path:
```bash
brutespray -f nmap.gnmap -u admin -p passlist.txt -checkpoint engagement1.json
```

## Embedded Wordlists

Brutespray ships with curated default wordlists compiled into the binary. No external files are needed for basic operation.

Wordlists are organized via a manifest system with shared base lists and per-service overrides. Override with your own using `-u` and `-p`.

### Wordlist Subcommand

```bash
brutespray wordlist seasonal     # Generate seasonal passwords (current year/month)
brutespray wordlist validate     # Validate wordlists and manifest
brutespray wordlist build        # Build flat wordlists from manifest
brutespray wordlist research     # AI-powered research via Ollama
brutespray wordlist merge        # Merge research candidates into wordlists
brutespray wordlist download -o path  # Download rockyou.txt
```

## Stop on Success

Stop testing a host after finding the first valid credential:

```bash
brutespray -f nmap.gnmap -u admin -p passlist.txt -stop-on-success
```

This is per-host — other hosts continue normally. Useful for reducing noise when you only need proof of access.

## Performance Tuning

### Threading Model

| Flag | Description | Default |
|------|-------------|---------|
| `-t` | Threads per host | 10 |
| `-T` | Concurrent hosts | 5 |

Each host gets its own worker pool. Total concurrent workers = `-t` × `-T`.

### Dynamic Thread Scaling

The worker pool monitors per-host performance and adjusts thread counts:
- Fast responses (<200ms) → scales up to 2x threads
- Slow responses (>2s) → scales down to half
- High success rate → modest thread increase

### Circuit Breaker

In spray mode, the circuit breaker tracks consecutive connection failures per host. After 5 failures, the host is skipped for remaining credentials. Resets on successful connection.

### Adaptive Backoff

When a host has consecutive connection failures, workers apply exponential backoff: 2s, 4s, 8s, 16s, capped at 30s. This prevents hammering unreachable hosts.

### Connection Pooling

Connections are pooled per service with a 30-second max age. Reused connections reduce handshake overhead.

### Disabling Statistics

For very large scans, disable metrics tracking to reduce overhead:

```bash
brutespray -f nmap.gnmap -u admin -p password -no-stats
```
