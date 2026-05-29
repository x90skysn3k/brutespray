# Pipeline integration

Brutespray accepts targets on stdin and auto-detects the input format,
making it a natural terminator for modern recon pipelines.

Supported input formats:

- **naabu** — bare `host:port` lines
- **Nerva URI** — `scheme://host:port` lines (e.g. `ssh://10.0.0.5:22`)
- **Nerva JSON** — newline-delimited JSON objects with `ip`/`port`/`protocol`
- **fingerprintx JSON** — newline-delimited JSON objects with `host`/`port`/`service`
- **masscan JSON** — masscan `-oJ` array of host records

## naabu → brutespray

```
naabu -host 10.0.0.0/24 -p 22,3306,3389,5984 -silent \
  | brutespray -u root -P wordlist/_base/password
```

naabu emits `host:port` lines; brutespray maps each port to its canonical
service via the embedded default-port table.

## naabu → fingerprintx → brutespray

```
naabu -host 10.0.0.0/24 -silent \
  | fingerprintx --json \
  | brutespray -u root -P wordlist/_base/password
```

fingerprintx classifies the service explicitly — brutespray uses that
directly instead of falling back to the port-table.

## masscan → brutespray

```
masscan -p22,3389,5984 10.0.0.0/24 -oJ - \
  | brutespray --no-badkeys -u admin -p admin
```

masscan's JSON array is decoded; only open ports survive; closed and
filtered are dropped silently.

## SSH bad-keys only

```
masscan -p22 10.0.0.0/24 -oJ - \
  | brutespray --badkeys-only --output-format json -o results.jsonl
```

Skips password attempts entirely. Each successful match emits a
`type:badkey` JSONL record carrying the vendor and CVE.

## RDP recon scan

```
naabu -host 10.0.0.0/24 -p 3389 -silent \
  | brutespray -s rdp -u test -p test --output-format json -o rdp-findings.jsonl
```

The NLA fingerprint and sticky-keys probe run before any credential
attempts. Findings stream into the same JSONL output channel as auth
attempts — filter by `type=="finding"` downstream.
