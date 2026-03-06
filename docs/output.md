# Output and Reporting

## Output Directory

Results are saved to `brutespray-output/` by default. Override with `-o`:

```bash
brutespray -f nmap.gnmap -u admin -p password -o engagement-results
```

Successful credentials are written to per-service files in the output directory as they are found.

## Summary Reports

Generate comprehensive reports with `-summary`:

```bash
brutespray -f nmap.gnmap -u admin -p password -summary
```

This produces:

| File | Format | Description |
|------|--------|-------------|
| `brutespray-summary.json` | JSON | Machine-readable full report |
| `brutespray-summary.csv` | CSV | Tabular results for spreadsheets/analysis |
| `brutespray-summary.txt` | Text | Human-readable summary |
| `brutespray-msf.rc` | Metasploit RC | Resource script for `msfconsole -r` |
| `brutespray-nxc.sh` | Shell script | NetExec/CrackMapExec commands |

## Statistics

When statistics tracking is enabled (default), the summary includes:

- Session duration and timing
- Total attempts, successes, and failures
- Connection vs authentication error breakdown
- Success rate percentage
- Attempts per second
- Average response time
- Peak concurrency
- Per-service and per-host breakdown
- Full list of found credentials

## Pentesting Integration

### Metasploit

The `-summary` flag generates a `.rc` resource script with auxiliary modules pre-configured for each found credential:

```bash
msfconsole -r brutespray-msf.rc
```

### NetExec / CrackMapExec

The `-summary` flag also generates a shell script with `nxc` commands:

```bash
chmod +x brutespray-nxc.sh
./brutespray-nxc.sh
```

## Controlling Output Verbosity

| Flag | Effect |
|------|--------|
| `-silent` | Suppress per-attempt logs; successes and summary still recorded |
| `-log-every N` | Print every Nth attempt (e.g., `-log-every 100`) |
| `-no-stats` | Disable statistics tracking entirely |
| `-nc` | Disable colored output |
| `-q` | Suppress the banner |
| `--no-tui` | Use legacy text output instead of interactive TUI |
