# Interactive Terminal UI

Brutespray features an interactive TUI built with [Bubble Tea](https://github.com/charmbracelet/bubbletea), enabled by default on interactive terminals.

## Tabs

| Tab | Description |
|-----|-------------|
| **All** | Live scrolling log of every attempt |
| **By Host** | Attempts grouped by target, with host selector |
| **By Service** | Attempts grouped by protocol |
| **Completed** | Hosts that finished all credential attempts |
| **Successes** | Found valid credentials |
| **Errors** | Connection errors and warnings |
| **Findings** | Non-credential findings |
| **Settings** | Live adjustment of threads and parallelism |

## Findings

The Findings tab shows non-credential results with these displayed fields:

- **Severity** — how serious the finding is
- **Service** — the service or protocol associated with the finding
- **Target** — the host or endpoint the finding applies to
- **Message** — the finding details shown to the operator
- **Stable code** — an optional machine-stable identifier, when available
- **CVE** — an optional CVE identifier, when the finding maps to a known vulnerability

## Keybindings

Key hints are static: the footer always shows the same action labels, and the table below explains what each key does.

| Key | Action |
|-----|--------|
| `←` / `→` | Switch tabs while the tab bar is focused; adjust the selected value in Settings |
| `↑` / `↓` | Move focus from the tab bar into content, scroll/select rows, or move between Settings controls |
| `h` / `l` | Vim-style left/right navigation for the same focused action |
| `j` / `k` | Vim-style down/up navigation for the same focused action |
| `space` | Pause/resume the selected host in the By Host tab |
| `esc` | Pause all hosts |
| `enter` | Resume all paused hosts |
| `ctrl+c` × 2 | Quit (press twice within 2 seconds) |

## Live Settings

In the **Settings** tab, you can adjust these values while a scan is running:

- **Threads per host** — Number of concurrent workers per target
- **Concurrent hosts** — Number of hosts processed simultaneously

Changes take effect immediately. Workers scale up on the next tick; scaling down happens cooperatively as workers finish their current job.

## Status Bar

The bottom of the screen shows:
- **Progress** — Current attempt count, total, and percentage
- **Pause indicator** — Shows "⏸ PAUSED" when globally paused
- **Errors/Status** — Latest error or status message (auto-clears after 5 seconds)
- **Key hints** — Static footer with the main navigation and pause controls

## Disabling the TUI

For scripts, CI/CD, or piping output:

```bash
brutespray -f nmap.gnmap -u admin -p password --no-tui
```

The TUI is also automatically disabled when stdout is not a terminal (e.g., piped to a file).
