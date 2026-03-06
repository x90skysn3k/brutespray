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
| **Settings** | Live adjustment of threads and parallelism |

## Keybindings

| Key | Action |
|-----|--------|
| `←` / `→` | Switch tabs |
| `↓` | Enter content area from tab bar |
| `↑` / `↓` | Scroll or select within content |
| `←` / `→` | Adjust values in Settings tab |
| `space` | Pause/resume selected host (By Host tab) |
| `esc` | Pause all hosts |
| `enter` | Resume all paused hosts |
| `ctrl+c` × 2 | Quit (press twice within 2 seconds) |

Vim-style keys (`h`/`j`/`k`/`l`) also work for navigation.

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

## Disabling the TUI

For scripts, CI/CD, or piping output:

```bash
brutespray -f nmap.gnmap -u admin -p password --no-tui
```

The TUI is also automatically disabled when stdout is not a terminal (e.g., piped to a file).
