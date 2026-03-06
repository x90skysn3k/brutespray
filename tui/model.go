package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

// HostState tracks per-host state in the TUI.
type HostState struct {
	Host      string
	Port      int
	Service   string
	Threads   int
	Attempts  int
	Successes int
	Paused    bool
	Completed bool
	StartTime time.Time
}

// WorkerPoolController is implemented by WorkerPool to allow the TUI
// to pause/resume hosts and adjust settings without creating circular imports.
type WorkerPoolController interface {
	PauseHost(hostKey string)
	ResumeHost(hostKey string)
	PauseAll()
	ResumeAll()
	Stop()
	SetThreadsPerHost(n int)
	SetHostParallelism(n int)
	GetThreadsPerHost() int
	GetHostParallelism() int
}

// tickMsg fires periodically for stats refresh and color cycling.
type tickMsg time.Time

// splashDoneMsg signals the splash screen timer has elapsed.
type splashDoneMsg struct{}

// doneMsg signals that all work is complete.
type doneMsg struct{}

// Model is the main Bubble Tea model for the interactive TUI.
type Model struct {
	width, height int

	activeTab     Tab
	tabBarFocused bool

	allView       AllView
	hostView      HostView
	serviceView   ServiceView
	completedView CompletedView
	successView   SuccessView
	errorsView    ErrorsView
	settingsView  SettingsView

	hostStates  map[string]*HostState
	pausedHosts map[string]bool

	scheme ColorScheme

	lastCtrlC time.Time
	ctrlCHit  bool

	globalPaused bool

	pool WorkerPoolController

	totalCombinations int
	currentProgress   int

	keys KeyMap

	statusMsg     string
	statusTimeout time.Time

	// Error display
	errors []string // ring buffer of recent errors

	done    bool
	version string

	splashActive bool
}

// NewModel creates a new TUI model. resumedProgress is the number of attempts
// replayed from a previous session (used to initialize the progress counter).
func NewModel(pool WorkerPoolController, totalCombinations int, version string, resumedProgress int) Model {
	return Model{
		allView:           NewAllView(),
		hostView:          NewHostView(),
		serviceView:       NewServiceView(),
		completedView:     NewCompletedView(),
		successView:       NewSuccessView(),
		errorsView:        NewErrorsView(),
		settingsView:      NewSettingsView(pool),
		hostStates:        make(map[string]*HostState),
		pausedHosts:       make(map[string]bool),
		scheme:            NewRandomColorScheme(),
		pool:              pool,
		totalCombinations: totalCombinations,
		currentProgress:   resumedProgress,
		keys:              DefaultKeyMap(),
		tabBarFocused:     true,
		version:           version,
		splashActive:      true,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		tickCmd(),
		tea.ClearScreen,
		tea.Tick(800*time.Millisecond, func(t time.Time) tea.Msg {
			return splashDoneMsg{}
		}),
	)
}

func tickCmd() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		contentHeight := m.contentHeight()
		m.allView.SetSize(m.width, contentHeight)
		m.hostView.SetSize(m.width, contentHeight)
		m.serviceView.SetSize(m.width, contentHeight)
		m.completedView.SetSize(m.width, contentHeight)
		m.successView.SetSize(m.width, contentHeight)
		m.errorsView.SetSize(m.width, contentHeight)
		m.settingsView.SetSize(m.width, contentHeight)
		return m, nil

	case splashDoneMsg:
		m.splashActive = false
		return m, nil

	case tickMsg:
		stats := modules.GetStats()
		m.settingsView.Update(stats)
		return m, tickCmd()

	case ErrorMsg:
		errLine := strings.TrimRight(msg.Message, "\n")
		m.errors = append(m.errors, errLine)
		if len(m.errors) > 50 {
			m.errors = m.errors[len(m.errors)-50:]
		}
		m.errorsView.AddError(errLine, msg.Timestamp)
		return m, nil

	case BatchAttemptMsg:
		for _, a := range msg {
			m.currentProgress++
			m.allView.AddAttempt(a, &m.scheme)
			m.hostView.AddAttempt(a, &m.scheme)
			m.serviceView.AddAttempt(a, &m.scheme)
			if a.Success && a.Connected {
				m.successView.AddSuccess(a)
			}
			hostKey := fmt.Sprintf("%s:%d", a.Host, a.Port)
			if state, ok := m.hostStates[hostKey]; ok {
				state.Attempts++
				if a.Success && a.Connected {
					state.Successes++
				}
			}
		}
		return m, nil

	case HostStartedMsg:
		hostKey := fmt.Sprintf("%s:%d", msg.Host, msg.Port)
		m.hostStates[hostKey] = &HostState{
			Host:      msg.Host,
			Port:      msg.Port,
			Service:   msg.Service,
			Threads:   msg.Threads,
			StartTime: time.Now(),
		}
		return m, nil

	case HostCompletedMsg:
		hostKey := fmt.Sprintf("%s:%d", msg.Host, msg.Port)
		if state, ok := m.hostStates[hostKey]; ok {
			state.Completed = true
		}
		m.completedView.AddCompleted(msg)
		return m, nil

	case doneMsg:
		m.done = true
		m.setStatus("All hosts completed. Press Ctrl+C to exit.")
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	return m, nil
}

// contentHeight returns the available height for content between tab bar and status bar.
// Tab bar = 2 lines (tabs + separator), status bar = 3 lines (separator + progress + help).
func (m Model) contentHeight() int {
	h := m.height - 5 // 2 (tab bar) + 3 (status bar)
	if h < 1 {
		h = 1
	}
	return h
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Ctrl+C always works regardless of focus
	if key.Matches(msg, m.keys.Quit) {
		now := time.Now()
		if m.ctrlCHit && now.Sub(m.lastCtrlC) < 2*time.Second {
			// Don't call pool.Stop() here — it blocks waiting for workers
			// which deadlocks the event loop. Cleanup happens in executeTUI.
			return m, tea.Quit
		}
		m.ctrlCHit = true
		m.lastCtrlC = now
		m.setStatus("Press Ctrl+C again to quit")
		return m, nil
	}

	// Pause/resume always work
	switch {
	case key.Matches(msg, m.keys.Pause):
		if m.pool != nil {
			m.globalPaused = true
			m.pool.PauseAll()
			for k := range m.hostStates {
				m.pausedHosts[k] = true
			}
			m.setStatus("All hosts paused. Press Enter to resume.")
		}
		return m, nil

	case key.Matches(msg, m.keys.Resume):
		if m.pool != nil {
			m.globalPaused = false
			m.pool.ResumeAll()
			for k := range m.pausedHosts {
				delete(m.pausedHosts, k)
			}
			m.setStatus("Resumed all hosts")
		}
		return m, nil

	case key.Matches(msg, m.keys.TogglePause):
		m.toggleSelectedHost()
		return m, nil
	}

	// Focus-based navigation
	if m.tabBarFocused {
		return m.handleTabBarKeys(msg)
	}
	return m.handleContentKeys(msg)
}

func (m Model) handleTabBarKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.NextTab):
		m.activeTab = (m.activeTab + 1) % tabCount
		return m, nil

	case key.Matches(msg, m.keys.PrevTab):
		m.activeTab = (m.activeTab - 1 + tabCount) % tabCount
		return m, nil

	case key.Matches(msg, m.keys.ScrollDown):
		m.tabBarFocused = false
		return m, nil
	}

	return m, nil
}

func (m Model) handleContentKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.ScrollUp):
		switch m.activeTab {
		case TabAll:
			vp := m.allView.Viewport()
			if vp.YOffset <= 0 {
				m.tabBarFocused = true
			} else {
				vp.SetYOffset(vp.YOffset - 1)
			}
		case TabByHost:
			if !m.hostView.PrevHost() {
				m.tabBarFocused = true
			}
		case TabByService:
			if !m.serviceView.PrevService() {
				m.tabBarFocused = true
			}
		case TabSettings:
			if !m.settingsView.Prev() {
				m.tabBarFocused = true
			}
		default:
			m.tabBarFocused = true
		}
		return m, nil

	case key.Matches(msg, m.keys.ScrollDown):
		switch m.activeTab {
		case TabAll:
			vp := m.allView.Viewport()
			vp.SetYOffset(vp.YOffset + 1)
		case TabByHost:
			m.hostView.NextHost()
		case TabByService:
			m.serviceView.NextService()
		case TabSettings:
			m.settingsView.Next()
		}
		return m, nil

	case key.Matches(msg, m.keys.NextTab):
		if m.activeTab == TabSettings && m.settingsView.IsEditable() {
			m.settingsView.AdjustRight()
		}
		return m, nil

	case key.Matches(msg, m.keys.PrevTab):
		if m.activeTab == TabSettings && m.settingsView.IsEditable() {
			m.settingsView.AdjustLeft()
		}
		return m, nil
	}

	return m, nil
}

func (m *Model) toggleSelectedHost() {
	var hostKey string
	if m.activeTab == TabByHost {
		hostKey = m.hostView.SelectedHost()
	}
	if hostKey == "" || m.pool == nil {
		return
	}

	if m.pausedHosts[hostKey] {
		delete(m.pausedHosts, hostKey)
		m.pool.ResumeHost(hostKey)
		m.setStatus(fmt.Sprintf("Resumed %s", hostKey))
	} else {
		m.pausedHosts[hostKey] = true
		m.pool.PauseHost(hostKey)
		m.setStatus(fmt.Sprintf("Paused %s", hostKey))
	}
}

func (m *Model) setStatus(msg string) {
	m.statusMsg = msg
	m.statusTimeout = time.Now().Add(5 * time.Second)
}

func (m Model) View() string {
	if m.width == 0 {
		return "Initializing..."
	}

	if m.splashActive {
		return m.renderSplash()
	}

	badges := map[Tab]int{
		TabCompleted: m.completedView.Count(),
		TabSuccess:   m.successView.Count(),
		TabErrors:    m.errorsView.Count(),
	}

	tabBar := RenderTabBar(m.activeTab, m.width, &m.scheme, badges, m.tabBarFocused, m.version)

	var content string
	switch m.activeTab {
	case TabAll:
		content = m.allView.View()
	case TabByHost:
		content = m.hostView.View(&m.scheme, m.pausedHosts, m.hostStates)
	case TabByService:
		content = m.serviceView.View(&m.scheme)
	case TabCompleted:
		content = m.completedView.View(&m.scheme)
	case TabSuccess:
		content = m.successView.View(&m.scheme)
	case TabErrors:
		content = m.errorsView.View(&m.scheme)
	case TabSettings:
		content = m.settingsView.View(&m.scheme)
	}

	statusBar := m.renderStatusBar()

	// Assemble full frame, then force it to exactly m.height lines
	// to prevent ghost content from previous frames
	frame := tabBar + "\n" + content + "\n" + statusBar
	return m.fixFrameHeight(frame)
}

// fixFrameHeight ensures the frame is exactly m.height lines.
// Pads with empty lines if too short, truncates if too tall.
// This prevents ghost content from previous frames in the alt-screen.
func (m Model) fixFrameHeight(frame string) string {
	lines := strings.Split(frame, "\n")
	target := m.height
	if target < 1 {
		return frame
	}
	if len(lines) < target {
		// Pad with empty lines
		for len(lines) < target {
			lines = append(lines, "")
		}
	} else if len(lines) > target {
		// Truncate — keep the first (tab bar) and last (status bar) lines,
		// trim from content area
		lines = lines[:target]
	}
	return strings.Join(lines, "\n")
}

func (m Model) renderSplash() string {
	banner := `
                              #@                           @/
                           @@@                               @@@
                        %@@@                                   @@@.
                      @@@@@                                     @@@@%
                     @@@@@                                       @@@@@
                    @@@@@@@                  @                  @@@@@@@
                    @(@@@@@@@%            @@@@@@@            &@@@@@@@@@
                    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
                     @@*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ @@
                       @@@( @@@@@#@@@@@@@@@*@@@,@@@@@@@@@@@@@@@  @@@
                           @@@@@@ .@@@/@@@@@@@@@@@@@/@@@@ @@@@@@
                                  @@@   @@@@@@@@@@@   @@@
                                 @@@@*  ,@@@@@@@@@(  ,@@@@
                                 @@@@@@@@@@@@@@@@@@@@@@@@@
                                  @@@.@@@@@@@@@@@@@@@ @@@
                                    @@@@@@ @@@@@ @@@@@@
                                       @@@@@@@@@@@@@
                                       @@   @@@   @@
                                       @@ @@@@@@@ @@
                                         @@% @  @@
`
	logo := `
██████╗  ██████╗  ██╗   ██╗ ████████╗ ███████╗ ███████╗ ██████╗  ██████╗   █████╗  ██╗   ██╗
██╔══██╗ ██╔══██╗ ██║   ██║ ╚══██╔══╝ ██╔════╝ ██╔════╝ ██╔══██╗ ██╔══██╗ ██╔══██╗ ╚██╗ ██╔╝
██████╔╝ ██████╔╝ ██║   ██║    ██║    █████╗   ███████╗ ██████╔╝ ██████╔╝ ███████║  ╚████╔╝
██╔══██╗ ██╔══██╗ ██║   ██║    ██║    ██╔══╝   ╚════██║ ██╔═══╝  ██╔══██╗ ██╔══██║   ╚██╔╝
██████╔╝ ██║  ██║ ╚██████╔╝    ██║    ███████╗ ███████║ ██║      ██║  ██║ ██║  ██║    ██║
╚═════╝  ╚═╝  ╚═╝  ╚═════╝     ╚═╝    ╚══════╝ ╚══════╝ ╚═╝      ╚═╝  ╚═╝ ╚═╝  ╚═╝    ╚═╝`

	style := lipgloss.NewStyle().Foreground(m.scheme.Primary).Bold(true)
	versionLine := lipgloss.NewStyle().Foreground(m.scheme.Accent).Bold(true).Render(m.version)

	rendered := style.Render(banner) + "\n" + style.Render(logo) + "\n\n" + lipgloss.PlaceHorizontal(m.width, lipgloss.Center, versionLine)

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, rendered)
}

func (m Model) renderStatusBar() string {
	var pct float64
	if m.totalCombinations > 0 {
		pct = float64(m.currentProgress) / float64(m.totalCombinations) * 100
	}

	progressStyle := lipgloss.NewStyle().Foreground(m.scheme.Primary).Bold(true)
	progress := progressStyle.Render(fmt.Sprintf(" %d/%d (%.1f%%)", m.currentProgress, m.totalCombinations, pct))

	pauseStr := ""
	if m.globalPaused {
		pauseStr = lipgloss.NewStyle().Foreground(m.scheme.Warning).Bold(true).Render(" ⏸ PAUSED ")
	}

	// Show latest error or status message, truncated to fit
	infoStr := ""
	progressWidth := lipgloss.Width(progress) + lipgloss.Width(pauseStr)
	maxInfoWidth := m.width - progressWidth - 3
	if maxInfoWidth < 10 {
		maxInfoWidth = 10
	}
	if len(m.errors) > 0 {
		latest := m.errors[len(m.errors)-1]
		if len(latest) > maxInfoWidth {
			latest = latest[:maxInfoWidth-3] + "..."
		}
		infoStr = "  " + lipgloss.NewStyle().Foreground(m.scheme.Error).Render(latest)
	} else if m.statusMsg != "" && time.Now().Before(m.statusTimeout) {
		msg := m.statusMsg
		if len(msg) > maxInfoWidth {
			msg = msg[:maxInfoWidth-3] + "..."
		}
		infoStr = "  " + lipgloss.NewStyle().Foreground(m.scheme.Accent).Render(msg)
	}

	separator := lipgloss.NewStyle().
		Foreground(m.scheme.CycleColor()).
		Render(strings.Repeat("─", m.width))

	keyStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#ffffff")).Bold(true)
	descStyle := lipgloss.NewStyle().Foreground(m.scheme.Muted)
	sep := descStyle.Render(" │ ")

	helpItems := []string{
		keyStyle.Render("←/→") + descStyle.Render(" tabs"),
		keyStyle.Render("↓") + descStyle.Render(" enter"),
		keyStyle.Render("↑/↓") + descStyle.Render(" select"),
		keyStyle.Render("←/→") + descStyle.Render(" adjust"),
		keyStyle.Render("space") + descStyle.Render(" pause"),
		keyStyle.Render("esc") + descStyle.Render(" pause all"),
		keyStyle.Render("enter") + descStyle.Render(" resume"),
		keyStyle.Render("ctrl+c×2") + descStyle.Render(" quit"),
	}
	helpBar := " " + strings.Join(helpItems, sep)

	return separator + "\n" + progress + pauseStr + infoStr + "\n" + helpBar
}
