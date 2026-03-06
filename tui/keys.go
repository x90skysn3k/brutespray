package tui

import "github.com/charmbracelet/bubbles/key"

// KeyMap defines all keyboard bindings for the TUI.
type KeyMap struct {
	NextTab    key.Binding
	PrevTab    key.Binding
	Quit       key.Binding
	Pause      key.Binding
	Resume     key.Binding
	TogglePause key.Binding
	ScrollUp   key.Binding
	ScrollDown key.Binding
}

// DefaultKeyMap returns the default key bindings.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		NextTab:     key.NewBinding(key.WithKeys("right", "l"), key.WithHelp("→/l", "next tab")),
		PrevTab:     key.NewBinding(key.WithKeys("left", "h"), key.WithHelp("←/h", "prev tab")),
		Quit:        key.NewBinding(key.WithKeys("ctrl+c"), key.WithHelp("ctrl+c ×2", "quit")),
		Pause:       key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "pause all")),
		Resume:      key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "resume")),
		TogglePause: key.NewBinding(key.WithKeys(" "), key.WithHelp("space", "pause host")),
		ScrollUp:    key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		ScrollDown:  key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
	}
}
