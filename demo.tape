# VHS tape file — https://github.com/charmbracelet/vhs
# Install: go install github.com/charmbracelet/vhs@latest
# Run:     vhs demo.tape

Output brutespray.gif

Set FontSize 14
Set Width 1200
Set Height 600
Set Theme "Catppuccin Mocha"
Set TypingSpeed 50ms

# Type the command
Type "go run . -f scan.gnmap -t 10 -T 10"
Sleep 500ms
Enter

# Let TUI render and attempts stream in on All tab
Sleep 5s

# Navigate to By Host tab
Right
Sleep 500ms
Down
Sleep 3s

# Navigate to By Service tab
Up
Right
Sleep 500ms
Down
Sleep 3s

# Navigate to Successes tab
Up
Right Right
Sleep 3s

# Navigate to Errors tab
Up
Right
Sleep 3s

# Navigate to Settings tab
Up
Right
Sleep 3s

# Back to All tab to show final state
Up
Left Left Left Left Left
Sleep 500ms
Down
Sleep 3s
