# Record with: podman run --rm -v "$PWD":/vhs:Z -w /vhs ghcr.io/charmbracelet/vhs tui.tape
# (copy soc-thief-console and examples/demo-snapshot.json into this folder first)
Output tui.gif
Set Shell "bash"
Set FontSize 15
Set Width 1600
Set Height 900
Set Padding 16
Set TypingSpeed 60ms
Set Theme { "name": "night", "background": "#07080a", "foreground": "#c9d1d9", "cursor": "#f2cc60", "selectionBackground": "#2a2f37", "black": "#07080a", "red": "#ff4d6d", "green": "#7ee787", "yellow": "#f2cc60", "blue": "#79c0ff", "purple": "#e8893a", "cyan": "#7ee787", "white": "#c9d1d9", "brightBlack": "#2a2f37", "brightRed": "#ff4d6d", "brightGreen": "#7ee787", "brightYellow": "#f2cc60", "brightBlue": "#79c0ff", "brightPurple": "#e8893a", "brightCyan": "#7ee787", "brightWhite": "#ffffff" }
Hide
Type "cd /vhs && clear"
Enter
Show
Type "soc-thief-console tui --snapshot demo-snapshot.json"
Sleep 400ms
Hide
Backspace 52
Type "./soc-thief-console tui --snapshot demo-snapshot.json"
Enter
Show
Sleep 3.5s
Type "2"
Sleep 2s
Down 2
Sleep 800ms
Enter
Sleep 3.5s
Escape
Sleep 500ms
Type "c"
Sleep 1.2s
Type "c"
Sleep 2s
Type "3"
Sleep 2.5s
Type "4"
Sleep 2.5s
Type "1"
Sleep 2s
Type "q"
Sleep 300ms
