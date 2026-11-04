# Record with: podman run --rm -v "$PWD":/vhs:Z -w /vhs ghcr.io/charmbracelet/vhs globe.tape
# (copy soc-thief-console and examples/demo-snapshot.json into this folder first)
# Timing: the demo's breaches are 71522 to 72347 s into the window. The replay runs at x360,
# jumps to x3600, then slows to x1440 a few seconds before them; keystrokes land late, so
# the slower speed is what keeps the breach banner on camera.
Output globe.gif
Set Shell "bash"
Set FontSize 15
Set Width 1600
Set Height 900
Set Padding 16
Set Framerate 10
Set TypingSpeed 60ms
Set Theme { "name": "night", "background": "#07080a", "foreground": "#c9d1d9", "cursor": "#f2cc60", "selectionBackground": "#2a2f37", "black": "#07080a", "red": "#ff4d6d", "green": "#7ee787", "yellow": "#f2cc60", "blue": "#79c0ff", "purple": "#e8893a", "cyan": "#7ee787", "white": "#c9d1d9", "brightBlack": "#2a2f37", "brightRed": "#ff4d6d", "brightGreen": "#7ee787", "brightYellow": "#f2cc60", "brightBlue": "#79c0ff", "brightPurple": "#e8893a", "brightCyan": "#7ee787", "brightWhite": "#ffffff" }
Hide
Type "cd /vhs && clear"
Enter
Type "./soc-thief-console tui --snapshot demo-snapshot.json"
Enter
Sleep 1s
Type "5"
Show
Sleep 7s
Type "l"
Sleep 4s
Type "m"
Sleep 3s
Type "+"
Type "+"
Sleep 14500ms
Type "-"
Sleep 14s
Type "q"
Sleep 300ms
