# CLI demo recorded with vhs (https://github.com/charmbracelet/vhs).
# Regenerate with `make demo-cli` (builds bin/escalint first).
Output docs/media/cli.gif

Require escalint

Set Shell "bash"
Set FontSize 15
Set Width 1200
Set Height 720
Set Padding 16
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms
Set WindowBar Colorful

Hide
Type `export PS1="$ " && cd examples/vulnerable-account && clear`
Enter
Show

# The rule catalog: escalation paths, trust and parse rules.
Type "escalint rules list | head -n 16"
Sleep 300ms
Enter
Sleep 3s

# Scan the vulnerable example (its .escalint.yaml is read automatically).
Type "clear && escalint scan snapshot.json --min-severity critical | head -n 24"
Sleep 300ms
Enter
Sleep 6s

# What a pull request would add, relative to the hardened baseline.
Type `clear && escalint diff ../hardened-account/snapshot.json snapshot.json | head -n 12; echo "exit code: ${PIPESTATUS[0]}"`
Sleep 300ms
Enter
Sleep 5s

# The hardened account: no findings, exit code 0.
Type `clear && cd ../hardened-account && escalint scan snapshot.json; echo "exit code: $?"`
Sleep 300ms
Enter
Sleep 5s
