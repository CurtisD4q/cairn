package ui

import "github.com/CurtisD4q/mint-kit"

// guide is the short orientation: a few lines, in plain words.
func (a *App) guide() *mint.Screen {
	text := func(style mint.Style, s string) []mint.Row { return paragraph(style, s, 0.85) }
	var rows []mint.Row
	add := func(head, body string) {
		rows = append(rows, mint.Label(mint.StyleHeading, head))
		rows = append(rows, text(mint.StyleBody, body)...)
		rows = append(rows, mint.Spacer())
	}
	add("1. Set what you may test", "Open Case and add your scope: the networks, addresses or domains you have permission to test. cairn checks every scan against it and asks before going outside it.")
	add("2. Enter a target once", "Type a target in the Workbench. Every tool starts with it, so you do not retype it.")
	add("3. Pick a tool and choose Run", "Each tool explains itself beside its controls, and shows the exact command it will run, so you can see what is happening and learn from it.")
	add("4. Send results on", "Select a row in the results. You can open it in another tool, add it to the case, or copy it. A port found by a scan can go straight to a web check.")
	add("5. Look, hunt and harden", "Something's wrong runs checks for signs that someone got in, or what others can reach. Hunt in the logs narrows the logs down to failed logins, logins or administrator commands, step by step. Machines keeps the machines you work on, for ssh and tunnels. Harden this machine changes accounts, permissions, the firewall and ssh settings, and puts a change back on its own if it cuts you off.")
	add("6. Any program, in the Mint layout", "Programs opens any command-line program inside cairn: its options, the exact command, Run and what came back, in panes. Type a name with Open a program, or choose one from the groups. For programs that reach other machines, every command is checked against the case's scope first, and refused if a target is outside it. Every run goes in the audit log.")
	add("7. Everything is recorded", "The Audit log lists everything done in the case, by every part of cairn: each command, when it ran, and whether it was in scope or agreed to. Save a report from the Case screen when you are done.")
	rows = append(rows, text(mint.StyleCaption, "Keys: arrows move, Enter opens or changes, Tab moves between panes, b goes back, q quits. The mouse works too. Set MINT_KEYS=emacs or vim for those key styles.")...)
	return &mint.Screen{Icon: "?", Title: "How this works", Hints: " ↑↓ scroll   b back   q quit ", Sections: []mint.Section{{Rows: rows}}}
}
