package ui

import (
	"fmt"

	"github.com/CurtisD4q/Mint-Interfaces/mint"

	"github.com/CurtisD4q/cairn/internal/tools"
)

const hubHints = " ↑↓ move   ⏎ open   b back   q quit "

// hub is the workbench: the case on the left, the tools in the middle and
// what has just been run on the right, side by side.
func (a *App) hub() *mint.Screen {
	s := &mint.Screen{Icon: "◈", Title: "Workbench", TopTitle: "Case", TopWidth: 1, Hints: hubHints, SectionSpacing: 1}
	s.Refresh = func(s *mint.Screen) {
		s.Sections = a.caseSummary()
		s.Banner = a.banner()
	}
	toolsPane := &mint.Pane{Title: "Tools", Beside: true, Width: 1.25}
	toolsPane.Refresh = func(p *mint.Pane) { p.Sections = a.toolList() }
	recent := &mint.Pane{Title: "Recent", Beside: true, Width: 1.1}
	recent.Refresh = func(p *mint.Pane) { p.Sections = a.recentRuns() }
	s.Panes = []*mint.Pane{toolsPane, recent}
	s.Sections = a.caseSummary()
	toolsPane.Sections = a.toolList()
	recent.Sections = a.recentRuns()
	return s
}

func (a *App) banner() string {
	if _, _, _, rules, _ := a.snapshot(); len(rules) == 0 {
		return "No scope set: Cairn will ask before it tests anything. Open Case to set one."
	}
	return ""
}

func (a *App) caseSummary() []mint.Section {
	name, active, targets, rules, _ := a.snapshot()
	scopeText := "not set"
	if n := len(rules); n > 0 {
		scopeText = plural(n, "rule")
	}
	top := []mint.Row{
		mint.Value(mint.ValueOpts{Label: "Name", Get: func() string { return name }, OnActivate: a.switchCase}),
		mint.Value(mint.ValueOpts{Label: "Scope", Get: func() string { return scopeText }, OnActivate: func(c *mint.Ctx) { c.Push(a.caseScreen()) }}),
		mint.Text(mint.TextOpts{
			Label: "Target", Placeholder: "address or name", Get: func() string { return active },
			Set: func(v string) { a.setTarget(v) },
		}),
	}
	if k := kindOf(active); k != "" {
		top = append(top, mint.Label(mint.StyleCaption, "  "+k))
	}
	secs := []mint.Section{{Rows: top}}
	if len(targets) > 0 {
		var rows []mint.Row
		for _, t := range targets {
			t := t
			mark := "○ "
			if t == active {
				mark = "● "
			}
			rows = append(rows, mint.Action(mint.ActionOpts{
				Label: mark + t, Hint: kindOf(t),
				OnActivate: func(c *mint.Ctx) { a.SetActive(t); c.Toast("Tools now start with " + t) },
			}))
		}
		secs = append(secs, mint.Section{Name: "Targets", Rows: rows})
	}
	return secs
}

func (a *App) setTarget(text string) {
	if text == "" {
		return
	}
	if t, err := a.AddTarget(text); err != nil {
		mint.ToastWarn(err.Error())
	} else {
		mint.Toast("Target set to " + t)
	}
}

func (a *App) toolList() []mint.Section {
	var secs []mint.Section
	for _, g := range tools.Groups {
		var rows []mint.Row
		for _, t := range tools.All() {
			if t.Group != g {
				continue
			}
			t := t
			hint := t.Bin
			if !t.Available() {
				hint = t.Bin + " (not installed)"
			}
			rows = append(rows, mint.Action(mint.ActionOpts{
				Label: t.Title, Hint: hint,
				OnActivate: func(c *mint.Ctx) { a.openTool(c, t, a.startInput(t)) },
			}))
		}
		if len(rows) > 0 {
			secs = append(secs, mint.Section{Name: string(g), Rows: rows})
		}
	}
	return secs
}

func (a *App) recentRuns() []mint.Section {
	es := a.entries()
	if len(es) == 0 {
		return []mint.Section{{Rows: []mint.Row{mint.Label(mint.StyleCaption, "Nothing run yet."), mint.Label(mint.StyleCaption, "Pick a tool to begin.")}}}
	}
	var rows []mint.Row
	for i := len(es) - 1; i >= 0 && len(rows) < 8; i-- {
		e := es[i]
		who := e.Target
		if who == "" {
			who = "this computer"
		}
		rows = append(rows, mint.Value(mint.ValueOpts{
			Label: stamp(e.Time) + "  " + e.Tool, Get: func() string { return who },
			OnActivate: func(c *mint.Ctx) { c.Push(a.logScreen()) },
		}))
	}
	return []mint.Section{{Rows: rows}}
}

func (a *App) switchCase(c *mint.Ctx) {
	cur, _, _, _, _ := a.snapshot()
	items := []mint.Choice{{Label: "＋ New case…", Value: "\x00new"}}
	for _, n := range a.st.List() {
		label := n
		if n == cur {
			label += "  (open)"
		}
		items = append(items, mint.Choice{Label: label, Value: n})
	}
	pick, ok := c.ChooseItem("Cases", items, "Each case has its own targets, scope and audit log")
	if !ok {
		return
	}
	name := pick.Value
	if name == "\x00new" {
		n, ok := c.Prompt("New case", "A short name: letters, digits, - or _", "")
		if !ok {
			return
		}
		cleaned, err := cleanCase(n)
		if err != nil {
			c.ToastWarn(err.Error())
			return
		}
		if _, err := a.st.Create(cleaned); err != nil {
			c.ToastWarn(err.Error())
			return
		}
		name = cleaned
	}
	if err := a.use(name); err != nil {
		c.ToastError(err.Error())
		return
	}
	c.Toast("Now working in case " + name)
}

func plural(n int, w string) string {
	if n == 1 {
		return "1 " + w
	}
	return fmt.Sprintf("%d %ss", n, w)
}
