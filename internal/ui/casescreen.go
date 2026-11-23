package ui

import (
	"os"
	"time"

	"github.com/CurtisD4q/pmin-kit"
)

// caseScreen is where the case is edited: its targets, the scope, notes, and
// a report.
func (a *App) caseScreen() *mint.Screen {
	s := &mint.Screen{Icon: "◇", Title: "Case", Hints: " ↑↓ move   ⏎ change or remove   b back   q quit "}
	s.Refresh = func(s *mint.Screen) { s.Sections = a.caseSections(); s.Banner = a.banner() }
	s.Sections = a.caseSections()
	return s
}

func (a *App) caseSections() []mint.Section {
	name, _, targets, rules, notes := a.snapshot()

	caseRows := []mint.Row{
		mint.Value(mint.ValueOpts{Label: "Name", Get: func() string { return name }, OnActivate: a.switchCase}),
	}

	tRows := []mint.Row{mint.Text(mint.TextOpts{
		Label: "Add a target", Placeholder: "address, name, network or web address",
		Get: func() string { return "" }, Set: func(v string) { a.setTarget(v) },
	})}
	for _, t := range targets {
		t := t
		tRows = append(tRows, mint.Action(mint.ActionOpts{
			Label: t, Hint: kindOf(t),
			OnActivate: func(c *mint.Ctx) {
				if c.Confirm("Remove target", "Remove "+t+" from this case?\n\nThe audit log keeps what was already run.") {
					a.RemoveTarget(t)
					c.Toast("Removed " + t)
				}
			},
		}))
	}

	sRows := paragraph(mint.StyleCaption, "What you are allowed to test. cairn checks every scan against it before it sends anything. Use a network (10.0.0.0/24), an address (192.168.1.9), or a domain (example.com covers its subdomains too; *.lab.test covers only the subdomains).", 0.85)
	sRows = append(sRows, mint.Text(mint.TextOpts{
		Label: "Add a rule", Placeholder: "10.0.0.0/24 or example.com",
		Get: func() string { return "" },
		Set: func(v string) {
			if v == "" {
				return
			}
			if err := a.AddScope(v); err != nil {
				mint.ToastWarn(err.Error())
			} else {
				mint.Toast("Scope updated")
			}
		},
	}))
	for _, r := range rules {
		r := r
		sRows = append(sRows, mint.Action(mint.ActionOpts{
			Label: r, Hint: "remove",
			OnActivate: func(c *mint.Ctx) {
				if c.Confirm("Remove scope rule", "Remove "+r+" from the scope?\n\nTools will then ask before testing anything it covered.") {
					a.RemoveScope(r)
					c.Toast("Removed " + r)
				}
			},
		}))
	}

	return []mint.Section{
		{Name: "Case", Rows: caseRows},
		{Name: "Targets", Rows: tRows},
		{Name: "Scope", Rows: sRows},
		{Name: "Notes", Rows: []mint.Row{mint.Text(mint.TextOpts{
			Label: "Notes", Placeholder: "anything worth remembering",
			Get: func() string { return notes }, Set: a.SetNotes,
		})}},
		{Name: "Report", Rows: []mint.Row{mint.Action(mint.ActionOpts{
			Label: "Save a report (Markdown)", Hint: "targets, scope, commands",
			OnActivate: a.saveReport,
		})}},
	}
}

func (a *App) saveReport(c *mint.Ctx) {
	cs := a.Case()
	a.mu.Lock()
	snap := *cs
	a.mu.Unlock()
	path := a.st.Path(snap.Name) + "-report.md"
	body := Report(&snap, a.entries(), time.Now())
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		c.ToastError("Could not save the report: " + err.Error())
		return
	}
	c.Message("Report saved", "Saved to:\n\n"+path)
}
