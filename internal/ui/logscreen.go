package ui

import (
	"fmt"
	"strings"

	"github.com/CurtisD4q/pmin-kit"

	"github.com/CurtisD4q/cairn/internal/store"
	"github.com/CurtisD4q/cairn/internal/tools"
)

// logScreen lists every command run in the case, newest first.
func (a *App) logScreen() *mint.Screen {
	rows := func() [][]string {
		es := a.entries()
		out := make([][]string, 0, len(es))
		for i := len(es) - 1; i >= 0; i-- {
			e := es[i]
			scope := e.Scope
			if e.Override {
				scope += ", overridden"
			}
			out = append(out, []string{e.Time.Local().Format("Jan 02 15:04:05"), e.Tool, orDash(e.Target), scope, resultOf(e)})
		}
		return out
	}
	table := mint.Table(mint.TableOpts{
		Headers: []string{"When", "Tool", "Target", "Scope", "Result"}, Get: rows, Empty: "Nothing has been run in this case yet.",
		OnSelect: func(c *mint.Ctx, i int, _ []string) {
			es := a.entries()
			if i < 0 || i >= len(es) {
				return
			}
			c.Message("Command", detail(es[len(es)-1-i]))
		},
	})
	return &mint.Screen{
		Icon: "≡", Title: "Audit log", Hints: " ↑↓ move   ⏎ details   b back   q quit ",
		Sections: []mint.Section{{Rows: []mint.Row{
			mint.Label(mint.StyleCaption, "Every command cairn has run in this case, in the order they happened."),
			table,
		}}},
	}
}

func detail(e store.Entry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", tools.Quote(e.Argv))
	fmt.Fprintf(&b, "When:    %s\n", e.Time.Local().Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&b, "Scope:   %s", e.Scope)
	if e.Override {
		b.WriteString(" (you chose to run it anyway)")
	}
	fmt.Fprintf(&b, "\nTook:    %.1f s\nResult:  %s", e.Seconds, resultOf(e))
	return b.String()
}
