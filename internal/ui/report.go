package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/CurtisD4q/cairn/internal/store"
	"github.com/CurtisD4q/cairn/internal/tools"
)

// Report is the case as Markdown: what was in scope, what was tested, and
// every command that was run, ready to hand on or paste into notes.
func Report(c *store.Case, entries []store.Entry, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Case: %s\n\n", c.Name)
	fmt.Fprintf(&b, "Created %s. Report made %s.\n\n", c.Created.Format("2006-01-02"), now.UTC().Format("2006-01-02 15:04 UTC"))
	b.WriteString("## Scope\n\n")
	if len(c.Scope) == 0 {
		b.WriteString("No scope was set.\n\n")
	}
	for _, r := range c.Scope {
		fmt.Fprintf(&b, "- %s\n", mdText(r))
	}
	b.WriteString("\n## Targets\n\n")
	if len(c.Targets) == 0 {
		b.WriteString("None.\n")
	}
	for _, t := range c.Targets {
		fmt.Fprintf(&b, "- %s\n", mdText(t))
	}
	if strings.TrimSpace(c.Notes) != "" {
		b.WriteString("\n## Notes\n\n" + strings.TrimSpace(c.Notes) + "\n")
	}
	b.WriteString("\n## Commands run\n\n")
	if len(entries) == 0 {
		b.WriteString("None.\n")
		return b.String()
	}
	b.WriteString("| Time (UTC) | Tool | Target | Scope | Result |\n|---|---|---|---|---|\n")
	for _, e := range entries {
		scope := e.Scope
		if e.Override {
			scope += " (overridden)"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", e.Time.UTC().Format("2006-01-02 15:04:05"),
			mdText(e.Tool), mdText(orDash(e.Target)), scope, mdText(resultOf(e)))
	}
	b.WriteString("\n```\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "%s  %s\n", e.Time.UTC().Format("15:04:05"), strings.ReplaceAll(tools.Quote(e.Argv), "```", "'''"))
	}
	b.WriteString("```\n")
	return b.String()
}

func resultOf(e store.Entry) string {
	switch {
	case e.Error != "":
		return "failed: " + e.Error
	case e.Exit != 0:
		return fmt.Sprintf("exit %d", e.Exit)
	}
	return fmt.Sprintf("%d found", e.Findings)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// mdText makes text safe inside a Markdown table cell or list item.
func mdText(s string) string {
	s = strings.NewReplacer("|", `\|`, "\n", " ", "\r", " ", "`", "'").Replace(s)
	return strings.TrimSpace(s)
}
