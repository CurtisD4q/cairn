package ui

import (
	"github.com/CurtisD4q/mint-tl/scope"
	"github.com/CurtisD4q/mint-tl/values"
	"strings"

	"github.com/CurtisD4q/mint-kt"
)

// wrap breaks text into lines of at most width cells, at spaces.
func wrap(text string, width int) []string {
	if width < 16 {
		width = 16
	}
	var lines []string
	line := ""
	for _, w := range strings.Fields(text) {
		switch {
		case line == "":
			line = w
		case mint.VLen(line)+1+mint.VLen(w) <= width:
			line += " " + w
		default:
			lines = append(lines, line)
			line = w
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// paragraph is text as readable rows, wrapped to a pane about frac of the
// terminal's width.
func paragraph(style mint.Style, text string, frac float64) []mint.Row {
	_, cols := mint.TermSize()
	var rows []mint.Row
	for _, l := range wrap(text, int(float64(cols)*frac)-8) {
		rows = append(rows, mint.Label(style, l))
	}
	return rows
}

// kindName says what a target is, in words a newcomer knows.
func kindName(k values.Kind) string {
	switch k {
	case values.IP:
		return "address"
	case values.Domain:
		return "name"
	case values.URL:
		return "web address"
	case values.Endpoint:
		return "address and port"
	case values.Range:
		return "network"
	}
	return string(k)
}

func kindOf(text string) string {
	if v, ok := values.Parse(text); ok {
		return kindName(v.Kind)
	}
	return ""
}

func ruleOf(text string) (string, bool) { return scope.Rule(text) }
