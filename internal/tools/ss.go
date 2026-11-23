package tools

import (
	txt "github.com/CurtisD4q/pmin-base/text"
	"regexp"
	"strings"
	"time"

	"github.com/CurtisD4q/pmin-base/values"
)

// Ss lists what this computer is listening on.
func Ss() Tool {
	return Tool{
		ID: "ss", Title: "Open ports here", Group: Local, Bin: "ss",
		Plain:   "Lists what this computer is listening for, which is what others could connect to.",
		Timeout: 15 * time.Second,
		Options: []Option{
			{ID: "programs", Label: "Show programs", Kind: Switch, Default: "off",
				Plain: "Names the program behind each port. Other users' programs show only if you run cairn as root."},
		},
		Args: func(in Input) []string {
			a := []string{"-H", "-tuln"}
			if in.on("programs") {
				a = append(a, "-p")
			}
			return a
		},
		Parse: parseSs,
	}
}

var ssProc = regexp.MustCompile(`\(\("([^"]+)"`)

func parseSs(out string, _ Input) Result {
	res := Result{Headers: []string{"Type", "Address", "Port", "Program"}}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || (f[1] != "LISTEN" && f[1] != "UNCONN") {
			continue
		}
		local := f[4]
		i := strings.LastIndex(local, ":")
		if i < 0 {
			continue
		}
		addr, port := local[:i], local[i+1:]
		addr = strings.Trim(addr, "[]")
		if j := strings.Index(addr, "%"); j >= 0 {
			addr = addr[:j]
		}
		wildcard := addr == "*" || addr == "0.0.0.0" || addr == "::"
		if addr == "*" {
			addr = "any"
		}
		prog := ""
		if m := ssProc.FindStringSubmatch(line); m != nil {
			prog = m[1]
		}
		row := Row{Cells: []string{f[0], addr, port, prog}}
		host := addr
		if wildcard {
			host = "127.0.0.1"
		}
		if n := atoi(port); n > 0 {
			if ep, ok := values.MakeEndpoint(host, n); ok {
				row.Offers = append(row.Offers, ep)
			}
		}
		res.Rows = append(res.Rows, row)
	}
	if len(res.Rows) == 0 {
		res.Summary = "Nothing is listening, or the list could not be read."
	} else {
		res.Summary = txt.Count(len(res.Rows), "listening port") + "."
	}
	return res
}
