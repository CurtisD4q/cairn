package tools

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/CurtisD4q/cairn/internal/values"
)

// Traceroute shows the path to a host.
func Traceroute() Tool {
	return Tool{
		ID: "traceroute", Title: "Trace the route", Group: Discover, Bin: "traceroute",
		Plain:   "Shows each stop (router) between this computer and the target.",
		Takes:   []values.Kind{values.Host},
		Active:  true,
		Timeout: 3 * time.Minute,
		Options: []Option{
			{ID: "hops", Label: "Longest path", Kind: Count, Default: "20", Min: 2, Max: 40, Unit: "stops",
				Plain: "Where to give up. Most paths are under 20 stops."},
		},
		Args: func(in Input) []string {
			return []string{"-n", "-q", "1", "-w", "2", "-m", itoa(clamp(in.num("hops", 20), 2, 40)), "--", in.Target.Text}
		},
		Parse: parseTraceroute,
	}
}

var hopLine = regexp.MustCompile(`^\s*(\d+)\s+(.+?)\s*$`)

func parseTraceroute(out string, _ Input) Result {
	res := Result{Headers: []string{"Stop", "Address", "Time"}}
	silent := 0
	for _, line := range strings.Split(out, "\n") {
		m := hopLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		f := strings.Fields(m[2])
		if len(f) == 0 {
			continue
		}
		addr, rtt := f[0], ""
		if addr == "*" {
			addr = "no reply"
			silent++
		} else if len(f) >= 3 && f[2] == "ms" {
			rtt = f[1] + " ms"
		}
		row := Row{Cells: []string{m[1], addr, rtt}}
		if v, ok := values.Parse(f[0]); ok && v.Kind == values.IP {
			row.Offers = append(row.Offers, v)
		}
		res.Rows = append(res.Rows, row)
	}
	switch {
	case len(res.Rows) == 0:
		res.Summary = "No path found. The host name may not exist, or the network may be down."
	case silent > 0:
		res.Summary = fmt.Sprintf("%s, %d did not reply (often a firewall; the path still continues).", plural(len(res.Rows), "stop"), silent)
	default:
		res.Summary = plural(len(res.Rows), "stop") + " to the target."
	}
	return res
}
