package tools

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/CurtisD4q/mint-tl/values"
)

// Ping checks that a host answers and how quickly.
func Ping() Tool {
	return Tool{
		ID: "ping", Title: "Is it up?", Group: Reach, Bin: "ping",
		Plain:   "Checks that a computer answers, and how long a reply takes.",
		Takes:   []values.Kind{values.Host},
		Active:  true,
		Timeout: 60 * time.Second,
		Options: []Option{
			{ID: "count", Label: "Tries", Kind: Count, Default: "4", Min: 1, Max: 20,
				Plain: "How many times to ask. More tries give a steadier average."},
		},
		Args: func(in Input) []string {
			return []string{"-c", itoa(clamp(in.num("count", 4), 1, 20)), "-W", "2", "--", in.Target.Text}
		},
		Parse: parsePing,
	}
}

var (
	pingStats = regexp.MustCompile(`(\d+) packets transmitted, (\d+) (?:packets )?received.*?(\d+(?:\.\d+)?)% packet loss`)
	pingRTT   = regexp.MustCompile(`= ([\d.]+)/([\d.]+)/([\d.]+)`)
	pingFrom  = regexp.MustCompile(`^PING \S+ \(([^)]+)\)`)
)

func parsePing(out string, _ Input) Result {
	res := Result{Headers: []string{"Sent", "Received", "Lost", "Fastest", "Average", "Slowest"}}
	m := pingStats.FindStringSubmatch(out)
	if m == nil {
		res.Summary = "No result. The host name may not exist, or the network may be down."
		return res
	}
	row := Row{Cells: []string{m[1], m[2], m[3] + "%", "", "", ""}}
	if r := pingRTT.FindStringSubmatch(out); r != nil {
		row.Cells[3], row.Cells[4], row.Cells[5] = r[1]+" ms", r[2]+" ms", r[3]+" ms"
	}
	for _, line := range strings.Split(out, "\n") {
		if f := pingFrom.FindStringSubmatch(line); f != nil {
			if v, ok := values.Parse(f[1]); ok && v.Kind == values.IP {
				row.Offers = append(row.Offers, v)
			}
			break
		}
	}
	res.Rows = []Row{row}
	if m[2] == "0" {
		res.Summary = "No reply. The host may be off, or it may ignore pings."
	} else {
		res.Summary = fmt.Sprintf("%s of %s answered, %s%% lost.", m[2], m[1], m[3])
		if row.Cells[4] != "" {
			res.Summary += " Average reply " + row.Cells[4] + "."
		}
	}
	return res
}
