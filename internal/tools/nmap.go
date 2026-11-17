package tools

import (
	"fmt"
	"strings"
	"time"

	"github.com/CurtisD4q/mint-tools/values"
)

// Nmap finds which ports are open on a host or a network.
func Nmap() Tool {
	return Tool{
		ID: "nmap", Title: "Port scan", Group: Discover, Bin: "nmap",
		Plain:    "Finds which doors (ports) are open on a computer or network, and what is listening behind them.",
		Takes:    []values.Kind{values.Host, values.Range},
		UsesPort: true,
		Active:   true,
		Timeout:  15 * time.Minute,
		Options: []Option{
			{ID: "depth", Label: "How many ports", Kind: Pick, Default: "standard", Choices: []Choice{
				{"Quick: the 100 most common", "fast", "Checks the 100 ports most often used. Fast, and enough for a first look."},
				{"Standard: the 1000 most common", "standard", "Checks the 1000 ports most often used."},
				{"Everything: all 65,535", "all", "Checks every port. Thorough, and slow."},
			}},
			{ID: "speed", Label: "Speed", Kind: Pick, Default: "normal", Choices: []Choice{
				{"Careful", "careful", "Goes slowly, which is gentler on the network and less likely to be noticed."},
				{"Normal", "normal", "Nmap's usual pace."},
				{"Fast", "fast", "Goes quickly. Fine on a network you control."},
			}},
			{ID: "versions", Label: "Identify software", Kind: Switch, Default: "off",
				Plain: "Asks each open port what program and version it is. Takes longer, and is more noticeable."},
			{ID: "skipping", Label: "Skip the aliveness check", Kind: Switch, Default: "off",
				Plain: "Scans even if the host does not answer a ping. Slower, but finds hosts that hide."},
		},
		Args: func(in Input) []string {
			a := []string{"-oG", "-"}
			switch {
			case in.Port > 0:
				a = append(a, "-p", itoa(in.Port))
			case in.opt("depth", "standard") == "fast":
				a = append(a, "-F")
			case in.opt("depth", "standard") == "all":
				a = append(a, "-p-")
			}
			switch in.opt("speed", "normal") {
			case "careful":
				a = append(a, "-T2")
			case "fast":
				a = append(a, "-T4")
			}
			if in.on("versions") {
				a = append(a, "-sV")
			}
			if in.on("skipping") {
				a = append(a, "-Pn")
			}
			return append(a, "--", in.Target.Text)
		},
		Parse: parseNmap,
	}
}

func parseNmap(out string, in Input) Result {
	res := Result{Headers: []string{"Host", "Port", "State", "Service", "Version"}}
	up, hidden, maybe := 0, 0, 0
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "Host: ") {
			continue
		}
		fields := strings.Split(line, "\t")
		head := strings.Fields(strings.TrimPrefix(fields[0], "Host: "))
		if len(head) == 0 {
			continue
		}
		host := head[0]
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "Status: Up") {
				up++
			}
			list, ok := strings.CutPrefix(f, "Ports: ")
			if !ok {
				continue
			}
			for _, entry := range strings.Split(list, ", ") {
				p := strings.SplitN(strings.TrimSpace(entry), "/", 7)
				if len(p) < 5 {
					continue
				}
				port, state, proto, service := p[0], p[1], p[2], p[4]
				version := ""
				if len(p) == 7 {
					version = strings.TrimRight(p[6], "/ ")
				}
				switch state {
				case "closed":
					continue
				case "filtered":
					hidden++
					continue
				}
				if state != "open" {
					maybe++
				}
				if service == "" {
					service = "unknown"
				}
				row := Row{Cells: []string{host, port + "/" + proto, state, service, version}}
				if proto == "tcp" {
					if ep, ok := values.MakeEndpoint(host, atoi(port)); ok {
						row.Offers = append(row.Offers, ep)
						if isWeb(service) {
							if u, ok := ep.As(values.URL); ok {
								row.Offers = append(row.Offers, u)
							}
						}
					}
				}
				res.Rows = append(res.Rows, row)
			}
		}
	}
	switch {
	case up == 0 && len(res.Rows) == 0:
		res.Summary = "No host answered. It may be off, unreachable, or hiding; try skipping the aliveness check."
	case len(res.Rows) == 0:
		res.Summary = fmt.Sprintf("%s up, but no open ports among those checked.", plural(up, "host"))
	default:
		res.Summary = fmt.Sprintf("%s up, %s open.", plural(up, "host"), plural(len(res.Rows)-maybe, "port"))
		if maybe > 0 {
			res.Summary += fmt.Sprintf(" %d more may be open (no answer either way).", maybe)
		}
	}
	if hidden > 0 {
		res.Summary += fmt.Sprintf(" %s filtered (blocked by a firewall) and not listed.", plural(hidden, "port"))
	}
	if len(res.Rows) > 0 && !in.on("versions") {
		res.Summary += " Service names are guesses from the port number; turn on Identify software to check."
	}
	return res
}

func isWeb(service string) bool {
	service = strings.ToLower(service)
	service = service[strings.LastIndexAny(service, "|/")+1:]
	switch service {
	case "http", "https", "http-proxy", "http-alt", "https-alt", "http-mgmt", "sun-answerbook":
		return true
	}
	return false
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return itoa(n) + " " + word + "s"
}
