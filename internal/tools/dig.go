package tools

import (
	"strings"
	"time"

	"github.com/CurtisD4q/mint-tl/values"
)

// Dig asks the name system about a domain.
func Dig() Tool {
	return Tool{
		ID: "dig", Title: "Name records", Group: LookUp, Bin: "dig",
		Plain:   "Asks the internet's name system what a domain points to: its addresses, mail servers and name servers. For an address, it asks which name belongs to it.",
		Takes:   []values.Kind{values.Host},
		Timeout: 30 * time.Second,
		Options: []Option{
			{ID: "type", Label: "Record type", Kind: Pick, Default: "A", Choices: []Choice{
				{"Address (A)", "A", "The IPv4 address the name points to."},
				{"Address (AAAA)", "AAAA", "The IPv6 address the name points to."},
				{"Mail servers (MX)", "MX", "Which servers receive mail for the domain."},
				{"Name servers (NS)", "NS", "Which servers hold the domain's records."},
				{"Text (TXT)", "TXT", "Free text, often used for email policy and ownership checks."},
				{"Alias (CNAME)", "CNAME", "Whether the name is an alias for another name."},
				{"Authority (SOA)", "SOA", "Who is responsible for the domain, and when it last changed."},
			}},
		},
		Args: func(in Input) []string {
			a := []string{"+noall", "+answer", "+time=3", "+tries=1"}
			if in.Target.Kind == values.IP {
				return append(a, "-x", in.Target.Text)
			}
			return append(a, in.Target.Text, in.opt("type", "A"))
		},
		Parse: parseDig,
	}
}

func parseDig(out string, _ Input) Result {
	res := Result{Headers: []string{"Name", "Type", "Answer", "Seconds kept"}}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, ";") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 5 || f[2] != "IN" {
			continue
		}
		typ, data := f[3], strings.Join(f[4:], " ")
		switch typ {
		case "CNAME", "NS", "PTR", "MX":
			data = strings.TrimSuffix(data, ".")
		}
		row := Row{Cells: []string{strings.TrimSuffix(f[0], "."), typ, data, f[1]}}
		switch typ {
		case "A", "AAAA":
			if v, ok := values.Parse(data); ok && v.Kind == values.IP {
				row.Offers = append(row.Offers, v)
			}
		case "CNAME", "NS", "PTR":
			if v, ok := values.Parse(data); ok && v.Kind == values.Domain {
				row.Offers = append(row.Offers, v)
			}
		case "MX":
			if v, ok := values.Parse(f[len(f)-1]); ok && v.Kind == values.Domain {
				row.Offers = append(row.Offers, v)
			}
		}
		res.Rows = append(res.Rows, row)
	}
	if len(res.Rows) == 0 {
		res.Summary = "No records found. The name may not exist, or has none of this type."
	} else {
		res.Summary = plural(len(res.Rows), "record") + " found."
	}
	return res
}
