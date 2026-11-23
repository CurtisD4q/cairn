package tools

import (
	txt "github.com/CurtisD4q/pmin-base/text"
	"strings"
	"time"

	"github.com/CurtisD4q/pmin-base/values"
)

// Whois looks up who registered a domain or address.
func Whois() Tool {
	return Tool{
		ID: "whois", Title: "Who owns it", Group: LookUp, Bin: "whois",
		Plain:   "Looks up who registered a domain or an address block, and when.",
		Takes:   []values.Kind{values.Host},
		Timeout: 30 * time.Second,
		Args:    func(in Input) []string { return []string{"--", in.Target.Text} },
		Parse:   parseWhois,
	}
}

// whoisKeys maps the many spellings registries use to one label each.
var whoisKeys = map[string]string{
	"domain name": "Domain", "registrar": "Registrar",
	"creation date": "Created", "created": "Created",
	"registry expiry date": "Expires", "expiry date": "Expires", "expires": "Expires",
	"updated date": "Updated", "last-modified": "Updated",
	"name server": "Name server", "nserver": "Name server",
	"registrant organization": "Organisation", "org-name": "Organisation", "orgname": "Organisation", "owner": "Organisation",
	"registrant country": "Country", "country": "Country",
	"netname": "Network name", "netrange": "Network range", "inetnum": "Network range", "cidr": "Network range",
	"domain status": "Status", "status": "Status", "dnssec": "DNSSEC",
}

func parseWhois(out string, _ Input) Result {
	res := Result{Headers: []string{"Detail", "Value"}}
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ">") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		label, ok := whoisKeys[strings.ToLower(strings.TrimSpace(k))]
		v = strings.TrimSpace(v)
		if !ok || v == "" {
			continue
		}
		if label == "Status" {
			// Registries follow the status with a link to its meaning.
			if first, rest, ok := strings.Cut(v, " "); ok && strings.HasPrefix(rest, "http") {
				v = first
			}
		}
		if label == "Name server" {
			v = strings.ToLower(strings.TrimSuffix(strings.Fields(v)[0], "."))
		}
		key := label + "\x00" + v
		if seen[key] || len(res.Rows) >= 40 {
			continue
		}
		seen[key] = true
		row := Row{Cells: []string{label, v}}
		if label == "Name server" {
			if d, ok := values.Parse(v); ok && d.Kind == values.Domain {
				row.Offers = append(row.Offers, d)
			}
		}
		res.Rows = append(res.Rows, row)
	}
	if len(res.Rows) == 0 {
		res.Summary = "No registration details found. The name or address may not be registered, or the lookup may have failed."
	} else {
		res.Summary = txt.Count(len(res.Rows), "detail") + " found."
	}
	return res
}
