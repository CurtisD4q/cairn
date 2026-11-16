package tools

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/CurtisD4q/cairn/internal/values"
)

// Curl reads a web server's reply headers.
func Curl() Tool {
	return Tool{
		ID: "curl", Title: "Web headers", Group: Reach, Bin: "curl",
		Plain:   "Asks a web server for a page and shows what it says about itself: its software, redirects and security settings.",
		Takes:   []values.Kind{values.URL},
		Active:  true,
		Timeout: 40 * time.Second,
		Options: []Option{
			{ID: "method", Label: "Request", Kind: Pick, Default: "head", Choices: []Choice{
				{"Headers only (HEAD)", "head", "Asks for the headers and no page. The lightest request."},
				{"Whole page (GET)", "get", "Asks for the page as a browser would, and shows only the headers."},
			}},
			{ID: "redirects", Label: "Follow redirects", Kind: Switch, Default: "off",
				Plain: "Goes where the server points you, up to 5 times, and shows every step."},
			{ID: "insecure", Label: "Accept bad certificates", Kind: Switch, Default: "off",
				Plain: "Carries on even if the site's certificate is invalid. Useful in a test lab, risky anywhere else."},
		},
		Args: func(in Input) []string {
			a := []string{"-sS", "-m", "10", "-A", "Cairn"}
			if in.opt("method", "head") == "get" {
				a = append(a, "-D", "-", "-o", "/dev/null")
			} else {
				a = append(a, "-I")
			}
			if in.on("redirects") {
				a = append(a, "-L", "--max-redirs", "5")
			}
			if in.on("insecure") {
				a = append(a, "-k")
			}
			return append(a, "--url", in.Target.Text)
		},
		Parse: parseCurl,
	}
}

func parseCurl(out string, in Input) Result {
	res := Result{Headers: []string{"Step", "Header", "Value"}}
	base, _ := url.Parse(in.Target.Text)
	step := 0
	status := ""
	inBlock := false
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		if line == "" {
			inBlock = false
			continue
		}
		if strings.HasPrefix(line, "HTTP/") {
			step++
			inBlock = true
			f := strings.Fields(line)
			if len(f) >= 2 {
				status = strings.Join(f[1:], " ")
				res.Rows = append(res.Rows, Row{Cells: []string{itoa(step), "Status", status}})
			}
			continue
		}
		name, val, ok := strings.Cut(line, ":")
		if !inBlock || !ok {
			continue
		}
		name, val = strings.TrimSpace(name), strings.TrimSpace(val)
		row := Row{Cells: []string{itoa(step), name, val}}
		if strings.EqualFold(name, "location") && base != nil {
			if ref, err := url.Parse(val); err == nil {
				if next := base.ResolveReference(ref).String(); next != "" {
					if v, ok := values.Parse(next); ok && v.Kind == values.URL {
						row.Offers = append(row.Offers, v)
					}
				}
			}
		}
		res.Rows = append(res.Rows, row)
	}
	if step == 0 {
		res.Summary = "No reply. The site may be down, may not speak this protocol, or may refuse the connection."
		return res
	}
	res.Summary = fmt.Sprintf("Final status: %s.", status)
	if step > 1 {
		res.Summary = fmt.Sprintf("%s steps. Final status: %s.", itoa(step), status)
	}
	if strings.HasPrefix(in.Target.Text, "https://") && !hasHeader(res, "strict-transport-security") {
		res.Summary += " No Strict-Transport-Security header."
	}
	return res
}

func hasHeader(r Result, name string) bool {
	for _, row := range r.Rows {
		if strings.EqualFold(row.Cells[1], name) {
			return true
		}
	}
	return false
}
