// Package scope decides whether a target is one the user said they may test.
// It never looks anything up: a domain name is judged by its text alone.
package scope

import (
	"net/netip"
	"strings"

	"github.com/CurtisD4q/cairn/internal/values"
)

// Status is the answer to "may I test this?".
type Status int

const (
	NoScope  Status = iota // no rules have been set
	InScope                // a rule covers the target
	OutScope               // rules exist and none covers the target
)

func (s Status) String() string {
	switch s {
	case InScope:
		return "in scope"
	case OutScope:
		return "out of scope"
	}
	return "no scope set"
}

// Verdict is a Status with the reason for it.
type Verdict struct {
	Status Status
	Rule   string // the rule that covered the target
	Why    string // in plain words, when the answer is not a clear yes
}

// Rule checks a rule's text. Rules are a network (10.0.0.0/24), an address
// (10.0.0.5) or a domain (example.com covers the domain and everything
// under it; *.example.com covers only what is under it).
func Rule(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", false
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked().String(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.String(), true
	}
	d := strings.TrimPrefix(s, "*.")
	v, ok := values.Parse(d)
	if !ok || v.Kind != values.Domain {
		return "", false
	}
	if strings.HasPrefix(s, "*.") {
		return "*." + v.Text, true
	}
	return v.Text, true
}

// Check judges v against rules. Rules that are not valid are ignored.
func Check(rules []string, v values.Value) Verdict {
	var clean []string
	for _, r := range rules {
		if r, ok := Rule(r); ok {
			clean = append(clean, r)
		}
	}
	if len(clean) == 0 {
		return Verdict{Status: NoScope, Why: "No scope has been set for this case."}
	}
	if v.Kind == values.Range {
		p, _ := netip.ParsePrefix(v.Text)
		for _, r := range clean {
			if rp, err := netip.ParsePrefix(r); err == nil && rp.Bits() <= p.Bits() && rp.Contains(p.Addr()) {
				return Verdict{Status: InScope, Rule: r}
			}
		}
		return Verdict{Status: OutScope, Why: "No rule covers the whole of " + v.Text + "."}
	}
	host := v.HostText()
	if host == "" {
		return Verdict{Status: OutScope, Why: "Nothing to check."}
	}
	if a, err := netip.ParseAddr(host); err == nil {
		for _, r := range clean {
			if rp, err := netip.ParsePrefix(r); err == nil && rp.Contains(a) {
				return Verdict{Status: InScope, Rule: r}
			}
			if ra, err := netip.ParseAddr(r); err == nil && ra == a {
				return Verdict{Status: InScope, Rule: r}
			}
		}
		return Verdict{Status: OutScope, Why: host + " is not in any listed network or address."}
	}
	hasName := false
	for _, r := range clean {
		if _, err := netip.ParsePrefix(r); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(r); err == nil {
			continue
		}
		hasName = true
		if strings.HasPrefix(r, "*.") {
			if strings.HasSuffix(host, r[1:]) {
				return Verdict{Status: InScope, Rule: r}
			}
		} else if host == r || strings.HasSuffix(host, "."+r) {
			return Verdict{Status: InScope, Rule: r}
		}
	}
	if !hasName {
		return Verdict{Status: OutScope, Why: "Cairn does not look up names, so " + host + " cannot be matched to the listed addresses. Use its address, or add the domain to the scope."}
	}
	return Verdict{Status: OutScope, Why: host + " is not under any listed domain."}
}
