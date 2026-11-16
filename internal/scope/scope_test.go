package scope

import (
	"testing"

	"github.com/CurtisD4q/cairn/internal/values"
)

func v(t *testing.T, s string) values.Value {
	t.Helper()
	x, ok := values.Parse(s)
	if !ok {
		t.Fatalf("not a value: %q", s)
	}
	return x
}

func TestCheck(t *testing.T) {
	rules := []string{"10.0.0.0/24", "192.168.1.9", "Example.com", "*.lab.test"}
	cases := []struct {
		target string
		want   Status
	}{
		{"10.0.0.77", InScope},
		{"10.0.1.77", OutScope},
		{"192.168.1.9", InScope},
		{"192.168.1.10", OutScope},
		{"10.0.0.77:443", InScope},
		{"http://10.0.0.9/admin", InScope},
		{"example.com", InScope},
		{"www.example.com", InScope},
		{"notexample.com", OutScope},
		{"example.com.evil.org", OutScope},
		{"a.lab.test", InScope},
		{"lab.test", OutScope},
		{"10.0.0.0/25", InScope},
		{"10.0.0.0/23", OutScope},
		{"https://shop.example.com/x", InScope},
	}
	for _, c := range cases {
		if got := Check(rules, v(t, c.target)); got.Status != c.want {
			t.Errorf("%s: %v (%s), want %v", c.target, got.Status, got.Why, c.want)
		}
	}
}

func TestNoRulesAndBadRules(t *testing.T) {
	if got := Check(nil, v(t, "10.0.0.1")); got.Status != NoScope || got.Why == "" {
		t.Errorf("no rules: %+v", got)
	}
	if got := Check([]string{"", "not a rule!", "-x"}, v(t, "10.0.0.1")); got.Status != NoScope {
		t.Errorf("only bad rules: %+v", got)
	}
}

func TestNamesAgainstAddressRulesExplainThemselves(t *testing.T) {
	got := Check([]string{"10.0.0.0/24"}, v(t, "intranet.local"))
	if got.Status != OutScope || got.Why == "" {
		t.Errorf("%+v", got)
	}
}

func TestRule(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.9/24": "10.0.0.0/24", " Example.COM ": "example.com", "*.Lab.test": "*.lab.test", "10.0.0.1": "10.0.0.1",
	} {
		if got, ok := Rule(in); !ok || got != want {
			t.Errorf("Rule(%q) = %q %v, want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "*.", "*", "a b", "-x", "http://x.com", "10.0.0.1:80"} {
		if got, ok := Rule(in); ok {
			t.Errorf("Rule(%q) accepted as %q", in, got)
		}
	}
}
