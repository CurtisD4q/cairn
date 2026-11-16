package values

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		kind Kind
		text string
	}{
		{"10.0.0.5", IP, "10.0.0.5"},
		{" 10.0.0.5 ", IP, "10.0.0.5"},
		{"::1", IP, "::1"},
		{"10.0.0.7/24", Range, "10.0.0.0/24"},
		{"Example.COM", Domain, "example.com"},
		{"example.com.", Domain, "example.com"},
		{"localhost", Domain, "localhost"},
		{"10.0.0.5:443", Endpoint, "10.0.0.5:443"},
		{"[::1]:80", Endpoint, "[::1]:80"},
		{"scanme.nmap.org:22", Endpoint, "scanme.nmap.org:22"},
		{"https://example.com/a?b=c", URL, "https://example.com/a?b=c"},
		{"http://10.0.0.5:8080", URL, "http://10.0.0.5:8080"},
	}
	for _, c := range cases {
		v, ok := Parse(c.in)
		if !ok || v.Kind != c.kind || v.Text != c.text {
			t.Errorf("Parse(%q) = %v %v, want %s %q", c.in, v, ok, c.kind, c.text)
		}
	}
}

func TestParseRefuses(t *testing.T) {
	for _, in := range []string{
		"", "   ", "-oN", "-p-", "--script=evil", "a b", "host;rm", "a\x00b", "a\nb",
		"example..com", "-example.com", "ftp://example.com", "http://", "http://bad host/",
		"10.0.0.5:0", "10.0.0.5:70000", "10.0.0.5:http", "10.0.0.256", "bücher.de",
		"a$(id).com", "a`id`.com", "|id",
	} {
		if v, ok := Parse(in); ok {
			t.Errorf("Parse(%q) accepted as %v", in, v)
		}
	}
}

func TestAs(t *testing.T) {
	ep, _ := Parse("10.0.0.5:8443")
	u, _ := Parse("http://Example.com:8080/x")
	d, _ := Parse("example.com")
	ip, _ := Parse("10.0.0.5")
	rg, _ := Parse("10.0.0.0/24")

	check := func(v Value, k Kind, want string) {
		t.Helper()
		got, ok := v.As(k)
		if want == "" {
			if ok {
				t.Errorf("%v.As(%s) = %v, want refusal", v, k, got)
			}
			return
		}
		if !ok || got.Text != want {
			t.Errorf("%v.As(%s) = %v %v, want %q", v, k, got, ok, want)
		}
	}
	check(ep, Host, "10.0.0.5")
	check(ep, IP, "10.0.0.5")
	check(ep, Domain, "")
	check(ep, URL, "https://10.0.0.5:8443")
	check(u, Host, "example.com")
	check(u, Domain, "example.com")
	check(d, URL, "https://example.com")
	check(ip, URL, "https://10.0.0.5")
	check(ip, Domain, "")
	check(rg, Host, "")
	check(rg, Range, "10.0.0.0/24")
	v6, _ := Parse("::1")
	check(v6, URL, "https://[::1]")
}

func TestPort(t *testing.T) {
	for in, want := range map[string]int{
		"10.0.0.5:22": 22, "http://x.com": 80, "https://x.com": 443, "http://x.com:81": 81, "x.com": 0, "10.0.0.5": 0,
	} {
		v, ok := Parse(in)
		if !ok || v.Port() != want {
			t.Errorf("%q port %d, want %d", in, v.Port(), want)
		}
	}
}

func TestMakeEndpoint(t *testing.T) {
	if v, ok := MakeEndpoint("::1", 80); !ok || v.Text != "[::1]:80" {
		t.Errorf("got %v %v", v, ok)
	}
	if _, ok := MakeEndpoint("bad host", 80); ok {
		t.Error("accepted a bad host")
	}
	if _, ok := MakeEndpoint("10.0.0.1", 0); ok {
		t.Error("accepted port 0")
	}
}
