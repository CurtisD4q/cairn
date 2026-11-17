package tools

import (
	"os"
	"strings"
	"testing"

	"github.com/CurtisD4q/mint-tl/values"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func val(t *testing.T, s string) values.Value {
	t.Helper()
	v, ok := values.Parse(s)
	if !ok {
		t.Fatalf("not a value: %q", s)
	}
	return v
}

func cells(r Result) []string {
	var out []string
	for _, row := range r.Rows {
		out = append(out, strings.Join(row.Cells, "¦"))
	}
	return out
}

func offers(r Result) []string {
	var out []string
	for _, row := range r.Rows {
		for _, o := range row.Offers {
			out = append(out, string(o.Kind)+":"+o.Text)
		}
	}
	return out
}

func eq(t *testing.T, what string, got, want []string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("%s\n got: %q\nwant: %q", what, got, want)
	}
}

func TestNmapParse(t *testing.T) {
	r := parseNmap(fixture(t, "nmap.grep"), Input{})
	eq(t, "rows", cells(r), []string{
		"127.0.0.1¦18080/tcp¦open¦http¦SimpleHTTPServer 0.6 (Python 3.13.17)",
		"127.0.0.1¦443/tcp¦open¦ssl|https¦nginx 1.24.0",
		"127.0.0.1¦53/udp¦open|filtered¦domain¦",
	})
	eq(t, "offers", offers(r), []string{
		"endpoint:127.0.0.1:18080", "url:http://127.0.0.1:18080",
		"endpoint:127.0.0.1:443", "url:https://127.0.0.1:443",
	})
	want := "1 host up, 2 ports open. 1 more may be open (no answer either way). 1 port filtered (blocked by a firewall) and not listed. Service names are guesses from the port number; turn on Identify software to check."
	if r.Summary != want {
		t.Errorf("summary %q", r.Summary)
	}
	r = parseNmap(fixture(t, "nmap_two.grep"), Input{})
	if len(r.Rows) != 3 || !strings.HasPrefix(r.Summary, "2 hosts up, 3 ports open.") {
		t.Errorf("two hosts: %d rows, %q", len(r.Rows), r.Summary)
	}
	eq(t, "web offers", offers(r), []string{
		"endpoint:10.0.0.1:22", "endpoint:10.0.0.1:8080", "url:http://10.0.0.1:8080",
		"endpoint:10.0.0.2:8443", "url:https://10.0.0.2:8443",
	})
	if r := parseNmap("", Input{}); !strings.HasPrefix(r.Summary, "No host answered") {
		t.Errorf("empty: %q", r.Summary)
	}
	if r := parseNmap("Host: 10.0.0.1 ()\tStatus: Up\n", Input{}); !strings.Contains(r.Summary, "no open ports") {
		t.Errorf("up, none open: %q", r.Summary)
	}
}

func TestPingParse(t *testing.T) {
	r := parsePing(fixture(t, "ping.txt"), Input{})
	eq(t, "row", cells(r), []string{"2¦2¦0%¦0.036 ms¦0.061 ms¦0.086 ms"})
	eq(t, "offers", offers(r), []string{"ip:127.0.0.1"})
	if r.Summary != "2 of 2 answered, 0% lost. Average reply 0.061 ms." {
		t.Errorf("summary %q", r.Summary)
	}
	if r := parsePing(fixture(t, "ping_none.txt"), Input{}); !strings.HasPrefix(r.Summary, "No reply") {
		t.Errorf("none: %q", r.Summary)
	}
	if r := parsePing("ping: nosuch: Name or service not known", Input{}); !strings.HasPrefix(r.Summary, "No result") || len(r.Rows) != 0 {
		t.Errorf("failure: %+v", r)
	}
}

func TestTracerouteParse(t *testing.T) {
	r := parseTraceroute(fixture(t, "traceroute.txt"), Input{})
	eq(t, "rows", cells(r), []string{"1¦192.168.1.1¦0.451 ms", "2¦10.20.0.1¦8.904 ms", "3¦no reply¦", "4¦93.184.216.34¦21.500 ms"})
	eq(t, "offers", offers(r), []string{"ip:192.168.1.1", "ip:10.20.0.1", "ip:93.184.216.34"})
	if !strings.Contains(r.Summary, "1 did not reply") {
		t.Errorf("summary %q", r.Summary)
	}
}

func TestDigParse(t *testing.T) {
	r := parseDig(fixture(t, "dig_a.txt"), Input{})
	if len(r.Rows) != 7 || r.Summary != "7 records found." {
		t.Fatalf("%d rows, %q", len(r.Rows), r.Summary)
	}
	eq(t, "cname row", []string{strings.Join(r.Rows[2].Cells, "¦")}, []string{"www.example.com¦CNAME¦example.com¦60"})
	eq(t, "offers", offers(r), []string{
		"ip:93.184.216.34", "ip:93.184.216.35", "domain:example.com", "domain:mail.example.com",
		"domain:a.iana-servers.net", "ip:2606:2800:220:1:248:1893:25c8:1946",
	})
	if r := parseDig("", Input{}); !strings.HasPrefix(r.Summary, "No records") {
		t.Errorf("empty: %q", r.Summary)
	}
}

func TestWhoisParse(t *testing.T) {
	r := parseWhois(fixture(t, "whois_domain.txt"), Input{})
	got := cells(r)
	for _, want := range []string{"Registrar¦RESERVED-Internet Assigned Numbers Authority", "Status¦clientDeleteProhibited", "Name server¦a.iana-servers.net", "Expires¦2025-08-13T04:00:00Z"} {
		found := false
		for _, g := range got {
			found = found || g == want
		}
		if !found {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	eq(t, "offers", offers(r), []string{"domain:a.iana-servers.net", "domain:b.iana-servers.net"})
	r = parseWhois(fixture(t, "whois_ip.txt"), Input{})
	found := false
	for _, g := range cells(r) {
		found = found || g == "Status¦ASSIGNED PA"
	}
	if !found {
		t.Errorf("an address registry's status was cut: %q", cells(r))
	}
	if r := parseWhois("getaddrinfo(whois.x): Name or service not known", Input{}); len(r.Rows) != 0 || !strings.HasPrefix(r.Summary, "No registration") {
		t.Errorf("failure: %+v", r)
	}
}

func TestCurlParse(t *testing.T) {
	r := parseCurl(fixture(t, "curl_head.txt"), Input{Target: val(t, "https://example.com/")})
	if len(r.Rows) != 9 {
		t.Fatalf("%d rows: %q", len(r.Rows), cells(r))
	}
	eq(t, "offers", offers(r), []string{"url:https://example.com/login"})
	if r.Summary != "2 steps. Final status: 200." {
		t.Errorf("summary %q", r.Summary)
	}
	r = parseCurl("HTTP/1.1 200 OK\r\nServer: x\r\n\r\n", Input{Target: val(t, "https://example.com/")})
	if !strings.Contains(r.Summary, "No Strict-Transport-Security") {
		t.Errorf("missing HSTS not noted: %q", r.Summary)
	}
	r = parseCurl("HTTP/1.1 302 Found\nLocation: /next\n\n", Input{Target: val(t, "http://example.com/a/b")})
	eq(t, "relative redirect", offers(r), []string{"url:http://example.com/next"})
	if r := parseCurl("", Input{Target: val(t, "http://x.com")}); !strings.HasPrefix(r.Summary, "No reply") {
		t.Errorf("empty: %q", r.Summary)
	}
}

func TestSsParse(t *testing.T) {
	r := parseSs(fixture(t, "ss.txt"), Input{})
	eq(t, "rows", cells(r), []string{
		"tcp¦0.0.0.0¦2024¦", "tcp¦127.0.0.1¦43593¦", "tcp¦127.0.0.53¦53¦systemd-resolve", "tcp¦::¦8080¦", "udp¦any¦5353¦",
	})
	eq(t, "offers", offers(r), []string{
		"endpoint:127.0.0.1:2024", "endpoint:127.0.0.1:43593", "endpoint:127.0.0.53:53", "endpoint:127.0.0.1:8080", "endpoint:127.0.0.1:5353",
	})
}

// Whatever a program prints, even nonsense, a parser must not panic.
func TestParsersSurviveGarbage(t *testing.T) {
	junk := []string{
		"", "\n\n\n", "Host:", "Host: \t", "Host: x\tPorts: ", "Host: x\tPorts: //////, 1/open", "HTTP/", "HTTP/1.1", "HTTP/1.1 \n: x\n:",
		"a b c d e f", " 1", " 1  ", " 1  *", "10.0.0.1 IN", "x IN A", "x 1 IN A ", ": :", "tcp LISTEN 0 0 :", "tcp LISTEN 0 0 [::]", "tcp LISTEN",
		"Name Server:", "Name Server:   ", "packets transmitted", "\x00\xff\xfe", strings.Repeat("a", 100000),
	}
	in := Input{Target: val(t, "http://example.com/")}
	for _, tool := range All() {
		for _, j := range junk {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("%s panicked on %.40q: %v", tool.ID, j, r)
					}
				}()
				tool.Parse(j, in)
			}()
		}
	}
}

func TestArgsAreSafe(t *testing.T) {
	for _, tool := range All() {
		if !tool.Needs() {
			continue
		}
		in, ok := tool.Accepts(val(t, "http://example.com/x"))
		if !ok {
			in, ok = tool.Accepts(val(t, "example.com"))
		}
		if !ok {
			t.Fatalf("%s accepts neither", tool.ID)
		}
		argv := tool.Argv(in)
		if argv[0] != tool.Bin {
			t.Errorf("%s: first word %q", tool.ID, argv[0])
		}
		// The target cannot be taken for an option: it follows -- (or --url,
		// or is followed only by dig's record type) and does not start with -.
		if strings.HasPrefix(in.Target.Text, "-") {
			t.Errorf("%s: target %q looks like an option", tool.ID, in.Target.Text)
		}
		i := -1
		for j, w := range argv {
			if w == in.Target.Text {
				i = j
			}
		}
		if i < 1 {
			t.Fatalf("%s: target missing from %v", tool.ID, argv)
		}
		switch tool.ID {
		case "dig":
			if i != len(argv)-2 {
				t.Errorf("dig: %v", argv)
			}
		case "curl":
			if argv[i-1] != "--url" {
				t.Errorf("curl: %v", argv)
			}
		default:
			if argv[i-1] != "--" || i != len(argv)-1 {
				t.Errorf("%s: no -- right before the target: %v", tool.ID, argv)
			}
		}
	}
}

func TestOptionsChangeTheCommand(t *testing.T) {
	n := Nmap()
	in, _ := n.Accepts(val(t, "10.0.0.5"))
	if got := n.Command(in); got != "nmap -oG - -- 10.0.0.5" {
		t.Errorf("defaults: %s", got)
	}
	in.Opts["depth"], in.Opts["speed"], in.Opts["versions"], in.Opts["skipping"] = "fast", "careful", "on", "on"
	if got := n.Command(in); got != "nmap -oG - -F -T2 -sV -Pn -- 10.0.0.5" {
		t.Errorf("all on: %s", got)
	}
	in, _ = n.Accepts(val(t, "10.0.0.5:8080"))
	in.Opts["depth"] = "all"
	if got := n.Command(in); got != "nmap -oG - -p 8080 -- 10.0.0.5" {
		t.Errorf("an endpoint's port wins over the depth: %s", got)
	}
	// An unset option uses its default rather than breaking.
	if got := n.Command(Input{Target: val(t, "10.0.0.5")}); got != "nmap -oG - -- 10.0.0.5" {
		t.Errorf("no options: %s", got)
	}
	p := Ping()
	in, _ = p.Accepts(val(t, "example.com"))
	in.Opts["count"] = "999"
	if got := p.Command(in); got != "ping -c 20 -W 2 -- example.com" {
		t.Errorf("count is clamped: %s", got)
	}
	in.Opts["count"] = "abc"
	if got := p.Command(in); got != "ping -c 4 -W 2 -- example.com" {
		t.Errorf("a bad count falls back: %s", got)
	}
	d := Dig()
	in, _ = d.Accepts(val(t, "10.0.0.5"))
	if got := d.Command(in); got != "dig +noall +answer +time=3 +tries=1 -x 10.0.0.5" {
		t.Errorf("reverse lookup: %s", got)
	}
}

func TestRoute(t *testing.T) {
	ids := func(s string) string {
		var out []string
		for _, c := range Route(val(t, s)) {
			out = append(out, c.Tool.ID)
		}
		return strings.Join(out, " ")
	}
	if got := ids("10.0.0.5:8080"); got != "nmap traceroute ping curl dig whois" {
		t.Errorf("endpoint: %s", got)
	}
	if got := ids("example.com"); got != "nmap traceroute ping curl dig whois" {
		t.Errorf("domain: %s", got)
	}
	if got := ids("https://example.com/x"); got != "nmap traceroute ping curl dig whois" {
		t.Errorf("url: %s", got)
	}
	if got := ids("10.0.0.0/24"); got != "nmap" {
		t.Errorf("range: %s", got)
	}
	for _, c := range Route(val(t, "10.0.0.5:8080")) {
		if c.Tool.ID == "nmap" && c.Input.Port != 8080 {
			t.Errorf("nmap lost the port: %+v", c.Input)
		}
		if c.Tool.ID == "ping" && c.Input.Port != 0 {
			t.Errorf("ping was given a port")
		}
		if c.Tool.ID == "curl" && c.Input.Target.Text != "http://10.0.0.5:8080" {
			t.Errorf("curl target %q", c.Input.Target.Text)
		}
	}
}

func TestQuote(t *testing.T) {
	if got := Quote([]string{"a", "b c", "it's", "$(x)", "ok-1.2/x:y"}); got != `a 'b c' 'it'\''s' '$(x)' ok-1.2/x:y` {
		t.Errorf("%s", got)
	}
}

func TestEveryToolIsComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, tool := range All() {
		if tool.ID == "" || tool.Title == "" || tool.Plain == "" || tool.Bin == "" || tool.Args == nil || tool.Parse == nil || tool.Timeout <= 0 {
			t.Errorf("%s is incomplete", tool.ID)
		}
		if seen[tool.ID] {
			t.Errorf("%s twice", tool.ID)
		}
		seen[tool.ID] = true
		ok := false
		for _, g := range Groups {
			ok = ok || g == tool.Group
		}
		if !ok {
			t.Errorf("%s is in no listed group", tool.ID)
		}
		for _, o := range tool.Options {
			if o.Label == "" || (o.Kind != Pick && o.Plain == "") {
				t.Errorf("%s/%s has no explanation", tool.ID, o.ID)
			}
			if o.Kind == Pick {
				found := false
				for _, c := range o.Choices {
					if c.Plain == "" {
						t.Errorf("%s/%s choice %q has no explanation", tool.ID, o.ID, c.Label)
					}
					found = found || c.Value == o.Default
				}
				if !found {
					t.Errorf("%s/%s default %q is not a choice", tool.ID, o.ID, o.Default)
				}
			}
		}
		if got, ok := ByID(tool.ID); !ok || got.ID != tool.ID {
			t.Errorf("ByID(%s)", tool.ID)
		}
	}
}
