package tools

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/CurtisD4q/cairn/internal/values"
)

// These run the real programs against this computer only. They check that
// the command lines are ones the installed programs accept and that the
// parsers understand what those programs really print.

func runReal(t *testing.T, tool Tool, in Input) (Result, string, error) {
	t.Helper()
	if !tool.Available() {
		t.Skipf("%s is not installed", tool.Bin)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	argv := tool.Argv(in)
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).Output()
	return tool.Parse(string(out), in), string(out), err
}

func TestLiveSs(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	tool := Ss()
	res, out, err := runReal(t, tool, Input{Opts: tool.Defaults()})
	if err != nil {
		t.Fatalf("ss: %v", err)
	}
	want := "127.0.0.1:" + itoa(port)
	for _, row := range res.Rows {
		for _, o := range row.Offers {
			if o.Text == want {
				return
			}
		}
	}
	t.Errorf("ss did not list %s\n%s\nrows: %q", want, out, cells(res))
}

func TestLiveCurl(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old" {
			http.Redirect(w, r, "/new", http.StatusFound)
			return
		}
		w.Header().Set("Server", "cairn-test")
		w.Write([]byte("hello"))
	}))
	defer srv.Close()
	tool := Curl()
	for _, method := range []string{"head", "get"} {
		in, _ := tool.Accepts(val(t, srv.URL+"/old"))
		in.Opts["method"], in.Opts["redirects"] = method, "on"
		res, out, err := runReal(t, tool, in)
		if err != nil {
			t.Fatalf("curl %s: %v\n%s", method, err, out)
		}
		if !strings.HasPrefix(res.Summary, "2 steps. Final status: 200") {
			t.Errorf("%s: %q\n%s", method, res.Summary, out)
		}
		found := false
		for _, row := range res.Rows {
			found = found || (row.Cells[1] == "Server" && row.Cells[2] == "cairn-test")
		}
		if !found {
			t.Errorf("%s: no Server header in %q", method, cells(res))
		}
	}
	// Without following, the redirect is the answer and offers where it goes.
	in, _ := tool.Accepts(val(t, srv.URL+"/old"))
	res, _, _ := runReal(t, tool, in)
	if !strings.Contains(res.Summary, "302") || len(offers(res)) != 1 || offers(res)[0] != "url:"+srv.URL+"/new" {
		t.Errorf("redirect: %q %v", res.Summary, offers(res))
	}
}

func TestLivePingTracerouteNmap(t *testing.T) {
	lo := val(t, "127.0.0.1")
	{
		tool := Ping()
		in, _ := tool.Accepts(lo)
		in.Opts["count"] = "2"
		res, out, err := runReal(t, tool, in)
		if err != nil || !strings.HasPrefix(res.Summary, "2 of 2 answered") {
			t.Errorf("ping: %v %q\n%s", err, res.Summary, out)
		}
	}
	{
		tool := Traceroute()
		in, _ := tool.Accepts(lo)
		in.Opts["hops"] = "3"
		res, out, err := runReal(t, tool, in)
		if err != nil || len(res.Rows) != 1 || res.Rows[0].Cells[1] != "127.0.0.1" {
			t.Errorf("traceroute: %v %q\n%s", err, cells(res), out)
		}
	}
	{
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skip(err)
		}
		defer ln.Close()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		ep, _ := values.MakeEndpoint("127.0.0.1", ln.Addr().(*net.TCPAddr).Port)
		tool := Nmap()
		in, _ := tool.Accepts(ep)
		in.Opts["skipping"] = "on"
		res, out, err := runReal(t, tool, in)
		if err != nil || len(res.Rows) != 1 || res.Rows[0].Cells[2] != "open" {
			t.Errorf("nmap: %v %q\n%s", err, cells(res), out)
		}
	}
}

func TestLiveDigAndWhoisAcceptTheirArguments(t *testing.T) {
	// There may be no network here, so only the command lines are checked:
	// the programs must start, and fail on the lookup, not on usage.
	for _, tool := range []Tool{Dig(), Whois()} {
		in, _ := tool.Accepts(val(t, "example.invalid"))
		_, out, _ := runReal(t, tool, in)
		if strings.Contains(strings.ToLower(out), "usage") {
			t.Errorf("%s rejected its arguments: %s", tool.ID, out)
		}
	}
}
