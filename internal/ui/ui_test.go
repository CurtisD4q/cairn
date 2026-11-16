package ui

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CurtisD4q/Mint-Interfaces/mint/runner"

	"github.com/CurtisD4q/cairn/internal/scope"
	"github.com/CurtisD4q/cairn/internal/store"
	"github.com/CurtisD4q/cairn/internal/tools"
	"github.com/CurtisD4q/cairn/internal/values"
)

func newApp(t *testing.T) (*App, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(st)
	if err != nil {
		t.Fatal(err)
	}
	return a, st
}

var sgr = regexp.MustCompile("\x1b\\[[0-9;?]*[A-Za-z]")

func plain(s string) string { return sgr.ReplaceAllString(s, "") }

func TestNewMakesADefaultCaseAndRemembersIt(t *testing.T) {
	a, st := newApp(t)
	if a.Case().Name != "default" || st.Current() != "default" {
		t.Fatalf("case %q current %q", a.Case().Name, st.Current())
	}
	if _, err := st.Create("other"); err != nil {
		t.Fatal(err)
	}
	if err := a.use("other"); err != nil || a.Case().Name != "other" {
		t.Fatalf("use: %v %q", err, a.Case().Name)
	}
	b, err := New(st)
	if err != nil || b.Case().Name != "other" {
		t.Fatalf("reopen: %v", err)
	}
}

func TestTargets(t *testing.T) {
	a, st := newApp(t)
	got, err := a.AddTarget("  Example.COM ")
	if err != nil || got != "example.com" {
		t.Fatalf("add: %q %v", got, err)
	}
	if _, err := a.AddTarget("10.0.0.5"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddTarget("example.com"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "-oN /etc/passwd", "a b", "x;y", "http://", "10.0.0.256"} {
		if _, err := a.AddTarget(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	c := a.Case()
	if len(c.Targets) != 2 || c.Active != "example.com" {
		t.Fatalf("targets %v active %q", c.Targets, c.Active)
	}
	a.SetActive("10.0.0.5")
	a.RemoveTarget("10.0.0.5")
	if c := a.Case(); len(c.Targets) != 1 || c.Active != "" {
		t.Fatalf("after remove: %v %q", c.Targets, c.Active)
	}
	saved, _ := st.Load("default")
	if len(saved.Targets) != 1 || saved.Targets[0] != "example.com" {
		t.Fatalf("not saved: %+v", saved)
	}
	for i := 0; i < maxTargets+5; i++ {
		a.AddTarget("10.1." + itoa(i/250) + "." + itoa(i%250+1))
	}
	if n := len(a.Case().Targets); n > maxTargets {
		t.Errorf("%d targets", n)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestScopeRules(t *testing.T) {
	a, _ := newApp(t)
	for _, ok := range []string{"10.0.0.0/24", "Example.com", "*.lab.test", "192.168.1.9"} {
		if err := a.AddScope(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	if err := a.AddScope("example.com"); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"", "not a rule!", "-x", "http://x.com"} {
		if err := a.AddScope(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if got := a.Case().Scope; len(got) != 4 {
		t.Fatalf("scope %v", got)
	}
	a.RemoveScope("example.com")
	if got := a.Case().Scope; len(got) != 3 {
		t.Fatalf("after remove %v", got)
	}
}

func TestNotesAreLimited(t *testing.T) {
	a, _ := newApp(t)
	a.SetNotes(strings.Repeat("x", maxNotes+500))
	if n := len(a.Case().Notes); n != maxNotes {
		t.Errorf("notes %d", n)
	}
}

func TestHubDrawsCaseToolsAndRecent(t *testing.T) {
	a, _ := newApp(t)
	frame := plain(a.hub().FrameText(36, 120))
	for _, want := range []string{"Workbench", "Port scan", "Trace the route", "Name records", "Open ports here", "Nothing run yet", "No scope set"} {
		if !strings.Contains(frame, want) {
			t.Errorf("hub lacks %q:\n%s", want, frame)
		}
	}
	a.AddScope("10.0.0.0/24")
	a.AddTarget("10.0.0.5")
	a.record(store.Entry{Time: time.Now(), Tool: "nmap", Target: "10.0.0.5", Scope: "in scope"})
	frame = plain(a.hub().FrameText(36, 120))
	if strings.Contains(frame, "No scope set:") || !strings.Contains(frame, "nmap") || !strings.Contains(frame, "10.0.0.5") || !strings.Contains(frame, "1 rule") {
		t.Errorf("hub after setting scope and running:\n%s", frame)
	}
}

func TestEveryScreenDrawsAtSmallSizes(t *testing.T) {
	a, _ := newApp(t)
	a.AddTarget("10.0.0.5")
	a.AddScope("10.0.0.0/24")
	a.record(store.Entry{Time: time.Now(), Tool: "ping", Argv: []string{"ping", "x"}, Scope: "in scope"})
	screens := map[string]func() string{}
	for _, size := range [][2]int{{24, 80}, {12, 40}, {40, 160}, {5, 20}} {
		h, w := size[0], size[1]
		screens["hub"] = func() string { return a.hub().FrameText(h, w) }
		screens["case"] = func() string { return a.caseScreen().FrameText(h, w) }
		screens["log"] = func() string { return a.logScreen().FrameText(h, w) }
		screens["guide"] = func() string { return a.guide().FrameText(h, w) }
		for _, tool := range tools.All() {
			tool := tool
			screens[tool.ID] = func() string { return a.toolScreen(tool, a.startInput(tool)).FrameText(h, w) }
		}
		for name, draw := range screens {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("%s at %dx%d panicked: %v", name, h, w, r)
					}
				}()
				if draw() == "" {
					t.Errorf("%s at %dx%d drew nothing", name, h, w)
				}
			}()
		}
	}
}

func TestToolScreenShowsTheExactCommandAndPlainWords(t *testing.T) {
	a, _ := newApp(t)
	a.AddTarget("10.0.0.5")
	nmap := tools.Nmap()
	frame := plain(a.toolScreen(nmap, a.startInput(nmap)).FrameText(40, 120))
	for _, want := range []string{"nmap -oG - -- 10.0.0.5", "Finds which doors", "How many ports", "Checks the 1000 ports", "Identify software", "none set"} {
		if !strings.Contains(frame, want) {
			t.Errorf("nmap screen lacks %q:\n%s", want, frame)
		}
	}
	a.AddScope("10.0.0.0/24")
	frame = plain(a.toolScreen(nmap, a.startInput(nmap)).FrameText(40, 120))
	if !strings.Contains(frame, "in scope (10.0.0.0/24)") {
		t.Errorf("scope not shown:\n%s", frame)
	}
	// A look-up tool is not scope-checked, and says so.
	dig := tools.Dig()
	if f := plain(a.toolScreen(dig, a.startInput(dig)).FrameText(40, 120)); !strings.Contains(f, "not needed") {
		t.Errorf("dig screen:\n%s", f)
	}
}

func TestStartInputUsesOnlyWhatTheToolCanTake(t *testing.T) {
	a, _ := newApp(t)
	a.AddTarget("10.0.0.5:8080")
	if in := a.startInput(tools.Nmap()); in.Target.Text != "10.0.0.5" || in.Port != 8080 {
		t.Errorf("nmap: %+v", in)
	}
	if in := a.startInput(tools.Curl()); in.Target.Text != "http://10.0.0.5:8080" {
		t.Errorf("curl: %+v", in)
	}
	a.AddTarget("10.0.0.0/24")
	if in := a.startInput(tools.Ping()); in.Target.Text != "" {
		t.Errorf("ping took a network: %+v", in)
	}
	if in := a.startInput(tools.Ss()); in.Opts == nil || in.Target.Text != "" {
		t.Errorf("ss: %+v", in)
	}
}

func TestSessionInput(t *testing.T) {
	a, _ := newApp(t)
	s := &session{a: a, t: tools.Ping(), opts: tools.Ping().Defaults()}
	if _, err := s.input(); err == nil || !strings.Contains(err.Error(), "Enter") {
		t.Errorf("empty target: %v", err)
	}
	s.target = "-c 1000000"
	if _, err := s.input(); err == nil {
		t.Error("an option was accepted as a target")
	}
	s.target = "10.0.0.0/24"
	if _, err := s.input(); err == nil || !strings.Contains(err.Error(), "cannot use a network") {
		t.Errorf("network for ping: %v", err)
	}
	s.target = "Example.com"
	in, err := s.input()
	if err != nil || in.Target.Text != "example.com" {
		t.Fatalf("%+v %v", in, err)
	}
	// The screen's option map is copied, not shared with the run.
	in.Opts["count"] = "99"
	if s.opts["count"] == "99" {
		t.Error("run changed the screen's options")
	}
	n := &session{a: a, t: tools.Nmap(), opts: tools.Nmap().Defaults(), target: "10.0.0.5", port: 443}
	if in, _ := n.input(); in.Port != 443 {
		t.Errorf("port lost: %+v", in)
	}
	ss := &session{a: a, t: tools.Ss(), opts: tools.Ss().Defaults()}
	if _, err := ss.input(); err != nil {
		t.Errorf("ss needs no target: %v", err)
	}
}

func TestVerdictOnlyForActiveToolsWithATarget(t *testing.T) {
	a, _ := newApp(t)
	a.AddScope("10.0.0.0/24")
	for id, want := range map[string]bool{"nmap": true, "ping": true, "curl": true, "dig": false, "whois": false, "ss": false} {
		tool, _ := tools.ByID(id)
		v, _ := values.Parse("10.0.0.5")
		s := &session{a: a, t: tool}
		in := tools.Input{Target: v}
		if _, checked := s.verdictFor(in); checked != want {
			t.Errorf("%s checked=%v, want %v", id, checked, want)
		}
	}
}

// fakeTool runs a real, harmless program so the run, parse and log path can
// be exercised without a terminal.
func fakeTool(bin string, args ...string) tools.Tool {
	return tools.Tool{
		ID: "fake", Title: "Fake", Bin: bin, Timeout: 10 * time.Second, Group: tools.Local, Plain: "x",
		Args: func(tools.Input) []string { return args },
		Parse: func(out string, _ tools.Input) tools.Result {
			var r tools.Result
			for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
				if l != "" {
					r.Rows = append(r.Rows, tools.Row{Cells: []string{l}})
				}
			}
			r.Summary = "got output"
			return r
		},
	}
}

func finishRun(t *testing.T, s *session) {
	t.Helper()
	s.argv = s.t.Argv(s.in)
	s.job = runner.Start(commandFor(s.t, s.argv))
	s.job.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for !s.fin && time.Now().Before(deadline) {
		s.poll()
		time.Sleep(10 * time.Millisecond)
	}
	if !s.fin {
		t.Fatal("the run never finished")
	}
}

func TestFinishParsesAndLogs(t *testing.T) {
	a, st := newApp(t)
	tool := fakeTool("printf", "one\ntwo\n")
	s := &session{a: a, t: tool, opts: tool.Defaults(), in: tools.Input{Opts: tool.Defaults()}}
	finishRun(t, s)
	if !s.ran || len(s.res.Rows) != 2 || s.summary != "got output" {
		t.Fatalf("result: ran=%v rows=%d %q", s.ran, len(s.res.Rows), s.summary)
	}
	es, err := st.Entries("default")
	if err != nil || len(es) != 1 {
		t.Fatalf("log: %v %v", es, err)
	}
	e := es[0]
	if e.Tool != "fake" || e.Findings != 2 || e.Exit != 0 || e.Error != "" || e.Scope != "not checked" || e.Argv[0] != "printf" {
		t.Errorf("entry %+v", e)
	}
	if len(a.entries()) != 1 {
		t.Error("recent runs not updated")
	}
}

func TestFinishReportsAFailureInPlainWords(t *testing.T) {
	a, st := newApp(t)
	tool := fakeTool("sh", "-c", "echo 'no route to host' >&2; exit 3")
	tool.Parse = func(string, tools.Input) tools.Result { return tools.Result{Summary: "Nothing found."} }
	s := &session{a: a, t: tool, opts: tool.Defaults(), in: tools.Input{Opts: tool.Defaults()}}
	finishRun(t, s)
	if !strings.Contains(s.summary, "It did not finish") || !strings.Contains(s.summary, "no route to host") {
		t.Errorf("summary %q", s.summary)
	}
	es, _ := st.Entries("default")
	if len(es) != 1 || es[0].Exit != 3 || !strings.Contains(es[0].Error, "no route to host") {
		t.Errorf("entry %+v", es)
	}
}

func TestOverrideAndScopeAreLogged(t *testing.T) {
	a, st := newApp(t)
	tool := fakeTool("true")
	tool.Active, tool.Takes = true, []values.Kind{values.Host}
	v, _ := values.Parse("10.9.9.9")
	s := &session{a: a, t: tool, opts: tool.Defaults(), in: tools.Input{Target: v, Opts: tool.Defaults()}, override: true}
	s.verdict.Status = 2
	finishRun(t, s)
	es, _ := st.Entries("default")
	if len(es) != 1 || es[0].Scope != "out of scope" || !es[0].Override || es[0].Target != "10.9.9.9" {
		t.Errorf("entry %+v", es)
	}
}

func TestReport(t *testing.T) {
	c := &store.Case{Name: "acme", Created: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), Targets: []string{"10.0.0.5"}, Scope: []string{"10.0.0.0/24"}, Notes: "weekly sweep"}
	es := []store.Entry{
		{Time: time.Date(2026, 1, 3, 9, 0, 0, 0, time.UTC), Tool: "nmap", Argv: []string{"nmap", "-oG", "-", "--", "10.0.0.5"}, Target: "10.0.0.5", Scope: "in scope", Findings: 3},
		{Time: time.Date(2026, 1, 3, 9, 5, 0, 0, time.UTC), Tool: "ping", Argv: []string{"ping", "x`y"}, Target: "a|b", Scope: "out of scope", Override: true, Exit: 1, Error: "boom"},
	}
	r := Report(c, es, time.Date(2026, 1, 4, 12, 0, 0, 0, time.UTC))
	for _, want := range []string{"# Case: acme", "- 10.0.0.0/24", "- 10.0.0.5", "weekly sweep", "| 2026-01-03 09:00:00 | nmap | 10.0.0.5 | in scope | 3 found |",
		"out of scope (overridden)", `a\|b`, "failed: boom", "nmap -oG - -- 10.0.0.5"} {
		if !strings.Contains(r, want) {
			t.Errorf("report lacks %q:\n%s", want, r)
		}
	}
	if strings.Count(r, "```") != 2 {
		t.Errorf("a backtick in a command broke the code block:\n%s", r)
	}
	empty := Report(&store.Case{Name: "e", Created: time.Now()}, nil, time.Now())
	if !strings.Contains(empty, "No scope was set.") || !strings.Contains(empty, "None.") {
		t.Errorf("empty report:\n%s", empty)
	}
}

func TestSaveReportWritesAPrivateFile(t *testing.T) {
	a, st := newApp(t)
	a.AddTarget("10.0.0.5")
	path := st.Path("default") + "-report.md"
	body := Report(a.Case(), a.entries(), time.Now())
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("%v %v", fi, err)
	}
}

func TestWrap(t *testing.T) {
	lines := wrap("one two three four five six seven eight nine ten", 16)
	for _, l := range lines {
		if len(l) > 16 {
			t.Errorf("line %q is too long", l)
		}
	}
	if strings.Join(lines, " ") != "one two three four five six seven eight nine ten" {
		t.Errorf("words lost: %q", lines)
	}
	if got := wrap("", 20); len(got) != 0 {
		t.Errorf("%q", got)
	}
	if got := wrap("averyveryverylongwordthatcannotbebroken", 16); len(got) != 1 {
		t.Errorf("%q", got)
	}
}

func TestCandText(t *testing.T) {
	v, _ := values.Parse("10.0.0.5:8080")
	var got []string
	for _, c := range tools.Route(v) {
		got = append(got, c.Tool.ID+"="+candText(c))
	}
	want := "nmap=10.0.0.5, port 8080 traceroute=10.0.0.5 ping=10.0.0.5 curl=http://10.0.0.5:8080 dig=10.0.0.5 whois=10.0.0.5"
	if strings.Join(got, " ") != want {
		t.Errorf("got %v", got)
	}
}

func TestGate(t *testing.T) {
	for _, c := range []struct {
		checked bool
		st      scope.Status
		want    gate
	}{
		{false, scope.OutScope, runFreely}, // a look-up tool is never gated
		{false, scope.NoScope, runFreely},
		{true, scope.InScope, runFreely},
		{true, scope.NoScope, askYesNo},
		{true, scope.OutScope, askToType},
	} {
		if got := gateFor(c.checked, c.st); got != c.want {
			t.Errorf("gateFor(%v, %v) = %v, want %v", c.checked, c.st, got, c.want)
		}
	}
}

func TestCommandsRunDirectlyInEnglish(t *testing.T) {
	ping := tools.Ping()
	in, _ := ping.Accepts(values.Value{Kind: values.IP, Text: "10.0.0.5"})
	argv := ping.Argv(in)
	cmd := commandFor(ping, argv)
	if cmd.Name != "ping" || strings.Join(cmd.Args, " ") != strings.Join(argv[1:], " ") {
		t.Errorf("not run as the command line says: %+v", cmd)
	}
	if cmd.Timeout != ping.Timeout || cmd.RawStdout <= 0 {
		t.Errorf("timeout %v raw %d", cmd.Timeout, cmd.RawStdout)
	}
	english := false
	for _, e := range cmd.Env {
		english = english || e == "LC_ALL=C"
	}
	if !english {
		t.Errorf("output is not forced to English, so the parsers would fail in other languages: %v", cmd.Env)
	}
}
