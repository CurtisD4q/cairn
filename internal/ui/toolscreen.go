package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/CurtisD4q/pmin-kit"
	"github.com/CurtisD4q/pmin-kit/runner"

	"github.com/CurtisD4q/cairn/internal/security"
	"github.com/CurtisD4q/cairn/internal/store"
	"github.com/CurtisD4q/cairn/internal/tools"
	"github.com/CurtisD4q/pmin-base/values"
	"github.com/CurtisD4q/pmin-tools/scope"
)

// debPackage names the package that holds each program on Debian and Ubuntu,
// for the "not installed" message.
var debPackage = map[string]string{
	"nmap": "nmap", "ping": "iputils-ping", "traceroute": "traceroute",
	"curl": "curl", "dig": "dnsutils", "whois": "whois", "ss": "iproute2",
}

// startInput is what a tool starts with: the case's active target, if the
// tool can take it.
func (a *App) startInput(t tools.Tool) tools.Input {
	in := tools.Input{Opts: t.Defaults()}
	if !t.Needs() {
		return in
	}
	_, active, _, _, _ := a.snapshot()
	if v, ok := values.Parse(active); ok {
		if got, ok := t.Accepts(v); ok {
			return got
		}
	}
	return in
}

func (a *App) openTool(c *mint.Ctx, t tools.Tool, in tools.Input) {
	if !t.Available() {
		msg := "cairn runs the program '" + t.Bin + "', and it was not found on this computer.\n\nInstall it with your package manager, then open this again."
		if p := debPackage[t.Bin]; p != "" {
			msg += "\n\nOn Debian or Ubuntu:  sudo apt install " + p
		}
		c.Message(t.Title+" is not installed", msg)
		return
	}
	c.Push(a.toolScreen(t, in))
}

// session is one visit to one tool: what was typed, what is running, and
// what came back.
type session struct {
	a      *App
	t      tools.Tool
	target string // as typed
	port   int    // from a result sent here; cleared when the target is edited
	opts   map[string]string

	job      *runner.Job
	argv     []string
	in       tools.Input
	verdict  scope.Verdict
	override bool
	fin      bool
	ran      bool
	res      tools.Result
	summary  string
	lastSec  int
}

func (a *App) toolScreen(t tools.Tool, in tools.Input) *mint.Screen {
	s := &session{a: a, t: t, target: in.Target.Text, port: in.Port, opts: map[string]string{}}
	for k, v := range t.Defaults() {
		s.opts[k] = v
	}
	for k, v := range in.Opts {
		s.opts[k] = v
	}
	scr := &mint.Screen{
		Icon: "▸", Title: t.Title, TopTitle: "Run", Hints: toolHints, TopWidth: 1.1, Weight: 0.5, SectionSpacing: 1, Boxed: true,
		Poll:   func(*mint.Screen) bool { return s.poll() },
		Status: s.badges,
		Context: func() string {
			if s.target == "" {
				return a.context()
			}
			return a.context() + " · target " + s.target
		},
	}
	about := &mint.Pane{Title: "In plain words", Beside: true, Width: 1, Weight: 0.5}
	results := &mint.Pane{Title: "What came back", Weight: 0.5}
	scr.Refresh = func(sc *mint.Screen) { sc.Sections = s.runSections() }
	about.Refresh = func(p *mint.Pane) { p.Sections = s.aboutSections() }
	results.Refresh = func(p *mint.Pane) { p.Sections = s.resultSections() }
	scr.Sections, about.Sections, results.Sections = s.runSections(), s.aboutSections(), s.resultSections()
	scr.Panes = []*mint.Pane{about, results}
	return scr
}

const toolHints = " ↑↓ move   ⏎ change or open   ←→ adjust   b back   q quit "

// input reads the screen's fields into something a tool can run.
func (s *session) input() (tools.Input, error) {
	opts := map[string]string{}
	for k, v := range s.opts {
		opts[k] = v
	}
	if !s.t.Needs() {
		return tools.Input{Opts: opts}, nil
	}
	v, ok := values.Parse(s.target)
	if !ok {
		return tools.Input{}, fmt.Errorf("Enter %s.", takesText(s.t))
	}
	in, ok := s.t.Accepts(v)
	if !ok {
		return tools.Input{}, fmt.Errorf("%s cannot use %s. It takes %s.", s.t.Title, indefinite(kindName(v.Kind)), takesText(s.t))
	}
	in.Opts = opts
	if s.port > 0 && s.t.UsesPort {
		in.Port = s.port
	}
	return in, nil
}

func takesText(t tools.Tool) string {
	var parts []string
	for _, k := range t.Takes {
		switch k {
		case values.Host:
			parts = append(parts, "an address or a name")
		case values.Range:
			parts = append(parts, "a network")
		case values.URL:
			parts = append(parts, "a web address (starting http:// or https://)")
		default:
			parts = append(parts, indefinite(kindName(k)))
		}
	}
	return strings.Join(parts, " or ")
}

func indefinite(w string) string {
	if w != "" && strings.ContainsRune("aeiou", rune(w[0])) {
		return "an " + w
	}
	return "a " + w
}

func (s *session) running() bool { return s.job != nil && s.job.Running() }

// verdictFor is the scope answer for the target now typed. Tools that only
// look things up, or only look at this computer, are not scope-checked.
func (s *session) verdictFor(in tools.Input) (scope.Verdict, bool) {
	if !s.t.Active || !s.t.Needs() {
		return scope.Verdict{}, false
	}
	_, _, _, rules, _ := s.a.snapshot()
	return scope.Check(rules, in.Target), true
}

func (s *session) runSections() []mint.Section {
	var rows []mint.Row
	if s.t.Needs() {
		rows = append(rows, mint.Text(mint.TextOpts{
			Label: "Target", Placeholder: takesShort(s.t), Get: func() string { return s.target },
			Set: func(v string) {
				v = strings.TrimSpace(v)
				if v != s.target {
					s.target, s.port = v, 0
				}
			},
		}))
		if _, _, targets, _, _ := s.a.snapshot(); len(targets) > 0 {
			rows = append(rows, mint.Action(mint.ActionOpts{Label: "Choose from the case's targets…", OnActivate: s.chooseTarget}))
		}
		if s.port > 0 && s.t.UsesPort {
			rows = append(rows, mint.Value(mint.ValueOpts{Label: "Port", Get: func() string { return fmt.Sprint(s.port) }}))
		}
	}
	for _, o := range s.t.Options {
		rows = append(rows, s.optionRow(o))
	}
	rows = append(rows, mint.Divider())
	in, err := s.input()
	switch {
	case err != nil:
		rows = append(rows, mint.Label(mint.StyleCaption, err.Error()))
	default:
		if v, checked := s.verdictFor(in); checked {
			rows = append(rows, mint.Value(mint.ValueOpts{Label: "Scope", Get: func() string { return scopeText(v) }}))
		} else {
			rows = append(rows, mint.Value(mint.ValueOpts{Label: "Scope", Get: func() string { return "not needed" }}))
		}
		rows = append(rows, mint.Label(mint.StyleCaption, "The command"))
		rows = append(rows, paragraph(mint.StyleBody, s.t.Command(in), 0.45)...)
	}
	if s.running() {
		rows = append(rows,
			mint.Value(mint.ValueOpts{Label: "Running", Get: func() string { return fmt.Sprintf("%ds", int(s.job.Elapsed().Seconds())) }}),
			mint.Action(mint.ActionOpts{Label: "■ Stop", Hint: "ends it now", OnActivate: func(c *mint.Ctx) { s.job.Stop(); c.Toast("Stopping…") }}))
	} else {
		rows = append(rows, mint.Action(mint.ActionOpts{Label: "▶ Run", Hint: "⏎", OnActivate: s.start, Does: s.does}))
	}
	return []mint.Section{{Rows: rows}}
}

func takesShort(t tools.Tool) string {
	for _, k := range t.Takes {
		if k == values.URL {
			return "https://example.com"
		}
	}
	return "address or name"
}

func scopeText(v scope.Verdict) string {
	switch v.Status {
	case scope.InScope:
		return "in scope (" + v.Rule + ")"
	case scope.OutScope:
		return "OUT OF SCOPE"
	}
	return "none set"
}

func (s *session) optionRow(o tools.Option) mint.Row {
	switch o.Kind {
	case tools.Switch:
		return mint.Toggle(mint.ToggleOpts{
			Label: o.Label,
			Get:   func() bool { return s.opts[o.ID] == "on" },
			Set: func(on bool) {
				if on {
					s.opts[o.ID] = "on"
				} else {
					s.opts[o.ID] = "off"
				}
			},
		})
	case tools.Count:
		return mint.Stepper(mint.StepperOpts{
			Label: o.Label, Min: o.Min, Max: o.Max, Step: 1, Unit: o.Unit,
			Get: func() int {
				n := 0
				fmt.Sscanf(s.opts[o.ID], "%d", &n)
				if n < o.Min || n > o.Max {
					fmt.Sscanf(o.Default, "%d", &n)
				}
				return n
			},
			Set: func(n int) { s.opts[o.ID] = fmt.Sprint(n) },
		})
	}
	labels := make([]string, len(o.Choices))
	for i, c := range o.Choices {
		labels[i] = c.Label
	}
	return mint.Picker(mint.PickerOpts{
		Label: o.Label, Options: labels,
		Get: func() string {
			for _, c := range o.Choices {
				if c.Value == s.opts[o.ID] {
					return c.Label
				}
			}
			return labels[0]
		},
		Set: func(label string) {
			for _, c := range o.Choices {
				if c.Label == label {
					s.opts[o.ID] = c.Value
				}
			}
		},
	})
}

// aboutSections explains the tool and the choices made, in plain words. The
// text sits beside the controls so nothing has to be looked up elsewhere.
func (s *session) aboutSections() []mint.Section {
	rows := paragraph(mint.StyleBody, s.t.Plain, 0.45)
	if s.t.Active {
		rows = append(rows, mint.Spacer())
		rows = append(rows, paragraph(mint.StyleCaption, "This sends traffic to the target, so cairn checks your scope first.", 0.45)...)
	}
	secs := []mint.Section{{Rows: rows}}
	if len(s.t.Options) > 0 {
		var o []mint.Row
		for _, opt := range s.t.Options {
			o = append(o, mint.Label(mint.StyleHeading, opt.Label))
			o = append(o, paragraph(mint.StyleBody, s.optionPlain(opt), 0.45)...)
		}
		secs = append(secs, mint.Section{Name: "What your choices do", Rows: o})
	}
	return secs
}

func (s *session) optionPlain(o tools.Option) string {
	if o.Kind == tools.Pick {
		for _, c := range o.Choices {
			if c.Value == s.opts[o.ID] {
				return c.Plain
			}
		}
		return o.Choices[0].Plain
	}
	text := o.Plain
	if o.Kind == tools.Switch {
		if s.opts[o.ID] == "on" {
			return "On. " + text
		}
		return "Off. " + text
	}
	return text
}

func (s *session) resultSections() []mint.Section {
	if !s.ran {
		msg := "Nothing yet. Choose Run."
		if s.running() {
			msg = "Running…"
		}
		return []mint.Section{{Rows: []mint.Row{mint.Label(mint.StyleCaption, msg)}}}
	}
	rows := paragraph(mint.StyleHeading, s.summary, 0.9)
	rows = append(rows, mint.Table(mint.TableOpts{
		Headers: s.res.Headers, Get: s.tableRows, Empty: "No rows",
		OnSelect: func(c *mint.Ctx, i int, _ []string) { s.sendTo(c, i) },
	}))
	rows = append(rows, mint.Label(mint.StyleCaption, "Select a row to send it to another tool, add it to the case, or copy it."))
	if s.job != nil {
		rows = append(rows, mint.Action(mint.ActionOpts{Label: "Full output…", OnActivate: func(c *mint.Ctx) { c.Push(mint.ViewLog("Full output", s.job.Lines)) }}))
	}
	return []mint.Section{{Rows: rows}}
}

func (s *session) tableRows() [][]string {
	out := make([][]string, len(s.res.Rows))
	for i, r := range s.res.Rows {
		out[i] = r.Cells
	}
	return out
}

func (s *session) chooseTarget(c *mint.Ctx) {
	_, _, targets, _, _ := s.a.snapshot()
	var items []mint.Choice
	for _, t := range targets {
		v, _ := values.Parse(t)
		if got, ok := s.t.Accepts(v); ok {
			items = append(items, mint.Choice{Label: t + "   (" + kindName(v.Kind) + ")", Value: got.Target.Text})
		}
	}
	if len(items) == 0 {
		c.ToastWarn(s.t.Title + " cannot use any of this case's targets. It takes " + takesText(s.t) + ".")
		return
	}
	if pick, ok := c.ChooseItem("Targets for "+s.t.Title, items, "Only targets this tool can use are listed"); ok {
		s.target, s.port = pick.Value, 0
	}
}

// gate is how much a run must be confirmed before it starts.
type gate int

const (
	runFreely gate = iota // in scope, or not a scope-checked tool
	askYesNo              // no scope has been set
	askToType             // outside the scope: the target must be typed out
)

// gateFor decides what a run must be confirmed with. Going outside the
// scope takes more than a keypress.
func gateFor(checked bool, st scope.Status) gate {
	switch {
	case !checked || st == scope.InScope:
		return runFreely
	case st == scope.OutScope:
		return askToType
	}
	return askYesNo
}

// does is what Enter on Run does, for the pane's header.
func (s *session) does() string {
	in, err := s.input()
	if err != nil {
		return "needs " + takesText(s.t)
	}
	return "runs " + s.t.Command(in)
}

// start checks scope, asks if it must, and runs the tool.
func (s *session) start(c *mint.Ctx) {
	if s.running() {
		c.ToastWarn("It is already running.")
		return
	}
	in, err := s.input()
	if err != nil {
		c.ToastWarn(err.Error())
		return
	}
	v, checked := s.verdictFor(in)
	s.override = false
	cmd := s.t.Command(in)
	// Anything that reaches another machine asks first, showing the
	// command; one question, however the scope came out.
	switch gateFor(checked, v.Status) {
	case askYesNo:
		if !c.Confirm("No scope set", cmd+"\n\nThis sends traffic to "+in.Target.Text+", and you have not said what you are allowed to test.\n\ncairn will log this run. Continue?") {
			return
		}
		s.override = true
	case askToType:
		if !c.TypeToConfirm("Outside your scope", cmd+"\n\n"+v.Why+"\n\nIf you are sure you may test it, type the target to go ahead. cairn will log that you did.", in.Target.Text) {
			return
		}
		s.override = true
	default:
		if checked && !c.Confirm("Run this?", cmd+"\n\n✓ "+scopeText(v)+"\n\nIt reaches "+in.Target.Text+", and the run is written to the audit log.") {
			return
		}
	}
	argv := s.t.Argv(in)
	s.in, s.argv, s.verdict = in, argv, v
	s.fin, s.ran, s.lastSec = false, false, 0
	s.job = runner.Start(commandFor(s.t, argv))
	c.Toast("Started " + s.t.Title)
}

// commandFor is how a tool's command line is run: directly, never through a
// shell, with the output kept in the form the parsers read.
func commandFor(t tools.Tool, argv []string) runner.Cmd {
	return runner.Cmd{
		Name: argv[0], Args: argv[1:], Timeout: t.Timeout, RawStdout: 4 << 20, Label: t.Title,
		Env: []string{"LC_ALL=C", "LANG=C"}, // the parsers read English output
	}
}

// poll is called about ten times a second; it reports when the screen must
// be drawn again, and handles a run that has just ended.
func (s *session) poll() bool {
	if s.job == nil {
		return false
	}
	changed := s.job.Changed()
	if s.job.Running() {
		if sec := int(s.job.Elapsed().Seconds()); sec != s.lastSec {
			s.lastSec, changed = sec, true
		}
		return changed
	}
	if !s.fin {
		s.finish()
		changed = true
	}
	return changed
}

func (s *session) finish() {
	s.fin = true
	raw, _ := s.job.RawStdout()
	s.res = s.t.Parse(string(raw), s.in)
	s.summary = s.res.Summary
	e := store.Entry{
		Time: time.Now().UTC().Truncate(time.Second), Tool: s.t.ID, Argv: s.argv,
		Scope: "not checked", Override: s.override, Exit: s.job.ExitCode(),
		Seconds: s.job.Elapsed().Seconds(), Findings: len(s.res.Rows),
	}
	if s.t.Needs() {
		e.Target = s.in.Target.Text
	}
	if s.t.Active && s.t.Needs() {
		e.Scope = s.verdict.Status.String()
	}
	if code := s.job.ExitCode(); code != 0 && len(s.res.Rows) == 0 {
		why := firstLine(s.job.LastError())
		if why == "" && s.job.Err() != nil {
			why = s.job.Err().Error()
		}
		if why == "" {
			why = fmt.Sprintf("it stopped with exit code %d", code)
		}
		e.Error = clip(why, 200)
		s.summary = "It did not finish: " + e.Error + ". " + s.res.Summary
	}
	s.ran = true
	s.a.record(e)
	if e.Error != "" {
		mint.ToastWarn(s.t.Title + " did not finish")
	} else {
		mint.Toast(s.t.Title + ": " + clip(s.res.Summary, 60))
	}
}

func (s *session) badges() []mint.Badge {
	var b []mint.Badge
	if s.job != nil {
		b = append(b, s.job.Badges()...)
	}
	return append(b, s.a.status()...)
}

// sendTo offers what a result row holds: add it to the case, copy it, or
// open it in a tool that can use it.
func (s *session) sendTo(c *mint.Ctx, i int) {
	if i < 0 || i >= len(s.res.Rows) {
		return
	}
	offers := s.res.Rows[i].Offers
	if len(offers) == 0 {
		c.Toast("Nothing in this row can be sent on. Copy it with y.")
		return
	}
	type act struct {
		offer values.Value
		cand  *tools.Candidate
		kind  string
	}
	var items []mint.Choice
	acts := map[string]act{}
	add := func(label string, a act) {
		key := fmt.Sprint(len(items))
		acts[key] = a
		items = append(items, mint.Choice{Label: label, Value: key})
	}
	for _, o := range offers {
		o := o
		for _, cand := range tools.Route(o) {
			cand := cand
			if cand.Tool.ID == s.t.ID && cand.Input.Target.Text == s.in.Target.Text {
				continue
			}
			add("Open in "+cand.Tool.Title+"   "+candText(cand), act{offer: o, cand: &cand, kind: "tool"})
		}
		add("Hunt for it in the logs   "+o.Text, act{offer: o, kind: "hunt"})
		if o.HostText() != "" {
			add("Save as a machine (connect, tunnel, copy)   "+o.HostText(), act{offer: o, kind: "machine"})
		}
		add("Add to the case's targets   "+o.Text, act{offer: o, kind: "add"})
		add("Copy   "+o.Text, act{offer: o, kind: "copy"})
	}
	pick, ok := c.ChooseItem("Send to…", items, "Choose what to do with this result")
	if !ok {
		return
	}
	a := acts[pick.Value]
	switch a.kind {
	case "add":
		if t, err := s.a.AddTarget(a.offer.Text); err != nil {
			c.ToastWarn(err.Error())
		} else {
			c.Toast("Added " + t + " to the case")
		}
	case "copy":
		c.Copy(a.offer.Text, "the value")
	case "hunt":
		c.Push(s.a.huntBuilder(security.HuntFor(a.offer.Text)))
	case "machine":
		s.a.saveMachine(c, a.offer)
	case "tool":
		s.a.openTool(c, a.cand.Tool, a.cand.Input)
	}
}

// candText is what a tool would be pointed at, as the person will see it.
func candText(c tools.Candidate) string {
	if c.Input.Port > 0 {
		return fmt.Sprintf("%s, port %d", c.Input.Target.Text, c.Input.Port)
	}
	return c.Input.Target.Text
}
