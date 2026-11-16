// Package tools describes the programs Cairn can run: what each takes, which
// few options matter, how to build its command line, and how to turn its
// output into rows. Nothing here runs a program; the caller does.
package tools

import (
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CurtisD4q/cairn/internal/values"
)

// Group is the heading a tool is listed under.
type Group string

const (
	Discover Group = "Discover"
	Reach    Group = "Reach"
	LookUp   Group = "Look up"
	Local    Group = "This machine"
)

// Groups is the order the headings are shown in.
var Groups = []Group{Discover, Reach, LookUp, Local}

// OptKind is how an option is changed.
type OptKind int

const (
	Pick   OptKind = iota // one of a short list
	Switch                // on or off
	Count                 // a number
)

// Choice is one entry of a Pick option.
type Choice struct {
	Label string
	Value string
	Plain string // what choosing it does, in a sentence
}

// Option is one setting a tool offers. Each has a plain-words explanation,
// shown beside it, because the flag names alone do not say what they do.
type Option struct {
	ID      string
	Label   string
	Plain   string
	Kind    OptKind
	Choices []Choice
	Default string // the value of a Pick, "on" or "off" for a Switch, a number for a Count
	Min     int
	Max     int
	Unit    string
}

// Input is what a run is given.
type Input struct {
	Target values.Value
	Port   int // from an endpoint, for tools that can use one
	Opts   map[string]string
}

// Opt is an option's value, or its default if it has not been set.
func (in Input) opt(id, def string) string {
	if v, ok := in.Opts[id]; ok {
		return v
	}
	return def
}

func (in Input) on(id string) bool { return in.opt(id, "off") == "on" }

func (in Input) num(id string, def int) int {
	n := atoi(in.opt(id, ""))
	if n == 0 {
		return def
	}
	return n
}

// Row is one line of a result, with the values it offers to other tools.
type Row struct {
	Cells  []string
	Offers []values.Value
}

// Result is what a tool's output means.
type Result struct {
	Headers []string
	Rows    []Row
	Summary string // one plain sentence
}

// Tool is one program.
type Tool struct {
	ID       string
	Title    string
	Group    Group
	Plain    string // what it is for, in a sentence a newcomer can act on
	Bin      string
	Takes    []values.Kind // what it can be pointed at; empty if it needs no target
	UsesPort bool          // an endpoint's port is passed on
	Active   bool          // sends traffic to the target, so scope is checked first
	Options  []Option
	Timeout  time.Duration
	Args     func(Input) []string
	Parse    func(out string, in Input) Result
}

// Needs reports whether the tool must be given a target.
func (t Tool) Needs() bool { return len(t.Takes) > 0 }

// Available reports whether the program is installed.
func (t Tool) Available() bool {
	_, err := exec.LookPath(t.Bin)
	return err == nil
}

// Defaults is the starting value of every option.
func (t Tool) Defaults() map[string]string {
	m := map[string]string{}
	for _, o := range t.Options {
		m[o.ID] = o.Default
	}
	return m
}

// Accepts says whether v can be given to the tool, and if so what the run's
// input would be.
func (t Tool) Accepts(v values.Value) (Input, bool) {
	for _, k := range t.Takes {
		if c, ok := v.As(k); ok {
			in := Input{Target: c, Opts: t.Defaults()}
			if t.UsesPort && v.Kind == values.Endpoint {
				in.Port = v.Port()
			}
			return in, true
		}
	}
	return Input{}, false
}

// Argv is the command line, program first.
func (t Tool) Argv(in Input) []string {
	if in.Opts == nil {
		in.Opts = t.Defaults()
	}
	return append([]string{t.Bin}, t.Args(in)...)
}

// Command is the command line as one line of text, quoted so it can be
// pasted into a shell. It is for showing; Cairn never runs it through one.
func (t Tool) Command(in Input) string { return Quote(t.Argv(in)) }

var safeWord = regexp.MustCompile(`^[A-Za-z0-9@%+=:,./_-]+$`)

// Quote joins words for a shell, quoting those that need it.
func Quote(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if safeWord.MatchString(a) {
			out[i] = a
		} else {
			out[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
	}
	return strings.Join(out, " ")
}

// Candidate is a tool a value can be sent to.
type Candidate struct {
	Tool  Tool
	Input Input
}

// All lists every tool in the order they are shown.
func All() []Tool {
	return []Tool{Nmap(), Traceroute(), Ping(), Curl(), Dig(), Whois(), Ss()}
}

// ByID finds a tool.
func ByID(id string) (Tool, bool) {
	for _, t := range All() {
		if t.ID == id {
			return t, true
		}
	}
	return Tool{}, false
}

// Route lists the tools v can be sent to.
func Route(v values.Value) []Candidate {
	var out []Candidate
	for _, t := range All() {
		if !t.Needs() {
			continue
		}
		if in, ok := t.Accepts(v); ok {
			out = append(out, Candidate{t, in})
		}
	}
	return out
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func clamp(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

func itoa(n int) string { return strconv.Itoa(n) }
