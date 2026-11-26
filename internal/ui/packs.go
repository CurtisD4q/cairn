package ui

// cairn's siblings: the Mint packs it is built with. Lookout looks for
// signs of trouble and intrusion, Conduit hunts through the logs, Bridge
// keeps the machines a case works on, and Warden hardens this one. Every
// action they take is written to the open case's audit log.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	mint "github.com/CurtisD4q/pmin-kit"
	"github.com/CurtisD4q/pmin-kit/layouts"

	"github.com/CurtisD4q/pmin-base/values"
	bridge "github.com/CurtisD4q/pmin-bridge"
	bridgeui "github.com/CurtisD4q/pmin-bridge/ui"
	conduit "github.com/CurtisD4q/pmin-conduit"
	conduitui "github.com/CurtisD4q/pmin-conduit/ui"
	lookout "github.com/CurtisD4q/pmin-lookout"
	lookoutui "github.com/CurtisD4q/pmin-lookout/ui"
	netfilter "github.com/CurtisD4q/pmin-netfilter"
	serial "github.com/CurtisD4q/pmin-serial"
	"github.com/CurtisD4q/pmin-tools/action"
	"github.com/CurtisD4q/pmin-tools/run"
	"github.com/CurtisD4q/pmin-tools/scope"
	warden "github.com/CurtisD4q/pmin-warden"
	wardenui "github.com/CurtisD4q/pmin-warden/ui"

	"github.com/CurtisD4q/cairn/internal/security"
	"github.com/CurtisD4q/cairn/internal/store"
)

// packs are the siblings, set up once.
type packs struct {
	exec    action.Executor
	look    *lookout.Lookout
	cond    *conduit.Conduit
	hosts   *bridge.Hosts
	bridge  *bridgeui.App
	program string
	home    string
}

// caseRecorder writes the packs' actions into the open case's audit log,
// so one log holds everything done in the case.
type caseRecorder struct{ a *App }

func (r caseRecorder) Record(e action.Entry) error {
	s := store.Entry{Time: e.Time, Tool: e.Name, Argv: e.Commands, Target: e.Target, Exit: e.Exit, Seconds: e.Seconds, Error: e.Error}
	switch {
	case e.Risk == "read":
		s.Scope = "reads only"
	case !e.Agreed:
		s.Scope = "not agreed"
	default:
		s.Scope = "agreed (" + e.Risk + ")"
	}
	r.a.record(s)
	return nil
}

// plug gives the packs the engines that do their heavy work. The packs use
// only the pmin foundation and never import an engine, so the program
// chooses: Warden reads and changes the firewall with pmin-netfilter, and
// Bridge finds serial ports and opens consoles with pmin-serial.
func plug() {
	warden.Net = netfilter.Engine{}
	bridge.Serial = serial.Engine{}
}

func (a *App) setupPacks() {
	plug()
	exe, _ := os.Executable()
	home := filepath.Dir(a.st.Dir())
	p := &packs{exec: run.Local{}, program: exe, home: home}
	p.look = lookout.New(p.exec)
	security.Add(p.look)
	p.look.Record = caseRecorder{a}
	p.cond = conduit.New(p.exec)
	security.AddHunting(p.cond)
	hs, err := bridge.Load(filepath.Join(home, "machines.json"))
	if err != nil {
		hs, _ = bridge.Load(filepath.Join(home, "machines-new.json"))
	}
	p.hosts = hs
	p.bridge = bridgeui.New(bridgeui.Options{Hosts: hs, Exec: p.exec, Record: caseRecorder{a}})
	a.packs = p
}

// packItems are the siblings' places on the home list.
func (a *App) packItems() []mint.HomeItem {
	p := a.packs
	look := lookoutui.Entries(p.look)
	bridges := p.bridge.Entries()
	harden := wardenui.Entries(wardenui.Options{Exec: p.exec, Record: caseRecorder{a}, Program: p.program, GuardDir: filepath.Join(p.home, "guards")})
	out := []mint.HomeItem{
		{Icon: "?", Label: "What's wrong", Desc: "Has someone got in? What can others reach? Start from what you notice", Open: look[1].Open},
		{Icon: "⌕", Label: "Log hunt", Desc: "Failed logins, who logged in, administrator commands: step by step", Open: a.huntScreen},
		{Icon: "◉", Label: "Health", Desc: "How this machine is doing, kept up to date", Open: look[0].Open},
		{Icon: "⇄", Label: "Machines", Desc: "The machines this work touches: check, connect, tunnel", Open: bridges[0].Open},
		{Icon: "◎", Label: "Keys", Desc: "Your ssh keys and fingerprints", Open: bridges[1].Open},
		{Icon: "⛨", Label: "Harden", Desc: "Accounts, permissions, firewall and ssh, with a lockout guard", Open: harden[0].Open},
	}
	return out
}

// huntScreen lists cairn's ready-made hunts and an empty one.
func (a *App) huntScreen() *mint.Screen {
	var rows []mint.Row
	rows = append(rows, layouts.Paragraphs([]string{"Each hunt is a chain of steps that narrows the logs down to what matters, and shows how many lines each step keeps. Change any step, or start from nothing. Hunting only reads."}, 0.9)...)
	rows = append(rows, mint.Spacer())
	for _, h := range security.Hunts() {
		h := h
		rows = append(rows, mint.Action(mint.ActionOpts{ID: "hunt-" + h.Chain.Name, Label: h.Title, Get: func() string { return h.Plain },
			OnActivate: func(c *mint.Ctx) { c.Push(a.huntBuilder(h.Chain)) }}))
	}
	rows = append(rows, mint.Action(mint.ActionOpts{ID: "hunt-new", Label: "Start from nothing", OnActivate: func(c *mint.Ctx) {
		c.Push(a.huntBuilder(conduit.Chain{}))
	}}))
	return &mint.Screen{Icon: "⌕", Title: "Log hunt", Sections: []mint.Section{{Rows: rows}}}
}

func (a *App) huntBuilder(ch conduit.Chain) *mint.Screen {
	return conduitui.Builder(a.packs.cond, conduitui.Options{Start: ch, Doer: action.Doer{Exec: a.packs.exec, Record: caseRecorder{a}}})
}

var hostSafe = regexp.MustCompile(`[^a-z0-9._-]+`)

// saveMachine saves a value from a result as a Bridge machine, after
// checking it against the case's scope.
func (a *App) saveMachine(c *mint.Ctx, v values.Value) {
	host := v.HostText()
	if host == "" {
		c.ToastWarn("That is not a machine")
		return
	}
	_, _, _, rules, _ := a.snapshot()
	verdict := scope.Check(rules, v)
	if verdict.Status == scope.OutScope && !c.Confirm("Outside your scope", host+" is outside this case's scope. Save it as a machine anyway?") {
		return
	}
	name := strings.Trim(hostSafe.ReplaceAllString(strings.ToLower(host), "-"), "-.")
	if len(name) > 60 {
		name = name[:60]
	}
	if _, exists := a.packs.hosts.Get(name); exists {
		c.Toast(name + " is already a saved machine")
		return
	}
	user, ok := c.Prompt("Save "+host+" as a machine", "The user to log in as (empty: the same as here)", "")
	if !ok {
		return
	}
	h := bridge.Host{Name: name, Address: host, User: strings.TrimSpace(user), Notes: "Saved from case " + a.Case().Name + " on " + time.Now().Format("2 Jan 2006")}
	if v.Kind == values.Endpoint {
		h.Port = v.Port()
	}
	if err := a.packs.hosts.Put(h); err != nil {
		c.ToastError(err.Error())
		return
	}
	if err := a.packs.hosts.Save(); err != nil {
		c.ToastError(err.Error())
		return
	}
	c.Toast(fmt.Sprintf("Saved %s; open Machines to connect or tunnel", name))
}
