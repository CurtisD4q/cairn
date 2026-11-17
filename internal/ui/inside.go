package ui

// Programs opened inside cairn: a Mint interface (mint-ak) for any
// command-line program, shown in cairn's own frame, with cairn watching
// every command it runs.

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	mint "github.com/CurtisD4q/mint-kt"

	appkit "github.com/CurtisD4q/mint-ak"
	"github.com/CurtisD4q/mint-sp"
	"github.com/CurtisD4q/mint-tl/action"
	"github.com/CurtisD4q/mint-tl/scope"
	"github.com/CurtisD4q/mint-tl/values"

	"github.com/CurtisD4q/cairn/internal/store"
)

// inside keeps one interface per program while cairn runs, so options set
// in nmap are still there when nmap is opened again.
type inside struct {
	mu   sync.Mutex
	apps map[string]*appkit.ToolApp
}

// closeInside wipes every secret typed into a program opened inside cairn.
func (a *App) closeInside() {
	a.in.mu.Lock()
	defer a.in.mu.Unlock()
	for _, t := range a.in.apps {
		t.Close()
	}
	a.in.apps = nil
}

// toolApp is the interface for sp, made once.
func (a *App) toolApp(sp spec.ToolSpec) *appkit.ToolApp {
	a.in.mu.Lock()
	defer a.in.mu.Unlock()
	if a.in.apps == nil {
		a.in.apps = map[string]*appkit.ToolApp{}
	}
	if t, ok := a.in.apps[sp.Name]; ok {
		return t
	}
	t := appkit.New(sp)
	t.Hooks = appkit.Hooks{Guard: a.guardFor(t.Spec), Ran: a.ranFor(t.Spec)}
	a.in.apps[sp.Name] = t
	return t
}

// openInside asks where the program starts, then shows that screen inside
// cairn.
func (a *App) openInside(c *mint.Ctx, sp spec.ToolSpec) {
	t := a.toolApp(sp)
	app := t.BuildApp()
	var items []mint.HomeItem
	var choices []mint.Choice
	for _, it := range app.Items {
		if it.Label == "Theme" {
			continue // cairn has its own look
		}
		items = append(items, it)
		label := it.Label
		if it.Desc != "" {
			label += " — " + it.Desc
		}
		choices = append(choices, mint.Choice{Label: label, Value: fmt.Sprint(len(items) - 1)})
	}
	if len(items) == 0 {
		return
	}
	pick := 0
	if len(items) > 1 {
		ch, ok := c.ChooseItem(label(t.Spec), choices, a.scopeNote(t.Spec))
		if !ok {
			return
		}
		fmt.Sscan(ch.Value, &pick)
	}
	scr := items[pick].Open()
	if scr == nil {
		return
	}
	scr.Breadcrumb = "cairn · " + t.Spec.Name
	if sendsTraffic(t.Spec) && scr.Banner == "" {
		scr.Banner = a.scopeNote(t.Spec)
	}
	c.Push(scr)
}

// label is a program's title without its icon.
func label(sp spec.ToolSpec) string {
	t := strings.TrimSpace(sp.Title)
	if f := strings.Fields(t); len(f) > 1 && len([]rune(f[0])) == 1 {
		t = strings.Join(f[1:], " ")
	}
	if t == "" {
		t = sp.Name
	}
	return t
}

// scopeNote says how cairn treats the program's targets.
func (a *App) scopeNote(sp spec.ToolSpec) string {
	if !sendsTraffic(sp) {
		return "Every run goes in the case's audit log."
	}
	_, _, _, rules, _ := a.snapshot()
	if len(rules) == 0 {
		return "No scope set for this case: runs at a target are refused until you set one in Case."
	}
	return "Scope " + strings.Join(rules, ", ") + ": targets outside it are refused."
}

// networkTools reach other machines even when their archetype does not say
// so.
var networkTools = map[string]bool{
	"curl": true, "wget": true, "ssh": true, "scp": true, "sftp": true, "rsync": true, "nc": true, "ncat": true,
	"netcat": true, "socat": true, "telnet": true, "ftp": true, "ping": true, "ping6": true, "traceroute": true,
	"tracepath": true, "mtr": true, "dig": true, "host": true, "nslookup": true, "whois": true, "nmap": true,
	"masscan": true, "zmap": true, "nikto": true, "gobuster": true, "ffuf": true, "dirb": true, "sqlmap": true,
	"hydra": true, "medusa": true, "wfuzz": true, "httpx": true, "http": true, "openssl": true, "sslscan": true,
	"testssl.sh": true, "smbclient": true, "rpcclient": true, "enum4linux": true, "snmpwalk": true, "ldapsearch": true,
	"arping": true, "hping3": true, "fping": true, "wpscan": true, "nuclei": true, "amass": true, "subfinder": true,
}

// sendsTraffic reports whether a program reaches other machines, so its
// targets must be in scope.
func sendsTraffic(sp spec.ToolSpec) bool {
	if networkTools[sp.BinaryName()] || networkTools[sp.Name] {
		return true
	}
	for _, m := range sp.Members() {
		if m.Group == "Act on targets" {
			return true
		}
	}
	return false
}

// targetsIn finds the machines a command names: addresses, networks,
// names and web addresses among its arguments, and in --option=value. A
// file that exists here is not a machine.
func targetsIn(argv []string) []values.Value {
	var out []values.Value
	seen := map[string]bool{}
	for _, arg := range argv[1:] {
		cand := arg
		if strings.HasPrefix(arg, "-") {
			i := strings.IndexByte(arg, '=')
			if i < 0 {
				continue
			}
			cand = arg[i+1:]
		}
		if at := strings.LastIndexByte(cand, '@'); at > 0 && !strings.Contains(cand, "://") {
			cand = cand[at+1:] // user@host
		}
		if i := strings.IndexByte(cand, ':'); i > 0 && !strings.Contains(cand, "://") {
			if _, ok := values.Parse(cand); !ok {
				cand = cand[:i] // host:path (scp, rsync)
			}
		}
		if cand == "" || seen[cand] {
			continue
		}
		if _, err := os.Stat(cand); err == nil {
			continue
		}
		v, ok := values.Parse(cand)
		if !ok {
			continue
		}
		switch v.Kind {
		case values.IP, values.Range, values.Domain, values.Host, values.URL, values.Endpoint:
			seen[cand] = true
			out = append(out, v)
		}
	}
	return out
}

// guardFor checks each command of a program that sends traffic: every
// target it names must be in the case's scope. A refusal is written to
// the audit log.
func (a *App) guardFor(sp spec.ToolSpec) func([]string) error {
	if !sendsTraffic(sp) {
		return nil
	}
	return func(argv []string) error {
		targets := targetsIn(argv)
		if len(targets) == 0 {
			return nil
		}
		_, _, _, rules, _ := a.snapshot()
		var refused error
		for _, v := range targets {
			switch verdict := scope.Check(rules, v); verdict.Status {
			case scope.NoScope:
				refused = fmt.Errorf("this case has no scope yet, so %s was not run. In Case, list what you may test, then run it again", label(sp))
			case scope.OutScope:
				refused = fmt.Errorf("%s is outside this case's scope (%s), so nothing was sent. Add it in Case if you may test it", v.Text, strings.Join(rules, ", "))
			}
			if refused != nil {
				a.record(store.Entry{Time: time.Now(), Tool: label(sp), Argv: []string{action.Command{Argv: argv}.String()}, Target: v.Text,
					Scope: "refused: " + scope.Check(rules, v).Status.String(), Exit: -1, Error: refused.Error()})
				return refused
			}
		}
		return nil
	}
}

// ranFor writes each finished command to the audit log.
func (a *App) ranFor(sp spec.ToolSpec) func(appkit.Ran) {
	checked := sendsTraffic(sp)
	return func(r appkit.Ran) {
		e := store.Entry{Time: r.Started, Tool: label(sp), Argv: []string{action.Command{Argv: r.Argv}.String()},
			Exit: r.Exit, Seconds: r.Seconds, Scope: "no machine named"}
		if t := targetsIn(r.Argv); len(t) > 0 {
			e.Target = t[0].Text
			e.Scope = "in scope"
		}
		if !checked {
			e.Scope = "not checked (does not reach other machines)"
		}
		if r.Err != nil {
			e.Error = r.Err.Error()
		}
		a.record(e)
	}
}
