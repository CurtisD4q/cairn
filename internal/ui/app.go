// Package ui is Cairn's terminal interface, built on the Mint library: the
// workbench, the case, one screen per tool, and the audit log.
package ui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/CurtisD4q/Mint-Interfaces/mint"
	"github.com/CurtisD4q/Mint-Interfaces/mint/runner"

	"github.com/CurtisD4q/cairn/internal/store"
	"github.com/CurtisD4q/cairn/internal/values"
)

// Version is Cairn's version.
const Version = "0.1.0"

// Limits keep a case file small and its screens quick.
const (
	maxTargets = 200
	maxScope   = 200
	maxNotes   = 2000
)

// App is the program: the open case and the store it lives in.
type App struct {
	st   *store.Store
	mu   sync.Mutex
	cs   *store.Case
	ents []store.Entry
}

// New opens the store's current case, making one called "default" if there is
// none.
func New(st *store.Store) (*App, error) {
	a := &App{st: st}
	name := st.Current()
	if name == "" {
		if names := st.List(); len(names) > 0 {
			name = names[0]
		} else {
			name = "default"
		}
	}
	return a, a.use(name)
}

// use makes name the open case, creating it if it does not exist.
func (a *App) use(name string) error {
	c, err := a.st.Load(name)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if c, err = a.st.Create(name); err != nil {
			return err
		}
	}
	ents, err := a.st.Entries(c.Name)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.cs, a.ents = c, ents
	a.mu.Unlock()
	return a.st.SetCurrent(c.Name)
}

// Case is the open case. Callers must not change it directly.
func (a *App) Case() *store.Case {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cs
}

func (a *App) save() {
	a.mu.Lock()
	c := *a.cs
	a.mu.Unlock()
	if err := a.st.Save(&c); err != nil {
		mint.ToastError("Could not save the case: " + err.Error())
	}
}

// AddTarget checks a target, adds it to the case and makes it the one tools
// start with. It returns the target as stored.
func (a *App) AddTarget(text string) (string, error) {
	v, ok := values.Parse(text)
	if !ok {
		return "", fmt.Errorf("%q is not an address, name, network or web address", clip(text, 40))
	}
	a.mu.Lock()
	found := false
	for _, t := range a.cs.Targets {
		found = found || t == v.Text
	}
	if !found {
		if len(a.cs.Targets) >= maxTargets {
			a.mu.Unlock()
			return "", fmt.Errorf("a case holds up to %d targets", maxTargets)
		}
		a.cs.Targets = append(a.cs.Targets, v.Text)
	}
	a.cs.Active = v.Text
	a.mu.Unlock()
	a.save()
	return v.Text, nil
}

// RemoveTarget takes a target out of the case.
func (a *App) RemoveTarget(text string) {
	a.mu.Lock()
	var keep []string
	for _, t := range a.cs.Targets {
		if t != text {
			keep = append(keep, t)
		}
	}
	a.cs.Targets = keep
	if a.cs.Active == text {
		a.cs.Active = ""
	}
	a.mu.Unlock()
	a.save()
}

// SetActive makes an existing target the one tools start with.
func (a *App) SetActive(text string) {
	a.mu.Lock()
	a.cs.Active = text
	a.mu.Unlock()
	a.save()
}

// AddScope checks a scope rule and adds it.
func (a *App) AddScope(text string) error {
	rule, ok := ruleOf(text)
	if !ok {
		return fmt.Errorf("%q is not a network, address or domain", clip(text, 40))
	}
	a.mu.Lock()
	for _, r := range a.cs.Scope {
		if r == rule {
			a.mu.Unlock()
			return nil
		}
	}
	if len(a.cs.Scope) >= maxScope {
		a.mu.Unlock()
		return fmt.Errorf("a case holds up to %d scope rules", maxScope)
	}
	a.cs.Scope = append(a.cs.Scope, rule)
	a.mu.Unlock()
	a.save()
	return nil
}

// RemoveScope takes a rule out of the scope.
func (a *App) RemoveScope(rule string) {
	a.mu.Lock()
	var keep []string
	for _, r := range a.cs.Scope {
		if r != rule {
			keep = append(keep, r)
		}
	}
	a.cs.Scope = keep
	a.mu.Unlock()
	a.save()
}

// SetNotes stores the case notes.
func (a *App) SetNotes(s string) {
	if len(s) > maxNotes {
		s = s[:maxNotes]
	}
	a.mu.Lock()
	a.cs.Notes = s
	a.mu.Unlock()
	a.save()
}

// snapshot copies what a screen needs, so it never holds the lock while it
// draws.
func (a *App) snapshot() (name string, active string, targets, rules []string, notes string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cs.Name, a.cs.Active, append([]string(nil), a.cs.Targets...), append([]string(nil), a.cs.Scope...), a.cs.Notes
}

func (a *App) record(e store.Entry) {
	a.mu.Lock()
	name := a.cs.Name
	a.ents = append(a.ents, e)
	a.mu.Unlock()
	if err := a.st.Append(name, e); err != nil {
		mint.ToastError("Could not write the audit log: " + err.Error())
	}
}

func (a *App) entries() []store.Entry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]store.Entry(nil), a.ents...)
}

// Items is the home list.
func (a *App) Items() []mint.HomeItem {
	return []mint.HomeItem{
		{Icon: "◈", Label: "Workbench", Desc: "Your case, your tools and what they found", Open: a.hub},
		{Icon: "◇", Label: "Case", Desc: "Targets, scope and notes", Open: a.caseScreen},
		{Icon: "≡", Label: "Audit log", Desc: "Every command run in this case", Open: a.logScreen},
		{Icon: "?", Label: "How this works", Desc: "A short guide, in plain words", Open: a.guide},
	}
}

func (a *App) status() []mint.Badge {
	name, _, _, rules, _ := a.snapshot()
	b := []mint.Badge{{Text: "case " + name, Kind: mint.BadgeInfo}}
	if len(rules) == 0 {
		b = append(b, mint.Badge{Text: "no scope set", Kind: mint.BadgeWarn})
	}
	return b
}

// Run opens the interface and returns when the person quits.
func (a *App) Run() {
	UsePalette()
	app := &mint.App{
		Title:   "◈ Cairn",
		Crumb:   "Cairn",
		Version: Version,
		Items:   a.Items(),
		Status:  a.status,
	}
	app.Run()
	runner.StopAll()
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func stamp(t time.Time) string { return t.Local().Format("15:04:05") }

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

func cleanCase(s string) (string, error) { return store.CleanName(s) }
