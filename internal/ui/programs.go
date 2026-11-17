package ui

// The Programs page: every Mint program on this computer, in drop-down
// groups, plus any program typed by name. A program opens inside cairn, in
// the Mint layout: its options, the exact command, Run and what came back,
// in panes. For programs that send traffic, every command is checked
// against the case's scope first; every command is written to the case's
// audit log. Apps built with mint-g carry no description, so they still
// open on their own.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	mint "github.com/CurtisD4q/mint-kit"
	"github.com/CurtisD4q/mint-kit/layouts"

	gen "github.com/CurtisD4q/mint-gen"
	"github.com/CurtisD4q/mint-spec"
	"github.com/CurtisD4q/mint-tools/action"

	"github.com/CurtisD4q/cairn/internal/programs"
	"github.com/CurtisD4q/cairn/internal/store"
)

type programList struct {
	mu     sync.Mutex
	found  []programs.Program
	looked bool
}

// keptDir is where cairn keeps the programs opened by name.
func (a *App) keptDir() string {
	return filepath.Join(filepath.Dir(a.st.Dir()), "programs")
}

// findPrograms gathers every source: cairn's own kept programs first, then
// mint-wr's, then Mint programs on the PATH-like folders.
func (a *App) findPrograms() []programs.Program {
	found := programs.Find(context.Background(), a.packs.exec, programs.Dirs())
	return programs.Merge(
		programs.Kept(a.keptDir(), "cairn"),
		programs.Kept(programs.WrapperDir(), "mint-wr"),
		found,
	)
}

func (a *App) programsScreen() *mint.Screen {
	pl := &programList{}
	look := func() {
		found := a.findPrograms()
		pl.mu.Lock()
		pl.found, pl.looked = found, true
		pl.mu.Unlock()
	}
	scr := &mint.Screen{Icon: "▤", Title: "Programs"}
	scr.Enter = func(*mint.Screen) {
		pl.mu.Lock()
		done := pl.looked
		pl.mu.Unlock()
		if !done {
			look()
		}
	}
	scr.Refresh = func(s *mint.Screen) {
		pl.mu.Lock()
		found, looked := pl.found, pl.looked
		pl.mu.Unlock()
		head := layouts.Paragraphs([]string{"Any command-line program, opened inside cairn: its options, the exact command, Run and what came back, side by side. Programs that reach other machines are checked against this case's scope before every run, and every run goes in the audit log."}, 0.9)
		head = append(head, mint.Spacer(),
			mint.Action(mint.ActionOpts{ID: "open-any", Label: "Open a program…", Get: func() string { return "any program, by name" }, OnActivate: func(c *mint.Ctx) {
				name, ok := c.Prompt("Open a program", "Its name, such as nmap, rsync or tar", "")
				name = strings.TrimSpace(name)
				if !ok || name == "" {
					return
				}
				if sp, ok := a.prepareProgram(c, name); ok {
					look()
					a.openInside(c, sp)
				}
			}}),
			mint.Action(mint.ActionOpts{ID: "look", Label: "Look again", OnActivate: func(c *mint.Ctx) {
				c.Busy("Looking for Mint programs…", look)
			}}),
		)
		switch {
		case !looked:
			head = append(head, mint.Note("Looking…"))
		case len(found) == 0:
			head = append(head, layouts.Paragraphs([]string{
				"None kept yet. Open a program by name, or make standalone copies with mint-wr (mint-wr --make nmap) and they appear here.",
			}, 0.9)...)
		}
		sections := []mint.Section{{Rows: head}}
		for _, g := range programs.ByGroup(found) {
			var rows []mint.Row
			for _, p := range g.Programs {
				p := p
				rows = append(rows, mint.Action(mint.ActionOpts{ID: "prog-" + p.Name, Label: p.Label(), Get: func() string { return programState(p) },
					OnActivate: func(c *mint.Ctx) { a.openProgram(c, p) }}))
			}
			// Each group starts folded, like a drop-down; the screen
			// remembers which ones the person has opened.
			sections = append(sections, mint.CollapsibleSection(fmt.Sprintf("%s (%d)", g.Name, len(g.Programs)), true, rows...))
		}
		s.Sections = sections
	}
	return scr
}

// programState is the line beside a program: what it needs, or what it
// is for.
func programState(p programs.Program) string {
	if len(p.Missing) > 0 {
		return "needs " + strings.Join(p.Missing, ", ")
	}
	desc := p.Note
	if desc == "" && len(p.Items) > 0 {
		desc = p.Items[0].Desc
	}
	if p.Spec == nil {
		desc = "opens on its own · " + desc
	}
	if desc == "" {
		return p.Name
	}
	return clip(desc, 48)
}

// prepareProgram checks a program typed by name, in the background, and
// keeps its description so it is listed from now on.
func (a *App) prepareProgram(c *mint.Ctx, name string) (spec.ToolSpec, bool) {
	var p gen.Prepared
	c.Busy("Checking "+name+"…", func() { p = gen.Prepare(name) })
	switch p.Fit {
	case gen.NotInstalled:
		c.Message(name+" is not here", p.Why+"\n\n"+p.Instead)
		return spec.ToolSpec{}, false
	case gen.DoesNotFit:
		c.Message(name+" cannot open here", p.Why+"\n\n"+p.Instead)
		return spec.ToolSpec{}, false
	case gen.FitsPartly:
		if !c.Confirm("Open "+name+" anyway?", p.Why) {
			return spec.ToolSpec{}, false
		}
	}
	path := filepath.Join(a.keptDir(), safeName(p.Spec.Name)+".json")
	if err := gen.SaveSpec(path, p.Spec); err != nil {
		c.ToastWarn("Could not keep " + name + " in the list: " + err.Error())
	}
	return p.Spec, true
}

func safeName(s string) string {
	var b strings.Builder
	for _, r := range filepath.Base(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.', r == '+':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.TrimLeft(b.String(), ".")
	if out == "" {
		out = "program"
	}
	return out
}

// openProgram opens a listed program: inside cairn when there is a
// description, otherwise on its own.
func (a *App) openProgram(c *mint.Ctx, p programs.Program) {
	if len(p.Missing) > 0 {
		c.Message(p.Label()+" cannot run here", p.Label()+" needs "+strings.Join(p.Missing, ", ")+", which is not installed.")
		return
	}
	if p.Spec != nil {
		if _, err := os.Stat(p.Path); p.Source != "copy" || err == nil {
			a.openInside(c, *p.Spec)
			return
		}
	}
	a.handOver(c, p)
}

// handOver runs an app that has no description cairn can read, giving it
// the terminal until it quits.
func (a *App) handOver(c *mint.Ctx, p programs.Program) {
	items := []mint.Choice{{Label: "Open " + p.Label(), Value: ""}}
	for _, it := range p.Items {
		label := "Start at " + it.Label
		if it.Desc != "" {
			label += " — " + it.Desc
		}
		items = append(items, mint.Choice{Label: label, Value: it.Label})
	}
	pick, ok := c.ChooseItem(p.Label(), items, p.Name+": it opens on its own, so cairn cannot check its targets or log what it runs.")
	if !ok {
		return
	}
	argv := []string{p.Path}
	if pick.Value != "" {
		argv = append(argv, "--screen", pick.Value)
	}
	if p.Group == "Act on targets" {
		_, _, _, rules, _ := a.snapshot()
		scopeText := "This case has no scope set."
		if len(rules) > 0 {
			scopeText = "This case's scope: " + strings.Join(rules, ", ") + "."
		}
		if !c.Confirm("Open "+p.Label()+"?", p.Label()+" sends traffic to the targets you give it, and it opens on its own, so cairn cannot check them: check each target yourself.\n\n"+scopeText) {
			return
		}
	}
	start := time.Now()
	code, err := c.Handover(argv, "", nil)
	e := store.Entry{Time: start, Tool: "Opened " + p.Label(), Argv: []string{action.Command{Argv: argv}.String()}, Scope: "handed over (not checked)",
		Exit: code, Seconds: time.Since(start).Seconds()}
	if err != nil {
		e.Error = err.Error()
		c.ToastError("Could not open " + p.Label() + ": " + err.Error())
	}
	a.record(e)
}
