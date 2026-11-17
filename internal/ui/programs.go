package ui

// The Programs page: every Mint app made by Mint-Interfaces on this
// computer, in drop-down groups. Choose a program first, then where to
// open it; cairn hands it the terminal and takes it back when it ends.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	mint "github.com/CurtisD4q/mint-kit"
	"github.com/CurtisD4q/mint-kit/layouts"
	"github.com/CurtisD4q/mint-tools/action"

	"github.com/CurtisD4q/cairn/internal/programs"
	"github.com/CurtisD4q/cairn/internal/store"
)

type programList struct {
	mu     sync.Mutex
	found  []programs.Program
	looked bool
}

func (a *App) programsScreen() *mint.Screen {
	pl := &programList{}
	dirs := programs.Dirs()
	look := func(c *mint.Ctx) {
		var found []programs.Program
		c.Busy("Looking for Mint programs…", func() {
			found = programs.Find(context.Background(), a.packs.exec, dirs)
		})
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
			found := programs.Find(context.Background(), a.packs.exec, dirs)
			pl.mu.Lock()
			pl.found, pl.looked = found, true
			pl.mu.Unlock()
		}
	}
	scr.Refresh = func(s *mint.Screen) {
		pl.mu.Lock()
		found, looked := pl.found, pl.looked
		pl.mu.Unlock()
		intro := layouts.Paragraphs([]string{"Programs made with Mint-Interfaces, grouped by what they do. Open a group, choose a program, then choose where it starts. It takes over the screen until you quit it, then you are back here."}, 0.9)
		var sections []mint.Section
		head := append(intro, mint.Spacer())
		switch {
		case !looked:
			head = append(head, mint.Note("Looking…"))
		case len(found) == 0:
			head = append(head, layouts.Paragraphs([]string{
				"No Mint programs found in " + strings.Join(dirs, ", ") + ".",
				"Make one with Mint-Interfaces (mint-gen --build --install nmap), or set MINT_APP_DIRS to the folders yours are in.",
			}, 0.9)...)
		}
		head = append(head, mint.Action(mint.ActionOpts{ID: "look", Label: "Look again", OnActivate: look}))
		sections = append(sections, mint.Section{Rows: head})
		for _, g := range programs.ByGroup(found) {
			g := g
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
	if len(p.Items) > 0 && p.Items[0].Desc != "" {
		return clip(p.Items[0].Desc, 48)
	}
	return p.Name
}

// openProgram asks where to start the chosen program, then runs it.
func (a *App) openProgram(c *mint.Ctx, p programs.Program) {
	if len(p.Missing) > 0 {
		c.Message(p.Label()+" cannot run here", p.Label()+" needs "+strings.Join(p.Missing, ", ")+", which is not installed.")
		return
	}
	items := []mint.Choice{{Label: "Open " + p.Label(), Value: ""}}
	for _, it := range p.Items {
		label := "Start at " + it.Label
		if it.Desc != "" {
			label += " — " + it.Desc
		}
		items = append(items, mint.Choice{Label: label, Value: it.Label})
	}
	sub := p.Name
	if p.Note != "" {
		sub += ": " + p.Note
	}
	pick, ok := c.ChooseItem(p.Label(), items, sub)
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
		if !c.Confirm("Open "+p.Label()+"?", p.Label()+" sends traffic to the targets you give it. cairn's scope check does not reach inside it, so check each target yourself.\n\n"+scopeText) {
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
