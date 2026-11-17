// Package programs finds the Mint apps made by Mint-Interfaces (mint-gen)
// on this computer, so Cairn can list them in groups and run them.
//
// A Mint app is an executable whose name ends in "-mint" (nmap-mint,
// tcpdump-mint) and that describes itself when run with --mint-info. Only
// such files, in the folders below, are ever asked: Cairn does not run
// arbitrary programs to find out what they are.
package programs

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/CurtisD4q/mint-tools/action"
)

// Item is one screen an app opens at.
type Item struct {
	Icon  string `json:"icon"`
	Label string `json:"label"`
	Desc  string `json:"desc"`
}

// Program is one Mint app.
type Program struct {
	Path    string   `json:"-"`
	Name    string   `json:"-"` // the file's name: nmap-mint
	Title   string   `json:"title"`
	Group   string   `json:"group"`
	Note    string   `json:"note"`
	Version string   `json:"version"`
	Require []string `json:"require"`
	Missing []string `json:"missing"`
	Items   []Item   `json:"items"`
}

// Label is the app's title without its icon: "Nmap".
func (p Program) Label() string {
	t := strings.TrimSpace(p.Title)
	if f := strings.Fields(t); len(f) > 1 && len([]rune(f[0])) == 1 {
		t = strings.Join(f[1:], " ")
	}
	if t == "" {
		t = strings.TrimSuffix(p.Name, "-mint")
	}
	return t
}

// Groups is the order groups are shown in: the order mint-gen uses for
// its archetypes. Apps that name no group go under "Anything else".
var Groups = []string{"Answer once", "Observe over time", "Act on targets", "Make something",
	"Change things", "Manage a collection", "Run other things", "Anything else"}

// Dirs are the folders searched: $MINT_APP_DIRS (separated by ":") when it
// is set; otherwise where mint-gen installs apps, and the apps folder of a
// Mint-Interfaces checkout named by $MINT_INTERFACES_DIR.
func Dirs() []string {
	if v := os.Getenv("MINT_APP_DIRS"); v != "" {
		return filepath.SplitList(v)
	}
	home, _ := os.UserHomeDir()
	dirs := []string{filepath.Join(home, ".local", "bin", "mint-interfaces"), filepath.Join(home, ".local", "bin"), "/usr/local/bin"}
	if mi := os.Getenv("MINT_INTERFACES_DIR"); mi != "" {
		dirs = append(dirs, filepath.Join(mi, "apps"))
	}
	return dirs
}

// candidates are the "-mint" executables in each folder and in its
// subfolders one level down (apps/nmap/nmap-mint), first folder first.
func candidates(dirs []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
			return
		}
		name := filepath.Base(p)
		if seen[name] {
			return
		}
		seen[name] = true
		out = append(out, p)
	}
	for _, d := range dirs {
		for _, pattern := range []string{filepath.Join(d, "*-mint"), filepath.Join(d, "*", "*-mint")} {
			ms, _ := filepath.Glob(pattern)
			sort.Strings(ms)
			for _, m := range ms {
				add(m)
			}
		}
	}
	return out
}

// infoTimeout is how long an app has to describe itself.
const infoTimeout = 3 * time.Second

// Find asks every candidate to describe itself, side by side, and returns
// the ones that answered as Mint apps, by title.
func Find(ctx context.Context, exec action.Executor, dirs []string) []Program {
	paths := candidates(dirs)
	out := make([]*Program, len(paths))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, p := range paths {
		wg.Add(1)
		go func(i int, p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := exec.Run(ctx, action.Pipeline{{Argv: []string{p, "--mint-info"}, Timeout: infoTimeout}})
			if !r.OK() || len(r.Stdout) > 1<<20 {
				return
			}
			var prog Program
			if json.Unmarshal(r.Stdout, &prog) != nil || prog.Title == "" {
				return
			}
			prog.Path, prog.Name = p, filepath.Base(p)
			out[i] = &prog
		}(i, p)
	}
	wg.Wait()
	var ps []Program
	for _, p := range out {
		if p != nil {
			ps = append(ps, *p)
		}
	}
	sort.SliceStable(ps, func(i, j int) bool { return strings.ToLower(ps[i].Label()) < strings.ToLower(ps[j].Label()) })
	return ps
}

// Group is one heading and its apps.
type Group struct {
	Name     string
	Programs []Program
}

// ByGroup puts apps under their groups, in Groups order; a group no app
// is in is left out, and unknown groups go after the known ones.
func ByGroup(ps []Program) []Group {
	idx := map[string]int{}
	var gs []Group
	for _, p := range ps {
		g := p.Group
		if g == "" {
			g = "Anything else"
		}
		i, ok := idx[g]
		if !ok {
			i = len(gs)
			idx[g] = i
			gs = append(gs, Group{Name: g})
		}
		gs[i].Programs = append(gs[i].Programs, p)
	}
	rank := func(name string) int {
		for i, g := range Groups {
			if g == name {
				return i
			}
		}
		return len(Groups)
	}
	sort.SliceStable(gs, func(i, j int) bool { return rank(gs[i].Name) < rank(gs[j].Name) })
	return gs
}
