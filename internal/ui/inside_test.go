package ui

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appkit "github.com/CurtisD4q/mint-appkit"
	"github.com/CurtisD4q/mint-spec"
)

func TestTargetsInACommand(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "notes.txt")
	os.WriteFile(local, nil, 0o600)
	got := func(argv ...string) string {
		var s []string
		for _, v := range targetsIn(argv) {
			s = append(s, string(v.Kind)+":"+v.Text)
		}
		return strings.Join(s, " ")
	}
	for _, c := range []struct {
		argv []string
		want string
	}{
		{[]string{"nmap", "-sV", "-p", "22", "10.0.0.5"}, "ip:10.0.0.5"},
		{[]string{"nmap", "10.0.0.0/24"}, "range:10.0.0.0/24"},
		{[]string{"curl", "-sI", "https://example.lab.test/x"}, "url:https://example.lab.test/x"},
		{[]string{"ssh", "alice@10.20.0.5"}, "ip:10.20.0.5"},
		{[]string{"rsync", "-a", local, "backup@10.1.2.3:/srv/"}, "ip:10.1.2.3"},
		{[]string{"nmap", "--exclude=10.0.0.9", "10.0.0.5"}, "ip:10.0.0.9 ip:10.0.0.5"},
		{[]string{"tar", "-cf", local}, ""},
	} {
		if g := got(c.argv...); g != c.want {
			t.Errorf("%q: got %q, want %q", c.argv, g, c.want)
		}
	}
}

func TestOnlyProgramsThatReachOtherMachinesAreChecked(t *testing.T) {
	if !sendsTraffic(spec.ToolSpec{Name: "curl"}) || !sendsTraffic(spec.ToolSpec{Name: "nmap", ArchetypeID: "probe"}) {
		t.Error("curl and nmap reach other machines")
	}
	if sendsTraffic(spec.ToolSpec{Name: "tar", ArchetypeID: "convert"}) || sendsTraffic(spec.ToolSpec{Name: "df", ArchetypeID: "list"}) {
		t.Error("tar and df do not")
	}
}

func TestGuardKeepsProgramsInScope(t *testing.T) {
	a, _ := newApp(t)
	nmap := spec.ToolSpec{Name: "nmap", ArchetypeID: "probe"}
	guard := a.guardFor(nmap)
	if guard == nil {
		t.Fatal("nmap needs a guard")
	}
	if a.guardFor(spec.ToolSpec{Name: "df", ArchetypeID: "list"}) != nil {
		t.Error("df needs no guard")
	}
	if err := guard([]string{"nmap", "10.0.0.5"}); err == nil || !strings.Contains(err.Error(), "no scope yet") {
		t.Errorf("no scope: %v", err)
	}
	if err := a.AddScope("10.0.0.0/24"); err != nil {
		t.Fatal(err)
	}
	if err := guard([]string{"nmap", "-p", "22", "10.0.0.5"}); err != nil {
		t.Errorf("in scope was refused: %v", err)
	}
	err := guard([]string{"nmap", "10.0.0.5", "192.168.1.1"})
	if err == nil || !strings.Contains(err.Error(), "192.168.1.1 is outside") {
		t.Errorf("out of scope: %v", err)
	}
	if err := guard([]string{"nmap", "--version"}); err != nil {
		t.Errorf("no target named: %v", err)
	}
	// Refusals are in the audit log.
	var refused int
	for _, e := range a.entries() {
		if strings.HasPrefix(e.Scope, "refused") {
			refused++
		}
	}
	if refused != 2 {
		t.Errorf("%d refusals logged, want 2", refused)
	}
}

func TestRunsInsideCairnAreLoggedAndGuarded(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	a, _ := newApp(t)
	if err := a.AddScope("127.0.0.0/8"); err != nil {
		t.Fatal(err)
	}
	tool := a.toolApp(spec.ToolSpec{Name: "ping", ArchetypeID: "probe"})
	if tool != a.toolApp(spec.ToolSpec{Name: "ping"}) {
		t.Error("a program's interface should be kept while cairn runs")
	}
	tool.Target = "192.168.77.1"
	if _, err := tool.StartJob(); !errors.Is(err, appkit.ErrRefused) {
		t.Fatalf("out of scope should be refused: %v", err)
	}
	tool.Hooks.Ran(appkit.Ran{Argv: []string{"ping", "-c", "1", "127.0.0.1"}, Started: time.Now(), Exit: 0})
	ents := a.entries()
	last := ents[len(ents)-1]
	if last.Tool != "ping" || last.Target != "127.0.0.1" || last.Scope != "in scope" || !strings.Contains(last.Argv[0], "ping -c 1 127.0.0.1") {
		t.Errorf("logged %+v", last)
	}
	a.closeInside()
}
