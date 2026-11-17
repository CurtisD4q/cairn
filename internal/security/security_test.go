package security

import (
	"context"
	"strings"
	"testing"

	conduit "github.com/CurtisD4q/mint-cd"
	lookout "github.com/CurtisD4q/mint-lo"
	"github.com/CurtisD4q/mint-tl/action"
	"github.com/CurtisD4q/mint-tl/run"
)

func judge(t *testing.T, id string, r action.Result) lookout.Finding {
	t.Helper()
	for _, c := range Checks() {
		if c.ID == id {
			return c.Judge(r, lookout.Params{})
		}
	}
	t.Fatalf("no check %s", id)
	return lookout.Finding{}
}

func TestChecksAreSafeAndComplete(t *testing.T) {
	l := lookout.New(nil)
	Add(l)
	if l.Symptoms[0].ID != "intrusion" {
		t.Fatal("cairn's symptoms come first")
	}
	for _, s := range l.Symptoms {
		for _, id := range s.Checks {
			if _, ok := l.Check(id); !ok {
				t.Errorf("%s names missing check %s", s.ID, id)
			}
		}
	}
	for _, c := range Checks() {
		if err := c.Probe(lookout.Params{}).Validate(); err != nil {
			t.Errorf("%s: %v", c.ID, err)
		}
	}
}

func TestJudges(t *testing.T) {
	old := journalDirs
	defer func() { journalDirs = old }()
	journalDirs = []string{t.TempDir()}
	if f := judge(t, "failed-logins", action.Result{Stdout: []byte("0\n"), Exit: 1}); f.Status != lookout.OK {
		t.Fatalf("%+v", f)
	}
	if f := judge(t, "failed-logins", action.Result{Stdout: []byte("3\n")}); f.Status != lookout.Warn || !strings.Contains(f.Next, "Failed logins by address") {
		t.Fatalf("%+v", f)
	}
	if f := judge(t, "failed-logins", action.Result{Stdout: []byte("412\n")}); f.Status != lookout.Bad || !strings.Contains(f.Summary, "guessing passwords") {
		t.Fatalf("%+v", f)
	}
	if f := judge(t, "failed-logins", action.Result{Stderr: []byte("No journal files were found.\n"), Stdout: []byte("0\n"), Exit: 1}); f.Status != lookout.Unknown {
		t.Fatalf("no journal: %+v", f)
	}
	journalDirs = []string{"/nonexistent-journal"}
	if f := judge(t, "failed-logins", action.Result{Stdout: []byte("0\n"), Exit: 1}); f.Status != lookout.Unknown {
		t.Fatalf("with no journal, no failed logins is not good news: %+v", f)
	}
	journalDirs = []string{t.TempDir()}
	if f := judge(t, "root-accounts", action.Result{Stdout: []byte("root\ntoor\n")}); f.Status != lookout.Bad || f.Details[0] != "toor" {
		t.Fatalf("%+v", f)
	}
	if f := judge(t, "root-accounts", action.Result{Stdout: []byte("root\n")}); f.Status != lookout.OK {
		t.Fatal("only root")
	}
	if f := judge(t, "new-keys", action.Result{Stdout: []byte("2026-11-16 /home/bob/.ssh/authorized_keys\n")}); f.Status != lookout.Warn {
		t.Fatal("new keys")
	}
	sudo := "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update\n"
	if f := judge(t, "sudo-use", action.Result{Stdout: []byte(sudo)}); f.Details[0] != "alice : /usr/bin/apt update" && !strings.Contains(f.Details[0], "/usr/bin/apt update") {
		t.Fatalf("%+v", f)
	}
	ss := "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 128 127.0.0.1:5432 0.0.0.0:*\nLISTEN 0 511 [::]:8080 [::]:*\n"
	f := judge(t, "open-to-all", action.Result{Stdout: []byte(ss)})
	if f.Status != lookout.Warn || len(f.Details) != 2 || strings.Contains(f.Summary, "5432") {
		t.Fatalf("%+v", f)
	}
}

// The hunts, run for real over a saved ssh log: the same steps, with the
// log read from a file instead of the journal.
func TestHuntsForReal(t *testing.T) {
	c := conduit.New(run.Local{})
	AddHunting(c)
	run := func(h Hunt) string {
		ch := h.Chain
		ch.Source = conduit.Source{Files: []string{"testdata/sshd.log"}}
		a, err := c.Action(ch)
		if err != nil {
			t.Fatal(err)
		}
		o := action.Doer{Exec: c.Exec}.Do(context.Background(), a)
		if !o.OK() {
			t.Fatalf("%s: %+v", h.Title, o.Results)
		}
		return strings.Join(strings.Fields(string(o.Results[0].Stdout)), " ")
	}
	hs := Hunts()
	if got := run(hs[0]); got != "3 198.51.100.23 2 203.0.113.9" {
		t.Fatalf("failed logins: %q", got)
	}
	if got := run(hs[1]); got != "2 192.0.2.10 1 192.0.2.44" {
		t.Fatalf("logins: %q", got)
	}
	for _, h := range hs {
		if c.Risk(h.Chain) != action.Read {
			t.Errorf("%s must only read", h.Title)
		}
		if _, err := c.Text(h.Chain); err != nil {
			t.Errorf("%s: %v", h.Title, err)
		}
	}
	if txt, _ := c.Text(HuntFor("10.0.0.5")); !strings.HasSuffix(txt, `grep -E -i -- '10\.0\.0\.5'`) {
		t.Fatal(txt)
	}
}
