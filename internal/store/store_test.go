package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCaseRoundTripAndModes(t *testing.T) {
	s := open(t)
	c, err := s.Create("Acme-Q4")
	if err != nil || c.Name != "acme-q4" {
		t.Fatalf("create: %v %v", c, err)
	}
	c.Targets = []string{"10.0.0.5"}
	c.Scope = []string{"10.0.0.0/24"}
	c.Notes = "weekly"
	if err := s.Save(c); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load("acme-q4")
	if err != nil || got.Targets[0] != "10.0.0.5" || got.Scope[0] != "10.0.0.0/24" || got.Notes != "weekly" {
		t.Fatalf("load: %+v %v", got, err)
	}
	fi, err := os.Stat(s.Path("acme-q4") + ".json")
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("case file mode %v %v", fi.Mode(), err)
	}
	di, _ := os.Stat(s.Dir())
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("case folder mode %v", di.Mode())
	}
	if _, err := s.Create("acme-q4"); err == nil {
		t.Error("created a case twice")
	}
	if names := s.List(); len(names) != 1 || names[0] != "acme-q4" {
		t.Errorf("list %v", names)
	}
}

func TestNamesCannotEscape(t *testing.T) {
	s := open(t)
	for _, n := range []string{"", "../x", "a/b", ".hidden", "a b", "a\nb", "-x", "a\x00", string(make([]byte, 50))} {
		if _, err := s.Create(n); err == nil {
			t.Errorf("accepted %q", n)
		}
		if _, err := s.Load(n); err == nil {
			t.Errorf("loaded %q", n)
		}
		if err := s.Append(n, Entry{Time: time.Now()}); err == nil {
			t.Errorf("appended to %q", n)
		}
	}
}

func TestCurrent(t *testing.T) {
	s := open(t)
	if s.Current() != "" {
		t.Fatal("current before any")
	}
	if _, err := s.Create("one"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCurrent("one"); err != nil || s.Current() != "one" {
		t.Fatalf("current %q %v", s.Current(), err)
	}
	os.Remove(s.Path("one") + ".json")
	if s.Current() != "" {
		t.Error("current names a case that is gone")
	}
}

func TestLogAppendsAndSkipsDamagedLines(t *testing.T) {
	s := open(t)
	if _, err := s.Create("c"); err != nil {
		t.Fatal(err)
	}
	if es, err := s.Entries("c"); err != nil || len(es) != 0 {
		t.Fatalf("empty log: %v %v", es, err)
	}
	t1 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for i, tool := range []string{"nmap", "dig"} {
		if err := s.Append("c", Entry{Time: t1.Add(time.Duration(i) * time.Minute), Tool: tool, Argv: []string{tool, "x"}, Scope: "in scope", Findings: i}); err != nil {
			t.Fatal(err)
		}
	}
	f, _ := os.OpenFile(filepath.Join(s.Dir(), "c.log.jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("{not json\n\n{\"tool\":\"no time\"}\n")
	f.Close()
	if err := s.Append("c", Entry{Time: t1.Add(time.Hour), Tool: "curl"}); err != nil {
		t.Fatal(err)
	}
	es, err := s.Entries("c")
	if err != nil || len(es) != 3 || es[0].Tool != "nmap" || es[2].Tool != "curl" {
		t.Fatalf("entries %+v %v", es, err)
	}
	fi, _ := os.Stat(filepath.Join(s.Dir(), "c.log.jsonl"))
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("log mode %v", fi.Mode())
	}
}

func TestDamagedCaseIsReported(t *testing.T) {
	s := open(t)
	os.WriteFile(filepath.Join(s.Dir(), "bad.json"), []byte("{oops"), 0o600)
	if _, err := s.Load("bad"); err == nil {
		t.Error("loaded a damaged case")
	}
}

func TestCleanNameTrimsPastedWhitespace(t *testing.T) {
	if n, err := CleanName("  Acme \n"); err != nil || n != "acme" {
		t.Errorf("got %q %v", n, err)
	}
}
