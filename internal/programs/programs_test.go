package programs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CurtisD4q/mint-tools/run"
)

func script(t *testing.T, path, body string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestFindAsksOnlyMintAppsAndGroupsThem(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	// A "-mint" app answering --mint-info, one in an apps/<tool>/ folder,
	// one that is not a Mint app, and a non "-mint" program that must
	// never be run.
	script(t, filepath.Join(dir, "nmap-mint"), "#!/bin/sh\necho '{\"title\":\"◈ Nmap\",\"group\":\"Act on targets\",\"items\":[{\"label\":\"Probe\"}]}'\n")
	script(t, filepath.Join(dir, "apps", "df", "df-mint"), "#!/bin/sh\necho '{\"title\":\"◈ Df\",\"group\":\"Answer once\"}'\n")
	script(t, filepath.Join(dir, "liar-mint"), "#!/bin/sh\necho not json\n")
	script(t, filepath.Join(dir, "rm"), "#!/bin/sh\ntouch "+marker+"\n")
	os.WriteFile(filepath.Join(dir, "notexec-mint"), []byte("x"), 0o644)
	ps := Find(context.Background(), run.Local{}, []string{dir, filepath.Join(dir, "apps")})
	if len(ps) != 2 || ps[0].Label() != "Df" || ps[1].Label() != "Nmap" || ps[1].Items[0].Label != "Probe" {
		t.Fatalf("%+v", ps)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a program not named -mint was run")
	}
	gs := ByGroup(append(ps, Program{Title: "X", Name: "x-mint"}))
	var names []string
	for _, g := range gs {
		names = append(names, g.Name)
	}
	if strings.Join(names, ",") != "Answer once,Act on targets,Anything else" {
		t.Fatal(names)
	}
}

func TestRealGeneratedApps(t *testing.T) {
	dir := os.Getenv("MINT_TEST_APPS")
	if dir == "" {
		t.Skip("set MINT_TEST_APPS to a folder of apps built by mint-g")
	}
	ps := Find(context.Background(), run.Local{}, []string{dir})
	if len(ps) == 0 {
		t.Fatal("no apps found")
	}
	for _, p := range ps {
		if p.Group == "" || len(p.Items) == 0 {
			t.Errorf("%s: %+v", p.Name, p)
		}
	}
}
