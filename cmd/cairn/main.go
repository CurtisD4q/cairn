// Command cairn is a terminal workbench for security work: one place to keep
// a case, check scope, run the usual tools, and send what one finds to the
// next.
package main

import (
	"fmt"
	"os"

	"github.com/CurtisD4q/pmin-base/selfinstall"
	warden "github.com/CurtisD4q/pmin-warden"

	"github.com/CurtisD4q/cairn/internal/store"
	"github.com/CurtisD4q/cairn/internal/ui"
)

func main() {
	// `cairn install` puts this program on the PATH, with cairn.el beside
	// it; `cairn uninstall` takes them off again.
	if ok, code := selfinstall.Handle(selfinstall.Program{Name: "cairn", Files: []string{"emacs/cairn.el"},
		After: "For Emacs, add to your init file: (load \"{data}/cairn.el\")"}, os.Args[1:], os.Stdout, os.Stderr); ok {
		os.Exit(code)
	}
	// A guarded change (Hardening) runs cairn again in the
	// background to put things back if the change cuts the person off.
	if warden.HandleArgs(os.Args[1:]) {
		return
	}
	st, err := store.Open("")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cairn:", err)
		os.Exit(1)
	}
	a, err := ui.New(st)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cairn:", err)
		os.Exit(1)
	}
	// With no arguments cairn opens on its launch menu.
	a.Run()
}
