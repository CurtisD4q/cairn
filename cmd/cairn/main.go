// Command cairn is a terminal workbench for security work: one place to keep
// a case, check scope, run the usual tools, and send what one finds to the
// next.
package main

import (
	"fmt"
	"os"

	"github.com/CurtisD4q/cairn/internal/store"
	"github.com/CurtisD4q/cairn/internal/ui"
)

func main() {
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
	// With no arguments, start on the workbench rather than the menu.
	if len(os.Args) == 1 {
		os.Args = append(os.Args, "--screen", "Workbench")
	}
	a.Run()
}
