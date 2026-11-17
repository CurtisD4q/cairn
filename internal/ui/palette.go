package ui

import (
	"os"

	"github.com/CurtisD4q/mint-kt"
	"github.com/CurtisD4q/mint-kt/theme"
)

// cairnSpec is cairn's own look: slate and sea-glass, with amber kept for
// warnings so that it always means something.
const cairnSpec = "accent=#5eead4,bright=#ccfbf1,text=#e2e8f0,muted=#94a3b8,on=#86efac,amber=#fbbf24,selbg=#134e4a,err=#fca5a5"

// UsePalette gives the app its own colours, unless the person has chosen a
// theme (in the Theme screen or with MINT_PALETTE), which always wins.
func UsePalette() {
	if os.Getenv("MINT_PALETTE") != "" || theme.Current() != "default" {
		return
	}
	if p, err := theme.FromSpec(theme.Load("default"), cairnSpec); err == nil {
		mint.SetPalette(p)
	}
}
