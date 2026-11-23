package ui

import (
	"testing"

	bridge "github.com/CurtisD4q/pmin-bridge"
	warden "github.com/CurtisD4q/pmin-warden"
)

// cairn plugs in the engines its packs need: without them Harden would
// have no firewall screens and Machines no serial consoles.
func TestPlug(t *testing.T) {
	warden.Net, bridge.Serial = nil, nil
	plug()
	if warden.Net == nil || bridge.Serial == nil {
		t.Fatalf("not plugged: warden.Net=%v bridge.Serial=%v", warden.Net, bridge.Serial)
	}
}
