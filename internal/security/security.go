// Package security is what Cairn adds to the Mint packs for security work:
// Lookout checks and symptoms for "has someone got in?", Conduit hunts
// through the logs, and a Conduit filter that picks addresses out of log
// lines. All of it is data on top of the packs, and all of it only reads.
package security

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	conduit "github.com/CurtisD4q/mint-conduit"
	lookout "github.com/CurtisD4q/mint-lookout"
	"github.com/CurtisD4q/mint-tools/action"
	"github.com/CurtisD4q/mint-tools/words"
)

const probeTimeout = 20 * time.Second

func probe(cmds ...action.Command) action.Pipeline {
	for i := range cmds {
		cmds[i].Timeout = probeTimeout
	}
	return action.Pipeline(cmds)
}

// sshLog is the ssh server's log for the last day, as plain messages.
var sshLog = []string{"journalctl", "-u", "ssh", "-u", "sshd", "--since", "-24h", "--no-pager", "-o", "cat"}

// failedLogin matches the lines ssh writes for a failed or unknown login.
const failedLogin = "Failed password|Invalid user|authentication failure"

// Checks are Cairn's security checks for Lookout.
func Checks() []lookout.Check {
	return []lookout.Check{
		{ID: "failed-logins", Title: "Failed logins", Plain: "How many times someone failed to log in over ssh in the last day.",
			Probe: func(lookout.Params) action.Pipeline {
				return probe(action.Command{Argv: sshLog}, action.Command{Argv: []string{"grep", "-E", "-c", "--", failedLogin}, OKExits: []int{1}})
			},
			Judge: judgeFailedLogins},
		{ID: "root-accounts", Title: "Accounts with full power", Plain: "Accounts other than root that have root's power (user number 0). There should be none.",
			Probe: func(lookout.Params) action.Pipeline {
				return probe(action.Command{Argv: []string{"getent", "passwd"}}, action.Command{Argv: []string{"awk", "-F:", "$3 == 0 {print $1}"}})
			},
			Judge: judgeRootAccounts},
		{ID: "new-keys", Title: "Login keys changed lately", Plain: "authorized_keys files changed in the last week: each one lets someone log in without a password.",
			Probe: func(lookout.Params) action.Pipeline {
				return probe(action.Command{Argv: []string{"find", "/root/.ssh", "/home", "-maxdepth", "3", "-name", "authorized_keys", "-mtime", "-7", "-printf", `%TY-%Tm-%Td %p\n`}, OKExits: []int{1}})
			},
			Judge: judgeNewKeys},
		{ID: "sudo-use", Title: "Administrator commands", Plain: "Commands run with sudo in the last day.",
			Probe: func(lookout.Params) action.Pipeline {
				return probe(action.Command{Argv: []string{"journalctl", "_COMM=sudo", "--since", "-24h", "--no-pager", "-o", "cat"}})
			},
			Judge: judgeSudo},
		{ID: "open-to-all", Title: "Open to every network", Plain: "Programs listening on every network this machine is on, not just on itself.",
			Probe: func(lookout.Params) action.Pipeline {
				return probe(action.Command{Argv: []string{"ss", "-H", "-l", "-t", "-n"}})
			},
			Judge: judgeOpenToAll},
	}
}

// Symptoms are Cairn's security symptoms for Lookout.
func Symptoms() []lookout.Symptom {
	return []lookout.Symptom{
		{ID: "intrusion", Title: "I think someone got in", Plain: "Looks at failed logins, accounts with full power, recently changed login keys, administrator commands and recent errors.",
			Checks: []string{"failed-logins", "root-accounts", "new-keys", "sudo-use", "recent-errors"}},
		{ID: "exposed", Title: "What can others reach here?", Plain: "Looks at what is open to every network, and who has been trying to log in.",
			Checks: []string{"open-to-all", "failed-logins", "listening"}},
	}
}

// Add puts Cairn's checks and symptoms into a Lookout, symptoms first.
func Add(l *lookout.Lookout) {
	l.Checks = append(l.Checks, Checks()...)
	l.Symptoms = append(Symptoms(), l.Symptoms...)
}

// journalDirs are where systemd keeps the journal; tests replace it.
var journalDirs = []string{"/var/log/journal", "/run/log/journal"}

// noJournal says why the logs cannot be read, or "". journalctl with a
// unit filter prints nothing at all when there is no journal, which looks
// the same as "nothing happened", so the journal's folders are looked at
// too: no news is only good news when there is a journal to have news in.
func noJournal(r action.Result) string {
	t := string(r.Stdout) + string(r.Stderr)
	switch {
	case r.Err != nil:
		return r.Err.Error()
	case strings.Contains(t, "No journal files were found"):
		return "This system keeps no journal, so there are no logs to read here."
	}
	for _, d := range journalDirs {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			return ""
		}
	}
	return "This system keeps no journal, so there are no logs to read here."
}

func judgeFailedLogins(r action.Result, _ lookout.Params) lookout.Finding {
	if why := noJournal(r); why != "" {
		return lookout.Finding{Status: lookout.Unknown, Summary: why}
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(r.Stdout)))
	if err != nil {
		return lookout.Finding{Status: lookout.Unknown, Summary: "Could not count failed logins."}
	}
	switch {
	case n == 0:
		return lookout.Finding{Status: lookout.OK, Summary: "No failed logins in the last day."}
	case n < 50:
		return lookout.Finding{Status: lookout.Warn, Summary: fmt.Sprintf("%d failed login%s in the last day.", n, plural(n)),
			Next: "Hunt in the logs (Failed logins by address) to see who is trying."}
	}
	return lookout.Finding{Status: lookout.Bad, Summary: fmt.Sprintf("%d failed logins in the last day: someone is guessing passwords.", n),
		Next: "Hunt in the logs (Failed logins by address) to see who; then, in Harden this machine, turn off password logins and allow ssh only from where you need it."}
}

func judgeRootAccounts(r action.Result, _ lookout.Params) lookout.Finding {
	if !r.OK() {
		return lookout.Finding{Status: lookout.Unknown, Summary: "Could not read the accounts."}
	}
	var others []string
	for _, n := range strings.Fields(string(r.Stdout)) {
		if n != "root" {
			others = append(others, n)
		}
	}
	if len(others) == 0 {
		return lookout.Finding{Status: lookout.OK, Summary: "Only root has full power."}
	}
	return lookout.Finding{Status: lookout.Bad, Summary: "These accounts have root's power: " + strings.Join(others, ", ") + ".", Details: others,
		Next: "An extra account with user number 0 is a common back door. Find out who made it; if no one can say, lock it in Harden this machine."}
}

func judgeNewKeys(r action.Result, _ lookout.Params) lookout.Finding {
	if r.Err != nil {
		return lookout.Finding{Status: lookout.Unknown, Summary: r.Err.Error()}
	}
	var ls []string
	for _, l := range strings.Split(strings.TrimSpace(string(r.Stdout)), "\n") {
		if l != "" {
			ls = append(ls, l)
		}
	}
	if len(ls) == 0 {
		return lookout.Finding{Status: lookout.OK, Summary: "No login keys changed in the last week."}
	}
	return lookout.Finding{Status: lookout.Warn, Summary: fmt.Sprintf("%d login key file%s changed in the last week.", len(ls), plural(len(ls))), Details: ls,
		Next: "Check each one with its owner: an added key lets someone log in without a password."}
}

var sudoCommand = regexp.MustCompile(`COMMAND=(.*)$`)

func judgeSudo(r action.Result, _ lookout.Params) lookout.Finding {
	if why := noJournal(r); why != "" {
		return lookout.Finding{Status: lookout.Unknown, Summary: why}
	}
	var cmds []string
	for _, l := range strings.Split(string(r.Stdout), "\n") {
		if m := sudoCommand.FindStringSubmatch(l); m != nil {
			who := strings.TrimSpace(strings.SplitN(l, ":", 2)[0])
			cmds = append(cmds, who+": "+m[1])
		}
	}
	if len(cmds) == 0 {
		return lookout.Finding{Status: lookout.OK, Summary: "No administrator commands in the last day."}
	}
	start := 0
	if len(cmds) > 10 {
		start = len(cmds) - 10
	}
	return lookout.Finding{Status: lookout.OK, Summary: fmt.Sprintf("%d administrator command%s in the last day.", len(cmds), plural(len(cmds))), Details: cmds[start:],
		Next: "Read them: anything you did not expect is worth asking about."}
}

func judgeOpenToAll(r action.Result, _ lookout.Params) lookout.Finding {
	if !r.OK() {
		return lookout.Finding{Status: lookout.Unknown, Summary: "Could not read the open ports."}
	}
	var open []string
	for _, l := range strings.Split(string(r.Stdout), "\n") {
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		local := f[3]
		if strings.HasPrefix(local, "0.0.0.0:") || strings.HasPrefix(local, "[::]:") || strings.HasPrefix(local, "*:") {
			open = append(open, local)
		}
	}
	if len(open) == 0 {
		return lookout.Finding{Status: lookout.OK, Summary: "Nothing is open to every network; programs listen only on this machine or chosen addresses."}
	}
	f := lookout.Finding{Status: lookout.OK, Summary: fmt.Sprintf("%d port%s open to every network: %s.", len(open), plural(len(open)), strings.Join(open, ", ")), Details: open}
	for _, o := range open {
		if !strings.HasSuffix(o, ":22") {
			f.Status = lookout.Warn
			f.Next = "Each of these can be reached by anything that can reach this machine. Close what is not needed, or allow it only from where it is used (Harden this machine, Firewall)."
		}
	}
	return f
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// AddressesFilter is a Conduit step that keeps only the IPv4 addresses in
// each line, one per line.
var AddressesFilter = conduit.Filter{ID: "addresses", Label: "Pick out addresses", Plain: "Keeps only the IP addresses in each line, one per line.",
	Build: func(words.Values) ([]action.Command, error) {
		return []action.Command{{Argv: []string{"grep", "-E", "-o", "--", `([0-9]{1,3}\.){3}[0-9]{1,3}`}, OKExits: []int{1}}}, nil
	}}

// Sources are the logs Cairn's hunts start from.
var Sources = []conduit.SourceProgram{
	{Label: "The ssh log (last day)", Argv: sshLog, Plain: "Every message from the ssh server in the last day."},
	{Label: "Administrator commands (last day)", Argv: []string{"journalctl", "_COMM=sudo", "--since", "-24h", "--no-pager", "-o", "cat"}, Plain: "Every sudo command in the last day."},
}

// Add puts Cairn's filter and sources into a Conduit.
func AddHunting(c *conduit.Conduit) {
	c.Filters = append(c.Filters, AddressesFilter)
	c.Sources = append(Sources, c.Sources...)
}

// Hunt is a ready-made chain for a question a person asks of the logs.
type Hunt struct {
	Title, Plain string
	Chain        conduit.Chain
}

// Hunts are Cairn's ready-made hunts.
func Hunts() []Hunt {
	return []Hunt{
		{Title: "Failed logins by address", Plain: "Who has been trying to log in over ssh, most attempts first.",
			Chain: conduit.Chain{Name: "failed-logins", Source: conduit.Source{Program: sshLog}, Stages: []conduit.Stage{
				{Filter: "keep", Values: words.Values{"pattern": failedLogin, "icase": "off"}},
				{Filter: "addresses"},
				{Filter: "tally"},
			}}},
		{Title: "Who logged in", Plain: "Addresses that logged in over ssh successfully, most logins first.",
			Chain: conduit.Chain{Name: "logins", Source: conduit.Source{Program: sshLog}, Stages: []conduit.Stage{
				{Filter: "keep", Values: words.Values{"pattern": "Accepted (password|publickey)", "icase": "off"}},
				{Filter: "addresses"},
				{Filter: "tally"},
			}}},
		{Title: "Administrator commands", Plain: "What was run with sudo in the last day, most often first.",
			Chain: conduit.Chain{Name: "sudo", Source: conduit.Source{Program: Sources[1].Argv}, Stages: []conduit.Stage{
				{Filter: "keep", Values: words.Values{"pattern": "COMMAND="}},
				{Filter: "replace", Values: words.Values{"find": "^.*COMMAND=", "with": ""}},
				{Filter: "tally"},
			}}},
	}
}

// HuntFor is a chain that finds every line mentioning text in the system
// log since it started.
func HuntFor(text string) conduit.Chain {
	return conduit.Chain{Name: "hunt", Source: conduit.Source{Program: conduit.BuiltinSources()[0].Argv}, Stages: []conduit.Stage{
		{Filter: "keep", Values: words.Values{"pattern": regexp.QuoteMeta(text)}},
	}}
}
