# cairn

A terminal workbench for security work. Keep a **case**, say what you are **allowed to test**, run the everyday tools from one place, and **send what one finds to the next**, so you stop retyping targets and hopping between windows.

Built with [pmin](https://github.com/CurtisD4q/pmin): the screens are [pmin-kit](https://github.com/CurtisD4q/pmin-kit), with its own look and layout. It runs in any modern terminal and inside Emacs.

![The workbench: the case, the tools grouped by what they do, and recent runs](screenshots/workbench.png)

## Screenshots

| | |
|---|---|
| ![A tool's screen: its options in plain words, the exact command, and what came back as a table](screenshots/results.png) | ![Send to: a port found by one tool opened in another, saved as a machine, hunted for in the logs or added to the case](screenshots/sendto.png) |
| **Run a tool.** Its options in plain words, the exact command, and what came back as a table. | **Send it on.** Anything a tool finds goes straight into the next tool, the logs, the machines list or the case. |
| ![Something's wrong: five read-only checks for signs of intrusion, problems first](screenshots/intrusion.png) | ![Hunt in the logs: a ready-made chain of filters, with the command it makes](screenshots/hunt.png) |
| **Something's wrong.** Start from what you notice; read-only checks list what they found, problems first. | **Hunt in the logs.** A chain of filters, one step at a time, with the exact command it makes. |
| ![Programs: any program by name, or from drop-down groups, with Act on targets open](screenshots/programs.png) | ![nmap opened inside cairn: its options, targets, output and Run in panes, with the case's scope above](screenshots/inside.png) |
| **Programs.** Open any program by name, or choose from drop-down groups. | **Any program, in the Mint layout.** nmap inside cairn: options, targets, output and Run, with the case's scope above. |
| ![A run at a target outside the scope is refused, and nothing is sent](screenshots/refused.png) | ![The audit log: the refused run and the run in scope, with the exact commands](screenshots/auditlog.png) |
| **Held to the scope.** A run at a target outside the case's scope is refused before anything is sent. | **Everything logged.** Every run, and every refusal, with the exact command. |

## What it does

- **One case, one target.** Type a target once. Every tool starts with it, in the form that tool needs (an address for `ping`, a web address for `curl`).
- **Scope first.** List the networks, addresses and domains you may test. Before any tool that sends traffic runs, cairn checks the target against that list. No scope set: it asks. Outside it: you must type the target out to go ahead, and the override is recorded.
- **Send results on.** Select a row in a result (an open port, an IP in a trace, a name server) and open it in another tool, hunt for it in the logs, save it as a machine, add it to the case, or copy it.
- **Look for signs of intrusion.** *Something's wrong* starts from what you notice ("I think someone got in", "What can others reach here?") and runs read-only checks: failed logins, accounts with root's power, login keys changed lately, administrator commands, what is open to every network.
- **Hunt in the logs.** Ready-made hunts (failed logins by address, who logged in, administrator commands) narrow the logs down step by step, showing what each step keeps and the command it makes.
- **Keep the machines.** Save machines from results, check their host keys, connect with ssh, open tunnels.
- **Harden this machine.** Accounts, permissions, the firewall and ssh settings, read-only until you choose Apply; a change that could cut off your own connection is refused or put back on its own unless you confirm you can still get in.
- **Any program, in the Mint layout.** *Programs* opens any command-line program inside cairn: its options, the exact command, Run and what came back, in panes. Programs that reach other machines are held to the case's scope on every run, and every run goes in the audit log.
- **Plain words, exact command.** Everything explains itself, and the exact command is always shown, so you can see and learn what is being run.
- **One audit log and a report.** Everything done in the case, by every part of cairn, is logged with its time, target and whether it was in scope or agreed to. Save the case as a Markdown report.

## Built with pmin

cairn is a program built with pmin (tier `example` in `pmin.json`). It uses the pmin foundation, four function modules and two engines, and no other program:

| Part of cairn | Module | What cairn adds |
|---|---|---|
| Something's wrong, Health | [pmin-lookout](https://github.com/CurtisD4q/pmin-lookout) | Five security checks and two symptoms, as data |
| Hunt in the logs | [pmin-conduit](https://github.com/CurtisD4q/pmin-conduit) | The ssh and sudo logs as sources, a "Pick out addresses" step, and three ready-made hunts |
| Machines, Your keys | [pmin-bridge](https://github.com/CurtisD4q/pmin-bridge) | Saving a result as a machine, checked against the case's scope |
| Harden this machine | [pmin-warden](https://github.com/CurtisD4q/pmin-warden) | Its lockout guard, served by cairn itself |
| Programs | [pmin-wrap](https://github.com/CurtisD4q/pmin-wrap) | Any program in the Mint layout, held to the case's scope |

The modules never import an engine, so cairn plugs them in itself (`plug` in `internal/ui/packs.go`): Warden reads and changes the firewall with [pmin-netfilter](https://github.com/CurtisD4q/pmin-netfilter), and Bridge opens serial consoles with [pmin-serial](https://github.com/CurtisD4q/pmin-serial).

Every module writes into the open case's audit log. The screens come from pmin-kit; the checks, values, wording and scope rules from pmin-base and pmin-tools.

## Tools in this version

| Tool | Program | For |
|---|---|---|
| Port scan | `nmap` | which ports are open, and what is behind them |
| Trace the route | `traceroute` | the path to a host |
| Is it up? | `ping` | whether a host answers, and how fast |
| Web headers | `curl` | what a web server says about itself, redirects, HSTS |
| Name records | `dig` | A, AAAA, MX, NS, TXT, CNAME, SOA, and reverse lookups |
| Who owns it | `whois` | registrar, dates, name servers, network owner |
| Open ports here | `ss` | what this computer is listening on |

Tools that are not installed are listed as such, with the package name for Debian and Ubuntu.

## Programs

*Programs* opens any command-line program inside cairn, in the Mint layout: its options in panes, the exact command, Run, and what came back, the way [pmin-wrap](https://github.com/CurtisD4q/pmin-wrap) shows it, in cairn's own frame.

![nmap opened inside cairn: its options, targets, output and Run in panes, with the case's scope above](screenshots/inside.png)

- **Open a program…** takes any program's name. It is checked in the background first: programs that draw their own screen (vim, less), parts of the shell (cd) and programs with windows are not opened, and you are told why. Programs opened this way are kept in the list (in `programs/` beside the cases).
- The list also shows the programs mint-wr keeps (its *Your programs*) and the standalone copies it makes (`mint-wr --make nmap` puts `nmap-mint` in `~/.local/bin`), in drop-down groups by what they do. Choose one, then the screen it starts at.
- **Scope.** For a program that reaches other machines (nmap, curl, ssh, rsync, dig… and anything in the *Act on targets* group), every command it is about to run is checked: each address, network, name or web address in it must be in the case's scope, or the command is refused and nothing is sent. With no scope set, commands at a target are refused until you set one.
- **Audit log.** Every command a program runs, and every refusal, goes in the case's audit log with the exact command.
- Settings typed into a program stay while cairn runs, so it opens as you left it; secrets typed into one are wiped when cairn closes.

cairn looks for Mint programs in `~/.local/bin/mint-interfaces`, `~/.local/bin`, `/usr/local/bin` and, when `MINT_INTERFACES_DIR` is set, that checkout's `apps` folder; set `MINT_APP_DIRS` to a `:`-separated list of folders to look there instead. Only executable files whose names end in `-mint` are asked what they are. An app built with `mint-g --build` carries no description cairn can read, so it opens on its own as before, and its runs are logged as *handed over (not checked)*.

## Install

Download, check and install the latest release in one go (Linux and macOS):

```
gh api repos/CurtisD4q/cairn/contents/install.sh -H 'Accept: application/vnd.github.raw' | sh
```

cairn's repository is public, so `curl -fsSL https://raw.githubusercontent.com/CurtisD4q/cairn/main/install.sh | sh` works too. The first way needs the [GitHub CLI](https://cli.github.com), logged in (`gh auth login`). Add `-s -- --system` after `sh` to install for everyone in `/usr/local`.

Or by hand: download the archive for your machine from Releases, check it against `SHA256SUMS`, unpack it and run `./cairn install`. Either way cairn ends up in `~/.local/bin`, with `cairn.el` for Emacs beside its data, and the download can be deleted.

To remove it: `cairn uninstall`. Your settings and data are kept.

### Build from source

Needs Go and access to the private pmin libraries:

```
git clone https://github.com/CurtisD4q/cairn
cd cairn
export GOPRIVATE='github.com/CurtisD4q/*'
make install        # builds, then installs into ~/.local/bin
```

After `make install` the cloned folder can be deleted. To clone and fetch the libraries over SSH instead of HTTPS, tell git once: `git config --global url."git@github.com:".insteadOf "https://github.com/"`, and clone `git@github.com:CurtisD4q/cairn.git`.

## Using it

Open **Case** and add your scope, for example `10.0.0.0/24` or `example.com` (a domain covers its subdomains; `*.lab.test` covers only the subdomains). On the **Workbench**, type a target, pick a tool, and choose **Run**. In the results, select a row to send it on. **How this works** in the app is a one-page guide.

Keys: arrows move, Enter opens or changes, Tab moves between panes, `b` goes back, `q` quits; the mouse works. `MINT_KEYS=emacs` or `vim` adds those key styles. Colours follow the Mint theme screen, or `MINT_PALETTE`.

## In Emacs

`emacs/cairn.el` adds `M-x cairn`. If [mint.el](https://github.com/CurtisD4q/mint-interfaces/tree/main/emacs) is installed, cairn is started with it (handover in terminal Emacs, Emacs keys, your theme's colours). Otherwise it runs in a `term` buffer. `M-x cairn-cases` opens the folder of cases and saved reports in Dired.

```elisp
(add-to-list 'load-path "/path/to/cairn/emacs")
(require 'cairn)
```

## Where things are kept

Cases, audit logs and reports are in `~/.local/share/cairn/cases/` (or `$CAIRN_HOME`), private to you (folders `0700`, files `0600`). cairn sends nothing anywhere itself; the tools talk to the targets you point them at, and `dig` and `whois` ask public servers.

## Safety, and what it does not do

- Programs are run directly, never through a shell. Targets are checked, and anything that could be taken for an option (a leading `-`) is refused; every command puts the target after `--`.
- The scope check judges text only. It does not resolve names, so a domain cannot be matched against an address range; use the address, or add the domain.
- cairn helps you stay within your permission. It does not give you any. Only test what you are authorised to test.

## Not tested here

ufw, systemd actions and a live ssh server were not available on the machine cairn was built on, so those paths are tested against saved output only. Each pack's README says the same for its part.

## Accessibility: where it stands

Built in: every option explained in plain words, the exact command always on screen, state always written out (never colour alone), consistent screens, keyboard and mouse, Emacs and vim key styles, and fallbacks for terminals without colour or Unicode.

Not yet done: it has **not been tested with a screen reader or braille display**, and has **not been tested with people who have learning disabilities**. A full-screen terminal interface that redraws in place is hard for screen readers; a plain, append-only mode is the planned answer. Treat the above as groundwork, not a claim.

## Development

```
go work init . ../pmin-kit   # to build against a local checkout; go.work is git-ignored
go vet ./... && go test ./...
emacs --batch -L emacs -l emacs/cairn-tests.el -f ert-run-tests-batch-and-exit
```

Tests include live runs of `ss`, `curl`, `ping`, `traceroute` and `nmap` against this computer only; they skip any program that is not installed.

## Licence

Apache-2.0, as pmin-kit.
