# Cairn

A terminal workbench for security work. Keep a **case**, say what you are **allowed to test**, run the everyday tools from one place, and **send what one finds to the next**, so you stop retyping targets and hopping between windows.

Built on [Mint-Interfaces](https://github.com/CurtisD4q/mint-interfaces) (the terminal UI library), with its own look and layout. It runs in any modern terminal and inside Emacs.

```
╭─ ◈ Workbench ─────────────────────────────────────────────────── Cairn ─╮
│ ▸ Case                    │ ┄ Tools                    │ ┄ Recent       │
│   Name           default  │ ┄ Discover                 │ 18:47 ping     │
│   Scope          2 rules  │   Port scan          nmap   │   127.0.0.1    │
│   Target       10.20.0.5  │   Trace the route  tracer…  │ 18:48 nmap     │
│ ┄ Targets                 │ ┄ Reach                    │   127.0.0.1    │
│   ● 10.20.0.5   address   │   Is it up?          ping   │                │
╰──────────────────────────────────────────────────────────────────────────╯
```

## What it does

- **One case, one target.** Type a target once. Every tool starts with it, in the form that tool needs (an address for `ping`, a web address for `curl`).
- **Scope first.** List the networks, addresses and domains you may test. Before any tool that sends traffic runs, Cairn checks the target against that list. No scope set: it asks. Outside it: you must type the target out to go ahead, and the override is recorded.
- **Send results on.** Select a row in a result (an open port, an IP in a trace, a name server) and open it in another tool, add it to the case, or copy it.
- **Plain words, exact command.** Each tool explains itself beside its controls, and each choice says what it does. The exact command is always shown, so you can see and learn what is being run.
- **Audit log and report.** Every command is logged with its time, target and scope result. Save the case as a Markdown report.

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

## Install

Cairn needs Go 1.21 or newer. It depends on the Mint-Interfaces library, which is a private repository, so tell Go to fetch it directly:

```
git clone https://github.com/CurtisD4q/cairn
cd cairn
export GOPRIVATE='github.com/CurtisD4q/*'
go mod tidy          # first time only: fetches Mint-Interfaces and writes go.sum
go build -o cairn ./cmd/cairn
./cairn
```

Git must be able to read the Mint-Interfaces repository (an SSH key or `gh auth login`). Put the binary anywhere on your `PATH`.

## Using it

Open **Case** and add your scope, for example `10.0.0.0/24` or `example.com` (a domain covers its subdomains; `*.lab.test` covers only the subdomains). On the **Workbench**, type a target, pick a tool, and choose **Run**. In the results, select a row to send it on. **How this works** in the app is a one-page guide.

Keys: arrows move, Enter opens or changes, Tab moves between panes, `b` goes back, `q` quits; the mouse works. `MINT_KEYS=emacs` or `vim` adds those key styles. Colours follow the Mint theme screen, or `MINT_PALETTE`.

## In Emacs

`emacs/cairn.el` adds `M-x cairn`. If [mint.el](https://github.com/CurtisD4q/mint-interfaces/tree/main/emacs) is installed, Cairn is started with it (handover in terminal Emacs, Emacs keys, your theme's colours). Otherwise it runs in a `term` buffer. `M-x cairn-cases` opens the folder of cases and saved reports in Dired.

```elisp
(add-to-list 'load-path "/path/to/cairn/emacs")
(require 'cairn)
```

## Where things are kept

Cases, audit logs and reports are in `~/.local/share/cairn/cases/` (or `$CAIRN_HOME`), private to you (folders `0700`, files `0600`). Cairn sends nothing anywhere itself; the tools talk to the targets you point them at, and `dig` and `whois` ask public servers.

## Safety, and what it does not do

- Programs are run directly, never through a shell. Targets are checked, and anything that could be taken for an option (a leading `-`) is refused; every command puts the target after `--`.
- The scope check judges text only. It does not resolve names, so a domain cannot be matched against an address range; use the address, or add the domain.
- Cairn helps you stay within your permission. It does not give you any. Only test what you are authorised to test.

## Accessibility: where it stands

Built in: every option explained in plain words, the exact command always on screen, state always written out (never colour alone), consistent screens, keyboard and mouse, Emacs and vim key styles, and fallbacks for terminals without colour or Unicode.

Not yet done: it has **not been tested with a screen reader or braille display**, and has **not been tested with people who have learning disabilities**. A full-screen terminal interface that redraws in place is hard for screen readers; a plain, append-only mode is the planned answer. Treat the above as groundwork, not a claim.

## Development

```
go work init . ../mint-interfaces   # to build against a local checkout; go.work is git-ignored
go vet ./... && go test ./...
emacs --batch -L emacs -l emacs/cairn-tests.el -f ert-run-tests-batch-and-exit
```

Tests include live runs of `ss`, `curl`, `ping`, `traceroute` and `nmap` against this computer only; they skip any program that is not installed.

## Licence

Apache-2.0, as Mint-Interfaces.
