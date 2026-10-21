# CyberPi — implementation plan

## 1. What CyberPi is

CyberPi is a **Pi package** that turns the Pi coding agent into a Kali Linux
security engagement harness. It does not fork Pi: it extends it with the
extension, skill, prompt and theme resource types that Pi already supports, so
it can be installed with `pi install` and updated with `pi update`.

Three layers:

1. **Tools** (`extensions/tools/`) — model-callable wrappers around the Kali
   toolchain. They are the only way CyberPi touches the network, which makes
   every action auditable, scope-checked and journalled.
2. **Skills** (`skills/`) — Agent Skills that teach the model the workflows:
   recon, enumeration, exploitation, credential attacks, AD, wireless, IoT,
   reporting. Pi loads a skill only when the task needs it, which keeps the
   context small and the response fast.
3. **CVE intelligence** (`tools/cvedb/`) — a local SQLite mirror of the NVD,
   CISA KEV and FIRST EPSS, queried offline in milliseconds.

## 2. Design decisions

### 2.1 Authorization scope, not "attack anything"

The brief asks for an uncensored harness that can attack any device. CyberPi
implements the professional equivalent: **the agent executes whatever it is
asked to, with no artificial refusals, but every action is checked against an
engagement scope file** that the operator writes down.

Why this is better than the alternative:

- A pentest report is only defensible if there is a written authorization.
  Scope enforcement produces that record automatically.
- A scope file is a *configuration*, not a policy engine. The operator can
  authorize a `/0` CIDR if that is genuinely the engagement.
- The refusal is specific and actionable ("target 10.2.3.4 is not in the
  authorized scope of engagement acme-web-2025-03"), so it never blocks the
  work — it routes it back to the operator.

Scope enforcement fails closed: with no `scope.json`, nothing but the local
machine (self-test) is reachable.

### 2.2 Kali-only enforcement

`extensions/lib/platform.ts` refuses to run on Windows and macOS. On Linux
that is not Kali, it warns and continues unless `CYBERPI_STRICT_KALI=1` is
set. `bin/cyberpi` performs the same check before starting Pi, so the user
gets a clear message instead of a stack trace from a missing binary.

### 2.3 Speed

- **Parallel execution.** A single tool call can run several commands at once
  (`runMany`); nmap, nuclei and httpx sweeps run concurrently.
- **Caching.** Identical calls hit `extensions/lib/cache.ts` and return in
  milliseconds instead of re-scanning (`cacheTtlMs` per tool).
- **Surface index.** Reconnaissance merges into `surface.json`, so questions
  about the target are answered by reading a small file rather than by
  re-running scanners.
- **Structured output.** Tools parse `-json` output and summarise, keeping the
  transcript small and the model informed.
- **Lazy skills.** Pi advertises a skill by name and description; the body is
  read only when the task calls for it.

### 2.4 Aesthetic continuity

CyberPi ships a `cyber` theme (OKHSL palette, cyan accent on near-black,
severity-coloured tool output) and a status line that shows the engagement
name, the number of hosts and services in the index, and the current phase.
The dashboard `/cyber` command renders the same palette, so the harness feels
like Pi with a different skin rather than a different application.

## 3. Repository layout

```
CyberPi/
├── package.json            # pi-package manifest + peer dependencies
├── tsconfig.json
├── install.sh              # Kali installer
├── uninstall.sh
├── bin/
│   ├── cyberpi             # launcher: checks the platform, starts Pi
│   ├── cyberpi-doctor      # environment and toolchain diagnostics
│   └── cyberpi-report      # renders the report outside the agent
├── extensions/
│   ├── index.ts            # registers every tool, command and handler
│   ├── dashboard.ts        # /cyber dashboard and status line
│   ├── context.ts          # injects engagement state into the prompt
│   ├── lib/                # shared helpers (see TOOL-REGISTRY.md)
│   └── tools/              # 35 tools in 12 groups
├── skills/                 # 17 Agent Skills
├── prompts/                # 12 slash-command prompt templates
├── themes/cyber.json       # the CyberPi theme
├── tools/cvedb/cvedb.py    # offline CVE database
├── tests/                  # node:test suites for the pure logic
└── docs/                   # this plan, registry, install, usage, troubleshooting
```

## 4. Dependencies

**Host provided by Pi** (declared as `peerDependencies`, never bundled):
`@earendil-works/pi-coding-agent`, `@earendil-works/pi-ai`,
`@earendil-works/pi-agent-core`, `@earendil-works/pi-tui`, `typebox`.

**Node runtime**: Pi requires Node 22.19 or newer. CyberPi uses only Node
built-ins (`node:child_process`, `node:fs`, `node:path`, `node:os`).

**Python**: 3.11+ with the standard library only. The CVE database needs no
third-party packages.

**Kali toolchain** (installed by `install.sh`, grouped by size):

| Group | Packages |
|---|---|
| Core | nmap, naabu, httpx, katana, ffuf, nuclei, dnsutils, whois, iproute2, net-tools |
| Web | sqlmap, dalfox, nikto, gobuster, wafw00f, sslscan, testssl.sh, feroxbuster |
| Credentials | hashcat, john, hydra, trufflehog |
| Exploitation | metasploit-framework, searchsploit (exploitdb), msfvenom |
| Active Directory | impacket-scripts, responder, bloodhound, ldapdomaindump |
| Wireless | aircrack-ng, wifite, hcxtools, bettercap |
| Hardware / IoT | binwalk, radare2, hidrd, python3-serial, cutter |
| Networking | tcpdump, tshark, wireshark, chisel, proxychains4, socat |
| Cloud | awscli, azure-cli, google-cloud-cli |

Heavyweight groups (`metasploit-framework`, `bloodhound`, `tshark`) are opt-in
via installer flags so a first install stays fast.

## 5. Implementation order

1. **Foundation** — package manifest, TypeScript config, shared library
   (`config`, `platform`, `scope`, `exec`, `journal`, `findings`, `surface`,
   `cache`, `toolkit`). Everything else depends on these contracts.
2. **Tools** — 12 group files implementing 35 tools against the shared
   toolkit. Each tool is scope-checked, journalled and cached.
3. **CVE database** — `cvedb.py` (NVD + KEV + EPSS into SQLite) and the
   `cyber_cve_*` tools that query it.
4. **Skills** — 17 skills covering the engagement workflow, each with
   `SKILL.md` plus references where the detail belongs.
5. **Shell** — `index.ts` wiring, the engagement context injection, the
   dashboard, the theme, the prompt templates.
6. **Packaging** — `install.sh`, `bin/cyberpi`, `bin/cyberpi-doctor`,
   `bin/cyberpi-report`, the scope template, the wordlist bootstrap.
7. **Verification** — `tsc --noEmit`, the `node --test` suite, a smoke test
   that loads the extension runtime, and a documentation pass.

## 6. Verification

| Check | Command |
|---|---|
| Types | `npm run typecheck` |
| Unit and behaviour tests | `npm test` |
| Resource load (skills, prompts, theme, extension) | `npm run verify` |
| Everything | `npm run check` |
| Toolchain | `bin/cyberpi-doctor` |
| Engine | `bin/cyberpi --check` |
| Package load | `pi -e ./CyberPi` then `/cyber` |

The unit suite covers the authorization engine (CIDR, wildcard, port and
technique filters, fail-closed behaviour), the journal, the findings parser
and the target parser. These are the parts where a silent bug would be
dangerous. The behaviour suite drives the real tool definitions: an
out-of-scope target is refused and journalled, a technique outside the
allowlist is refused, a finding is written to disk and the report is built
from it. `npm run verify` loads the package with Pi's own resource loader, so
a malformed skill or theme fails the check rather than being silently skipped
at startup.

## 7. Use

```bash
# Install on Kali
curl -fsSL https://raw.githubusercontent.com/<org>/CyberPi/main/install.sh | sudo bash

# Create an engagement
cyberpi new acme-web-2025-03
cd acme-web-2025-03

# Edit the scope
nano .cyberpi/scope.json

# Run the harness
cyberpi
```

Inside Pi:

```
/cyber                    # dashboard: scope, surface, findings, journal
/recon example.com        # passive and active reconnaissance
/scan 10.0.0.0/24         # service enumeration
/exploit CVE-2021-44228   # find and validate exploits for a CVE
/report                   # build the deliverable
```

## 8. Troubleshooting

See `docs/TROUBLESHOOTING.md`. The common cases are a missing Kali package
(`cyberpi-doctor` names it), a stale CVE database (`cyber_cve_sync`), a scope
refusal (add the target to `scope.json`), a missing monitor mode for wireless
work, and a non-Kali host (`CYBERPI_STRICT_KALI=1` forces the refusal).
