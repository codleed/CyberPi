# CyberPi

**A Kali Linux security engagement harness that turns the [Pi coding agent](https://github.com/earendil-works/pi) into a pen-testing operator.**

CyberPi is a Pi package. It does not fork Pi, and it does not replace it: it adds
the extension, skill, prompt and theme resource types that Pi already knows how
to load, so it installs with `pi install`, updates with `pi update`, and feels
like Pi with a different skin.

The result is an agent that can run a full engagement — recon, enumeration,
vulnerability assessment, exploitation, credential attacks, Active Directory,
wireless, IoT, cloud and reporting — from a single conversational session,
using the tools that are already installed on your Kali box.

---

## Why it exists

Running a pentest with a generic chat agent is painful for three reasons, and
CyberPi exists to remove all three.

**The agent does not know your tools.** A generic model can describe a SQL
injection, but it cannot run sqlmap against your target, read the JSON output
and adapt. CyberPi wraps the Kali toolchain in typed, model-callable tools, so
the agent can act instead of advising.

**The agent does not know what is authorized.** A pentest report is only
defensible if there is a written authorization behind it. CyberPi puts that
authorization in a file — `.cyberpi/scope.json` — and checks every network
action against it before the action runs. The scope is configuration, not
policy: you can authorize a `/0` CIDR if that genuinely is the engagement, but
you have to write it down first.

**The agent forgets.** A long engagement accumulates hundreds of facts. CyberPi
merges reconnaissance into a persistent surface index and appends every action
to an append-only journal, so the model answers questions from a small local
file instead of re-running scanners, and the engagement ends with a complete,
defensible record of what was attempted.

The result is a harness that is fast because it caches, journals and summarises
instead of repeating work, and safe because it fails closed when the scope file
is missing.

---

## What it can do

| Area | Capabilities |
|---|---|
| **Recon** | Subdomain discovery, DNS record lookups, WHOIS and registration data, HTTP probing of the live estate, passive packet capture |
| **Enumeration** | Fast SYN port scans, full service and version fingerprinting, web crawling, directory and file brute forcing, endpoint and technology inventory |
| **Vulnerability** | Template-driven scanning with nuclei, SQL injection testing, reflected and DOM XSS detection, CVE lookup against an offline NVD mirror, KEV and EPSS cross-reference |
| **Exploitation** | Exploit database search, Metasploit module execution, proof-of-concept request validation, CVE-to-exploit mapping |
| **Credentials** | Hash type identification, offline hash cracking, password auditing against a service, secret scanning across a code base or a file tree |
| **Active Directory** | LDAP domain enumeration, directory structure dumps, SMB and session review, Kerberos and delegation analysis, relay and abuse tooling from impacket |
| **Wireless** | Network discovery and capture in monitor mode, key recovery, handshake analysis |
| **IoT and hardware** | IoT device and service discovery, firmware extraction and analysis, USB HID descriptor inspection |
| **Cloud** | Cloud storage and bucket enumeration through the provider CLI, cloud asset inventory |
| **Reporting** | Structured finding records, a consolidated engagement report, the action journal, and the live attack-surface index |
| **Infrastructure** | Pivoting tunnels through chisel, proxying and lateral movement support |

---

## The design in one paragraph

CyberPi has three layers. **Tools** (`extensions/tools/`) are the only code that
touches the network, and every one of them is built with a shared wrapper that
checks the engagement scope, verifies the required binaries are installed,
applies a timeout, truncates the output, captures the raw result as an artifact,
consults a result cache and appends a journal entry — so an action either
happens inside the authorization and leaves a record, or it does not happen at
all. **Skills** (`skills/`) teach the model the workflows for each phase of an
engagement; Pi loads a skill only when the task needs it, which keeps the
context small and the response fast. **CVE intelligence** (`tools/cvedb/`) is a
local SQLite mirror of the NVD, the CISA Known Exploited Vulnerabilities
catalog and FIRST EPSS scores, queried offline in milliseconds so vulnerability
research never depends on a third-party API being up.

---

## Requirements

| Requirement | Detail |
|---|---|
| **Operating system** | Kali Linux. Non-Linux is refused outright. Other Linux distributions run in a degraded mode unless `CYBERPI_STRICT_KALI=1` is set. |
| **Node.js** | 22.19.0 or newer (the runtime Pi requires). |
| **Python** | 3.11 or newer, standard library only. Used by the offline CVE database. |
| **Provider key** | An LLM provider key for Pi (for example an Anthropic or OpenAI key), configured through Pi's own provider setup. |
| **Kali toolchain** | The security tools themselves (`nmap`, `httpx`, `nuclei`, `hashcat`, `impacket-scripts`, ...). `install.sh` installs them in groups, and `bin/cyberpi-doctor` tells you exactly what is missing. |

CyberPi itself has no runtime npm dependencies beyond what Pi provides. The
`@earendil-works/*` packages are peer dependencies and are never bundled.

---

## Quick start

```bash
# 1. Install the harness and the Kali toolchain
cd ~/CyberPi
sudo bash install.sh

# 2. Create an engagement directory
cyberpi new acme-web-2025-03 --client "Acme Corp"
cd acme-web-2025-03

# 3. Write down what the client authorized
nano .cyberpi/scope.json

# 4. Start the harness
cyberpi
```

`cyberpi new` creates the directory, the `.cyberpi/` subdirectories and a
commented `scope.json` template. `cyberpi` is a launcher: it checks the
platform, checks the toolchain, and starts Pi with the CyberPi extension,
skills, prompts and theme loaded. From there the engagement is a conversation.

Useful launcher flags:

```bash
cyberpi --engagement ./acme-web-2025-03   # work in a specific engagement directory
cyberpi --print "summarize the engagement" # one-shot run, text output
cyberpi --json                             # one-shot run, JSONL events
```

To use CyberPi inside an existing Pi session instead, install it as a package:

```bash
cd ~                 # the directory that contains the CyberPi checkout
pi install ./CyberPi
```

The installer can also add optional toolchain groups, or leave `apt` alone
entirely when the tools are already present:

```bash
sudo bash install.sh --groups web,creds   # core plus web and credential tooling
sudo bash install.sh --all                # everything, including the heavyweight groups
sudo bash install.sh --skip-apt           # do not touch the package manager
```

Verify the environment at any time:

```bash
cyberpi --check       # runs cyberpi-doctor: platform, Node, Python, toolchain report
cyberpi-doctor        # the same diagnostics on their own
cyberpi-report        # render the engagement report outside the agent
```

### The scope file

The scope file is the authorization. It lives at `<engagement>/.cyberpi/scope.json`
and may contain comments, so you can annotate it while you work:

```jsonc
{
  "engagement": "acme-web-2025-03",
  "client": "Acme Corp",
  "authorization": {
    "statement": "External web application penetration test, TCP/443 and TCP/8443 only.",
    "authorizedBy": "j.doe@acme.example",
    "start": "2025-03-01",
    "end": "2025-03-31"
  },
  "techniques": ["recon", "port-scan", "service-enumeration", "web-testing", "vulnerability-scan"],
  "allowSelfTest": true,
  "rules": [
    // Add the targets the client authorized. Until a rule is present only
    // self-tests against the local machine are allowed.
    {
      "id": "rule-1",
      "target": "app.acme.example",
      "ports": [443, 8443],
      "protocols": ["tcp"],
      "notes": "Authorized by the statement of work dated 2025-03-01."
    },
    {
      "id": "rule-2",
      "target": "10.10.0.0/24",
      "notes": "Internal jump host range."
    }
  ]
}
```

Targets accept IPv4 and IPv6 CIDRs, single hosts, bare domains (host and
subdomains), `*.example.com` (subdomains only) and `exact:example.com` (host
only). Rules may additionally restrict ports, protocols and techniques. A
technique allowlist at the top level applies everywhere in the engagement.

With no scope file, nothing but the local machine is reachable. The harness
fails closed.

---

## A tour of the commands

CyberPi ships twelve slash-command prompt templates in `prompts/`, plus the
`/cyber` dashboard. The five below are the ones you will use most.

| Command | What it does |
|---|---|
| `/cyber` | The dashboard. Renders the engagement name, the active scope, the size of the surface index, the open findings and the journal tail in the CyberPi theme. Also the command to run when you want to know where the engagement stands. |
| `/recon <target>` | A full reconnaissance sweep against the target: subdomain discovery, DNS records, WHOIS and live HTTP service discovery, with every result recorded in the surface index. |
| `/scan <target>` | Port scan the target, enumerate the services behind it and summarise what is exposed. Merges the result into the surface index. |
| `/exploit <cve-or-target>` | Research the vulnerability, find public exploits, assess the risk to the target and prepare a non-destructive proof of concept. |
| `/report [format]` | Builds the deliverable from the recorded findings and the journal, and writes it under `.cyberpi/reports/`. The same report can be rendered outside the agent with `cyberpi-report`. |

The remaining templates cover the other phases of an engagement:

| Command | What it does |
|---|---|
| `/ad [domain]` | Active Directory assessment and privilege-path mapping |
| `/cve [query]` | CVE intelligence for a product, a version or a CVE id, with the exploitability verdict |
| `/harness [topic]` | Explain the harness itself: the tools, the scope, the current engagement |
| `/iot [range]` | Discover IoT devices, check them for default credentials, analyse their firmware |
| `/privesc [focus]` | Enumerate and validate the local privilege escalation surface |
| `/status [detail]` | Summarise the engagement so far: scope, surface, findings by severity, recent journal activity |
| `/webtest [url]` | Test a web application or API and record every confirmed issue as a finding |
| `/wireless [interface]` | Survey the wireless networks around the operator and attempt key recovery on the authorized ones |

Every command takes an optional argument. With no argument it falls back to
the target in the engagement scope, so `/recon` on its own works once the
scope file names a target. Run `/help` inside Pi for the full list of your
installation.

---

## Tools

Thirty-five model-callable tools in twelve groups. The authoritative contract,
including the file each tool lives in, is
[`docs/TOOL-REGISTRY.md`](docs/TOOL-REGISTRY.md).

| Tool | Purpose | Needs |
|---|---|---|
| `cyber_subdomain` | Subdomain discovery | subfinder |
| `cyber_dns` | DNS record lookups | dig |
| `cyber_whois` | Domain registration and nameserver data | whois |
| `cyber_portscan` | Fast SYN port scan | naabu |
| `cyber_service_scan` | Service and version fingerprinting | nmap |
| `cyber_capture` | Packet capture and reassembly | tcpdump |
| `cyber_http_probe` | HTTP probing, status, title and technology fingerprinting | httpx |
| `cyber_crawl` | Web crawling and endpoint discovery | katana |
| `cyber_dir_enum` | Directory, file and parameter brute forcing | ffuf |
| `cyber_vuln_scan` | Template-driven vulnerability scanning | nuclei |
| `cyber_sqli` | SQL injection testing and validation | sqlmap |
| `cyber_xss` | Reflected and DOM XSS detection | dalfox |
| `cyber_exploit_search` | Search the local exploit database | searchsploit |
| `cyber_exploit_run` | Run a Metasploit module in a controlled session | msfconsole |
| `cyber_poc` | Send a proof-of-concept request to validate a hypothesis | curl |
| `cyber_hash_id` | Identify the type of a hash | hashcat |
| `cyber_hash_crack` | Crack a hash offline | hashcat |
| `cyber_password_audit` | Password audit against an authorized service | hydra |
| `cyber_secret_scan` | Secret scanning across files and repositories | trufflehog |
| `cyber_ad_enum` | Active Directory enumeration over LDAP | ldapdomaindump |
| `cyber_ad_attack` | AD relay and abuse tooling | impacket-smbserver |
| `cyber_wireless_scan` | Wireless network discovery in monitor mode | airodump-ng |
| `cyber_wireless_crack` | Wireless key recovery | aircrack-ng |
| `cyber_iot_scan` | IoT device and service discovery | nmap |
| `cyber_firmware_analysis` | Firmware extraction and embedded-file analysis | binwalk |
| `cyber_hid_attack` | USB HID descriptor analysis | hidrd |
| `cyber_pivot` | Pivoting tunnel | chisel |
| `cyber_cloud_enum` | Cloud asset and storage enumeration | aws |
| `cyber_cve_lookup` | Look up a CVE in the offline database | python3 |
| `cyber_cve_sync` | Sync the offline CVE database from NVD, KEV and EPSS | python3 |
| `cyber_exploit_map` | Map a CVE to known public exploits | python3 |
| `cyber_record_finding` | Record a structured finding | - |
| `cyber_report` | Build the engagement report | - |
| `cyber_journal` | Read the action journal | - |
| `cyber_surface` | Read the attack-surface index | - |

Every tool declares a `technique` and the binaries it `requires`, so the shared
wrapper can gate it correctly and tell you exactly what to install when
something is missing.

### The offline CVE database

`tools/cvedb/cvedb.py` mirrors the NVD 2.0 API, the CISA KEV catalog and FIRST
EPSS scores into a local SQLite database. It uses only the Python standard
library and can be driven directly:

```bash
python3 tools/cvedb/cvedb.py sync              # incremental sync
python3 tools/cvedb/cvedb.py sync --full        # full rebuild
python3 tools/cvedb/cvedb.py get CVE-2021-44228 --json
python3 tools/cvedb/cvedb.py search --product "log4j" --kev
python3 tools/cvedb/cvedb.py stats
```

The database lives at `$CYBERPI_CVE_DB` or `~/.cyberpi/cve.db`. Every command
prints a JSON object on stdout, which is how the `cyber_cve_*` tools consume
it.

---

## Skills

Agent Skills live in `skills/`, one per phase of an engagement. Pi advertises
each one by name and description and reads the body only when the task calls
for it, so the context stays small and the response stays fast.

| Skill | Covers |
|---|---|
| `engagement-ops` | Running an engagement end to end: scope, evidence, journalling and reporting discipline |
| `recon-osint` | Subdomain enumeration, DNS mapping, WHOIS and ASN ownership, live HTTP discovery, secret exposure hunting |
| `service-enumeration` | Port scanning and service identification with naabu and nmap, NSE scripts and banner grabbing |
| `web-application-pentest` | Endpoint discovery, content discovery, access control, injection classes, file upload, headers, API testing |
| `vulnerability-assessment` | Template scanning, result triage, CVSS and EPSS correlation, false-positive elimination |
| `cve-intelligence` | The offline NVD, KEV and EPSS database: lookups, product and CPE searches, exploitability verdicts |
| `exploitation` | Turning a confirmed vulnerability into evidence-backed access: exploit search, minimal PoC, safe module execution |
| `privilege-escalation` | Escalating from an unprivileged foothold to root: sudo, SUID, cron, systemd and PATH abuse |
| `active-directory` | Domain reconnaissance, LDAP and DNS enumeration, SMB review, Kerberos and delegation, password spraying |
| `pivoting-and-tunneling` | Moving between segments: chisel SOCKS5 and reverse tunnels, proxying, relay chains |
| `wireless-and-radio` | Adapter and monitor-mode preparation, network survey, WPA handshakes and PMKID capture, key recovery |
| `iot-and-hardware` | Identifying embedded and OT devices, default credentials, firmware extraction, physical attack surfaces |
| `cloud-and-container` | Cloud identities and resources, IAM and role trust, public buckets, Kubernetes and container platforms |
| `phishing-simulation` | Authorized awareness campaigns with GoPhish against a simulated population, measured and reported |
| `forensics-and-ir` | Preserving and hashing evidence, chain of custody, host triage, timeline reconstruction, incident reporting |
| `reporting-and-evidence` | Recording findings with reproducible proof, rating severity, collecting evidence, building the report |

---

## Directory layout

```
CyberPi/
├── package.json            # pi-package manifest and peer dependencies
├── tsconfig.json
├── install.sh              # Kali installer (toolchain groups, flags for heavy packages)
├── uninstall.sh
├── bin/
│   ├── cyberpi             # launcher: platform check, then start Pi
│   ├── cyberpi-doctor      # environment and toolchain diagnostics
│   └── cyberpi-report      # render the report outside the agent
├── extensions/
│   ├── index.ts            # registers every tool, command and handler
│   ├── dashboard.ts        # the /cyber dashboard and the status line
│   ├── context.ts          # injects engagement state into the prompt
│   ├── lib/                # shared helpers: scope, exec, journal, cache, toolkit
│   └── tools/              # 35 tools in 12 groups
├── skills/                 # Agent Skills, one per phase of an engagement
├── prompts/                # 12 slash-command prompt templates
├── themes/cyber.json       # the CyberPi theme
├── tools/cvedb/cvedb.py    # the offline CVE database
├── tests/                  # node:test suites for the pure logic
└── docs/                   # plan, registry, install, usage, troubleshooting
```

### Engagement layout

Every engagement is a self-contained directory. Nothing is written outside it,
so an assessment is reproducible and can be handed over as a folder.

```
acme-web-2025-03/
└── .cyberpi/
    ├── scope.json          # the authorization
    ├── journal.jsonl       # append-only record of every action
    ├── surface.json        # the attack-surface index
    ├── artifacts/          # raw tool output
    ├── findings/           # one markdown file per recorded finding
    ├── notes/              # free-form operator notes
    ├── reports/            # generated reports
    └── cache/              # cached results
```

---

## Security and authorization model

**The scope file is the only thing that grants access.** Before a tool runs,
the shared wrapper resolves the target from its parameters, matches it against
the rules in `.cyberpi/scope.json` — honouring CIDRs, wildcards, exact hosts,
port, protocol and technique restrictions — and refuses the action if it does
not match. The refusal is specific: `target 10.2.3.4 is not in the authorized
scope of engagement "acme-web-2025-03"`. It never blocks the work; it routes it
back to the operator, who decides whether the client actually authorized it.

**It fails closed.** No scope file means nothing but the local machine is
reachable. An empty rule list behaves the same way. Self-testing against
loopback and local interface addresses is allowed by default and can be turned
off with `allowSelfTest`.

**Refusals are journalled.** A blocked action is written to the journal exactly
like a successful one, so the engagement record shows what was attempted as
well as what was done.

**Every action is journalled.** Each entry records the timestamp, the tool,
the action, the target, the exact command line, the exit code, the duration,
the severity and the artifact file. The journal is append-only JSONL, and it is
the same file the dashboard reads and the report is built from.

**Raw output is kept, secrets are not.** Full tool output is written to
`.cyberpi/artifacts/`. Credential material, session cookies and tokens are
never printed into the conversation — the tool summarises what it found and
points at the artifact file instead.

**Everything is local.** The CVE database is a local SQLite mirror. The
engagement state is local files. The only network traffic CyberPi generates is
the traffic you authorized, plus the optional CVE database sync.

**Kali only.** The platform gate refuses Windows and macOS. On a non-Kali
Linux distribution it warns and continues, unless `CYBERPI_STRICT_KALI=1` turns
the warning into a refusal.

**This is a tool for authorized work.** CyberPi performs the actions it is
asked to perform without moralizing, but the authorization is yours to obtain
and to write down. Use it on engagements you are contracted and permitted to
perform.

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/PLAN.md`](docs/PLAN.md) | Architecture, design decisions, the scope model, the speed strategy and the implementation order |
| [`docs/TOOL-REGISTRY.md`](docs/TOOL-REGISTRY.md) | The tool contract: names, techniques, required binaries, the `defineCyberTool` API and the CVE database CLI |
| [`docs/INSTALL.md`](docs/INSTALL.md) | Installing the harness and the Kali toolchain, including the optional package groups |
| [`docs/USAGE.md`](docs/USAGE.md) | Working with the harness day to day: engagements, the scope file, the commands, the tools |
| [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) | Missing packages, scope refusals, stale CVE data, monitor mode, non-Kali hosts |
| [`docs/TOOLING.md`](docs/TOOLING.md) | The toolchain reference: which binary each tool drives and what it expects |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | How the extension, skills, prompts, theme and journal fit together |
| [`docs/SECURITY.md`](docs/SECURITY.md) | The authorization model in full, the data flow, and the operational safeguards |
| [`docs/ENGAGEMENT.md`](docs/ENGAGEMENT.md) | The engagement directory in detail: scope, journal, surface, findings and reports |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) | Working on CyberPi itself: layout, tests, type checking and the coding conventions |

---

## Development

```bash
npm install          # install the peer/dev dependencies
npm run typecheck    # tsc --noEmit
npm test             # node:test suites
npm run verify       # load the package with Pi's own resource loader
npm run check        # all three
npm run doctor       # bin/cyberpi-doctor
```

The test suite covers the parts where a silent bug would be dangerous: the
authorization engine (CIDR, wildcard, port and technique filters, fail-closed
behaviour), the journal, the findings parser and the target parser. It also
drives the real tool definitions end to end: an out-of-scope target is refused
and journalled, a technique outside the allowlist is refused, a finding is
written to disk and the report is generated from it.

`npm run verify` loads the package the way Pi does at startup, so a skill with
broken frontmatter or a theme with an unresolvable colour variable fails the
check instead of being silently skipped on Kali.

---

## License

Apache-2.0. The license is declared in `package.json`; the full text ships in the
`LICENSE` file at the repository root.
