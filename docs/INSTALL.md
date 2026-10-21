# Installing CyberPi

CyberPi turns the [Pi](https://github.com/earendil-works/pi) coding agent into a
Kali Linux security engagement harness: 35 scope-checked pentest tools, 17
engagement skills, an offline CVE database and a findings pipeline.

This document covers the prerequisites, the installer, the manual installation
path, the engagement directory layout and the LLM provider setup. For day-to-day
operation see [USAGE.md](USAGE.md).

---

## 1. Prerequisites

| Requirement | Detail |
|---|---|
| Operating system | **Kali Linux**, on bare metal or in a VM. Other Linux distributions run in a degraded mode; Windows and macOS are refused. |
| Memory | **4 GB RAM** minimum. 8 GB or more is recommended for `nuclei`, `metasploit-framework` and `bloodhound` in parallel. |
| Disk | ~6 GB for the core toolchain, ~15 GB with every optional group (metasploit, wireshark/tshark and radare2 dominate). |
| CPU | 2 cores minimum; 4+ for parallel scans. |
| Network | A wired or bridged interface. The host must be able to reach the engagement targets. |
| Wireless (optional) | A **network interface in monitor mode** with a driver that supports packet injection (for example `wlan0` with an Atheros AR9271, or an ALFA AWUS036NHA). Kali ships the `aircrack-ng` suite; the adapter needs to be in monitor mode before `cyber_wireless_scan` can capture anything. |
| Node.js | **22.19 or newer** (required by Pi). `node --version` must report `v22.19.0` or higher. |
| Python | **3.11 or newer**, standard library only. The CVE database needs no third-party packages. |
| Shell | `bash` and `coreutils` (present on every Kali image). |
| Privileges | `sudo` for the installer. Individual tools need root for raw sockets (`naabu`, `nmap -sS`, `tcpdump`) and for monitor mode. |

Check what is already on the machine:

```bash
node --version
python3 --version
cat /etc/os-release | head -3
iw list | grep -A 3 "Interface"   # wireless only
```

A Kali VM is the recommended setup: snapshot it before an engagement, keep the
adapter in a dedicated host-only network, and give the guest a second adapter
for wireless work if the engagement needs it.

---

## 2. One-line install

```bash
git clone https://github.com/<org>/CyberPi.git && cd CyberPi && sudo bash install.sh
```

Replace `<org>` with the repository owner. The installer installs the package
payload from the directory it lives in, so it has to run from the repository
root. The same applies to the piped form, which therefore has to be run from
inside a clone:

```bash
cd CyberPi
curl -fsSL https://raw.githubusercontent.com/<org>/CyberPi/main/install.sh | sudo bash
```

If you already have the sources, the installer is the only step:

```bash
cd /opt/CyberPi
sudo bash install.sh
```

### What the installer does

1. **Checks the runtime.** Linux is required and Kali is recommended; Node.js
   22.19+ and Python 3.11+ are checked. On a non-Kali distribution it prints a
   warning and continues (set `CYBERPI_STRICT_KALI=1` to turn the warning into
   a refusal).
2. **Installs the Kali packages** with `apt-get`: the core group by default,
   more with `--groups` or `--full`. The heavyweight groups ask for
   confirmation first, because they pull in gigabytes of data.
3. **Creates the data directory** `~/.cyberpi` with mode `700`. The CVE
   database lives at `~/.cyberpi/cve.db`.
4. **Copies the package payload** to `/usr/local/lib/cyberpi`.
5. **Installs the theme** as `~/.pi/agent/themes/cyber.json`.
6. **Registers the package with Pi** with `pi install /usr/local/lib/cyberpi`,
   so the tools, skills, prompt templates and the theme load in every session.
7. **Creates the commands** `cyberpi`, `cyberpi-doctor` and `cyberpi-report` in
   `/usr/local/bin`.
8. **Offers to seed the CVE database** with a first NVD, KEV and EPSS sync.

### Installer flags

| Flag | Effect |
|---|---|
| *(none)* | Core install: the core package group plus the Pi package, theme and launchers. |
| `--core` | Install the core tool group only. Same as the default. |
| `--groups <list>` | Install the given groups, comma-separated. |
| `--full` | Install every tool group. |
| `--no-apt` | Do not install any Kali package. Use it when the toolchain is already installed, on an air-gapped host, or when `apt` is managed by something else. |
| `--uninstall` | Remove CyberPi instead of installing it. |
| `--yes` | Do not ask for confirmation. |
| `--help` | Show the usage and the list of groups. |

```bash
sudo bash install.sh --groups web,creds      # core plus web and credential tooling
sudo bash install.sh --full                  # everything
sudo bash install.sh --no-apt                # no package manager, keep the toolchain
sudo bash install.sh --uninstall             # remove CyberPi
```

`sudo bash install.sh --help` prints the same list.

### Tool groups

| Group | Packages | Notes |
|---|---|---|
| `core` | nmap, naabu, httpx, katana, ffuf, nuclei, subfinder, dnsutils, whois, iproute2, net-tools | Installed by default. |
| `web` | sqlmap, dalfox, nikto, gobuster, wafw00f, sslscan, testssl.sh, feroxbuster | |
| `creds` | hashcat, john, hydra, trufflehog | |
| `exploit` | metasploit-framework, exploitdb (searchsploit) | Large. |
| `ad` | impacket-scripts, responder, bloodhound, ldapdomaindump | Large. |
| `wireless` | aircrack-ng, wifite, hcxtools, bettercap | |
| `iot` | binwalk, radare2, hidrd, python3-serial, cutter | Large. |
| `network` | tcpdump, tshark, wireshark, chisel, proxychains4, socat | Large. |
| `cloud` | awscli, azure-cli, google-cloud-cli | Very large; the Azure CLI alone is ~1 GB. |

---

## 3. Manual installation

Use this path when the installer cannot run: an air-gapped host, a managed
workstation, or a container image you build yourself.

### 3.1 Install Pi

```bash
curl -fsSL https://pi.dev/install.sh | sh
```

Or through npm (does not pin transitive dependencies):

```bash
npm install -g --ignore-scripts @earendil-works/pi-coding-agent
```

Verify:

```bash
pi --version
node --version        # must be v22.19.0 or newer
```

### 3.2 Install the CyberPi package into Pi

From a clone of the repository:

```bash
cd /opt/CyberPi
pi install /opt/CyberPi
```

`pi install` writes the package declaration to `~/.pi/agent/settings.json`
(personal scope), so the tools load in every session. Add `--local` to write it
to the current project's `.pi/settings.json` instead; project packages are only
loaded after the project is trusted.

Other package commands:

```bash
pi list                  # show configured packages
pi update --extensions   # reconcile every installed package
pi remove /opt/CyberPi   # remove the package declaration
```

For a one-off run without registering the package:

```bash
pi -e /opt/CyberPi
```

### 3.3 Install the theme

The theme lives in the package at `themes/cyber.json`. Pi loads user themes
from `~/.pi/agent/themes/<name>.json`, so install it once:

```bash
mkdir -p ~/.pi/agent/themes
cp /opt/CyberPi/themes/cyber.json ~/.pi/agent/themes/cyber.json
```

A symlink works too and keeps the theme in step with the package:

```bash
ln -sf /opt/CyberPi/themes/cyber.json ~/.pi/agent/themes/cyber.json
```

Then select it in Pi (see [§6](#6-the-theme)) or for a single run:

```bash
pi --use-theme cyber
```

### 3.4 Create the engagement directory

An engagement is a directory that contains a `.cyberpi/` state folder. The
launcher creates it for you:

```bash
cyberpi new acme-web-2025-03 --client "Acme Corporation"
cd acme-web-2025-03
```

`cyberpi new` creates the directory, the `.cyberpi/` subdirectories, a
`scope.json` template pre-filled with the engagement name and the client, and
a short `README.md` describing the layout. If you prefer to do it by hand:

```bash
mkdir -p acme-web-2025-03/.cyberpi/{artifacts,findings,notes,reports,cache}
cd acme-web-2025-03
```

### 3.5 Install the Kali toolchain

The installer does this with `apt-get`; manually:

```bash
sudo apt-get update
sudo apt-get install -y nmap naabu httpx-toolkit katana ffuf nuclei subfinder dnsutils whois iproute2 net-tools
```

Optional groups follow the table in [§2](#tool-groups), for example:

```bash
sudo apt-get install -y hashcat john hydra trufflehog
```

---

## 4. The engagement directory layout

Everything CyberPi produces lives inside the engagement, so an assessment is
self-contained and reproducible:

```
acme-web-2025-03/
├── .cyberpi/
│   ├── scope.json        # authorization: targets, ports, protocols, techniques
│   ├── journal.jsonl     # append-only log of every action taken
│   ├── surface.json      # attack surface index (hosts, services, endpoints)
│   ├── artifacts/        # raw scanner output, one file per command
│   ├── findings/         # one Markdown file per finding (F-001.md, F-002.md, ...)
│   ├── notes/            # free-form notes
│   ├── reports/          # generated deliverables
│   └── cache/            # cached tool results (results.json)
└── (your own working files)
```

The directory is what makes the engagement resumable: point CyberPi at it and
the scope, the index, the journal and the findings all come back.

### The scope file

`scope.json` is the authorization record. It is JSON **with comments allowed**,
so it can be annotated in place.

```jsonc
{
	"engagement": "acme-web-2025-03",
	"client": "Acme Corporation",
	"authorization": {
		"statement": "External web application penetration test, authorised by Jane Doe (CISO) under SOW-2025-014.",
		"authorizedBy": "jane.doe@acme.example",
		"start": "2025-03-03",
		"end": "2025-03-14"
	},
	// Techniques the engagement allows. A tool whose technique is not listed is refused.
	"techniques": [
		"recon",
		"port-scan",
		"service-enumeration",
		"web-testing",
		"vulnerability-scan"
	],
	"rules": [
		{
			"id": "web-production",
			"target": "example.com",
			"notes": "Production website and all of its subdomains."
		},
		{
			"id": "staging",
			"target": "*.staging.example.com",
			"notes": "Staging hosts only, the apex domain is excluded."
		},
		{
			"id": "office-network",
			"target": "10.10.10.0/24",
			"protocols": ["tcp"]
		},
		{
			"id": "appliance",
			"target": "10.10.20.7",
			"ports": [80, 443, 8443],
			"notes": "Single appliance, port restricted."
		}
	],
	// Allow scanning the local machine (self-test). Defaults to true.
	"allowSelfTest": true,
	"notes": "Out of hours: 22:00-06:00 UTC. No denial-of-service testing."
}
```

Minimal version, everything else optional:

```json
{
	"engagement": "acme-web-2025-03",
	"rules": [{ "target": "example.com" }]
}
```

**Target syntax** used by `rules[].target`:

| Form | Matches |
|---|---|
| `example.com` | The domain and every subdomain of it. |
| `*.example.com` | Subdomains only, not the apex. |
| `exact:example.com` | The host only, no subdomains. |
| `10.10.10.0/24` | Any host in the IPv4 CIDR. |
| `2001:db8::/32` | Any host in the IPv6 CIDR. |
| `10.10.20.7` | A single host. |

**Rule filters** — `ports`, `protocols` and `techniques` narrow a rule. A tool
that does not report a port is refused by a port-restricted rule, so restrict
by port only when the engagement really is port-limited.

**Fail-closed** — with no `scope.json`, only the local machine (loopback and the
host's own interface addresses) is reachable. Every other target is refused
with a message naming the file to edit.

---

## 5. Configure the LLM provider

CyberPi does not ship a model. It runs on whatever provider Pi is configured
with.

Inside Pi:

```
/login            # pick a provider, follow the OAuth or API-key flow
/model            # pick the model
```

The credential is stored in `~/.pi/agent/auth.json`. Keep it private.

Headless machines and CI:

```bash
export ANTHROPIC_API_KEY=sk-ant-...      # or OPENAI_API_KEY, GEMINI_API_KEY, ...
pi
```

Check the credential without starting a session:

```bash
pi auth check --provider anthropic --json
```

The provider list and the environment variable for each one are documented in
Pi's provider guide; the common ones are `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
`GEMINI_API_KEY`, `OPENROUTER_API_KEY` and `MISTRAL_API_KEY`.

CyberPi does not change the model configuration: a local model through
`llama.cpp` works exactly the same way, and `--model`/`--provider` on the `pi`
command line are honoured as usual.

---

## 6. The theme

The `cyber` theme uses an OKHSL palette: cyan accent on near-black, with
severity-coloured tool output (info, low, medium, high, critical).

Select it inside Pi:

```
/settings          # Terminal and display -> Theme -> cyber
```

Or for one run:

```bash
pi --use-theme cyber
```

Or permanently, in `~/.pi/agent/settings.json`:

```json
{
	"theme": "cyber"
}
```

The theme is only loaded from `~/.pi/agent/themes/cyber.json` when it is
hot-reloaded; after linking or editing the file, run `/reload` in Pi.

---

## 7. Verify the installation

```bash
cyberpi-doctor
```

The doctor checks, in order:

- the operating system and the kernel (and warns when the distribution is not
  Kali),
- the Node.js and Python versions,
- Pi itself: present, and which version,
- the CyberPi package registration in `~/.pi/agent/settings.json`,
- the theme in `~/.pi/agent/themes/cyber.json`,
- the engagement directory, the scope file, the journal and the findings,
- the CVE database: present, size and last sync,
- every binary the tools need, with the `apt-get` line that installs the
  missing ones.

It exits with status 1 when a check failed, so it can be used in a script.
Useful options:

```bash
cyberpi-doctor --engagement ~/engagements/acme-web-2025-03   # inspect an engagement
cyberpi-doctor --json                                        # machine readable report
cyberpi-doctor --fix                                         # apply the safe fixes
```

Run it from the repository as well:

```bash
bash bin/cyberpi-doctor
```

Check that the harness itself loads and the engagement layout is sound:

```bash
cyberpi --check
```

`cyberpi --check` runs the doctor and exits. Then try the package without
registering it:

```bash
pi -e /opt/CyberPi
```

Inside Pi, `/cyber` opens the dashboard. It should show the engagement name,
the scope summary, the surface index counters and the journal tail.

---

## 8. Update

```bash
pi update --extensions     # reconcile every installed package
pi update /opt/CyberPi     # update one package
pi list                    # check what is registered
```

For a clone-based installation:

```bash
cd /opt/CyberPi
git pull
pi update /opt/CyberPi
```

An installation done with `install.sh` keeps the payload in
`/usr/local/lib/cyberpi`; re-run the installer to update it:

```bash
sudo bash install.sh --no-apt
```

New Kali packages for a new tool group:

```bash
sudo bash install.sh --groups web
```

The CVE database is refreshed separately, because it is data and not code:

```bash
python3 /usr/local/lib/cyberpi/tools/cvedb/cvedb.py sync --full
```

or from inside the agent, `cyber_cve_sync`.

---

## 9. Uninstall

```bash
sudo bash uninstall.sh
```

This removes the commands (`/usr/local/bin/cyberpi`, `cyberpi-doctor`,
`cyberpi-report`), the theme, the Pi package declaration and the installed
payload. **Engagement directories are never touched** — they are your
deliverables.

| Flag | Effect |
|---|---|
| `--purge` | Also delete the data directory `~/.cyberpi`, which holds the CVE database. Without it the database survives. |
| `--keep-package` | Keep the payload in `/usr/local/lib/cyberpi`. |
| `--yes` | Do not ask for confirmation. |
| `--help` | Show the usage. |

`sudo bash install.sh --uninstall` runs the same uninstaller.

To do it by hand:

```bash
pi remove /opt/CyberPi
rm -f ~/.pi/agent/themes/cyber.json
rm -f /usr/local/bin/cyberpi /usr/local/bin/cyberpi-doctor /usr/local/bin/cyberpi-report
rm -rf /usr/local/lib/cyberpi
```

Removing the Kali packages is optional and usually a bad idea — other work on
the machine may need them. `sudo apt-get remove --purge <package>` removes
individual packages.

---

## 10. Environment variables

| Variable | Effect |
|---|---|
| `CYBERPI_HOME` | Global state directory. Default `~/.cyberpi`. |
| `CYBERPI_CVE_DB` | Path to the SQLite CVE database. Default `$CYBERPI_HOME/cve.db`. |
| `CYBERPI_ENGAGEMENT` | Use this directory as the engagement root instead of the working directory. Lets you point a session at an engagement from elsewhere. |
| `CYBERPI_STRICT_KALI` | Set to `1` to refuse to run on a Linux distribution that is not Kali. |
| `CYBERPI_PACKAGE_ROOT` | Root of the installed package payload. Set by the installed `cyberpi` commands. |
| `CYBERPI_INSTALL_PREFIX` | Installation prefix. Default `/usr/local`. Used by `install.sh` and `uninstall.sh`. |
| `CYBERPI_NO_COLOR` | Set to `1` to disable the colours of the shell commands. |

The Pi variables (`PI_OFFLINE`, `PI_CODING_AGENT_DIR`, `PI_SESSION_DIR`, ...)
apply as usual; see Pi's environment variable reference.

---

## 11. Where to go next

- [USAGE.md](USAGE.md) — the daily workflow, a worked engagement, the dashboard
  and the CVE database.
- [TOOL-REGISTRY.md](TOOL-REGISTRY.md) — the authoritative list of tools,
  techniques and required binaries.
- [TOOLING.md](TOOLING.md) — which binary each tool drives and what it expects.
- [SECURITY.md](SECURITY.md) — the authorization model in full.
- [PLAN.md](PLAN.md) — the architecture and the design decisions behind it.
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — scope refusals, missing packages,
  stale CVE data, monitor mode.
