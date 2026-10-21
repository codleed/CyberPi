# Using CyberPi

This is the day-to-day guide: how an engagement runs from "create the folder"
to "hand over the report", what the tools do, what lands on disk and how to
work fast.

Read [INSTALL.md](INSTALL.md) first if CyberPi is not installed yet. The
authoritative list of tools is [TOOL-REGISTRY.md](TOOL-REGISTRY.md).

---

## 1. The model

CyberPi is a Pi package. Inside a session the agent is the operator, and three
things happen for every action:

1. **The scope decides.** The tool's declared `technique` and the target are
   checked against `<engagement>/.cyberpi/scope.json`. A refusal is specific
   and actionable: it names the file to edit.
2. **The journal records it.** Every command is appended to
   `.cyberpi/journal.jsonl` with the target, the command line, the exit code
   and the duration — including the attempts that were refused.
3. **The index accumulates it.** Reconnaissance results are merged into
   `.cyberpi/surface.json`, so the next question about the target is answered
   from a file instead of a new scan.

You never have to remember step 1. You do have to write the scope.

---

## 2. The daily workflow

### Step 1 — Create the engagement

```bash
cyberpi new acme-web-2025-03 --client "Acme Corporation"
cd acme-web-2025-03
```

This creates the directory tree, a `scope.json` template with the engagement
name and the client filled in, and a `README.md` that describes the layout.

### Step 2 — Write the scope

```bash
nano .cyberpi/scope.json
```

Start from the template in [INSTALL.md §4](INSTALL.md#the-scope-file). The
minimum is an engagement name and the authorized targets:

```json
{
	"engagement": "acme-web-2025-03",
	"client": "Acme Corporation",
	"authorization": {
		"statement": "External web application penetration test, SOW-2025-014.",
		"authorizedBy": "jane.doe@acme.example",
		"start": "2025-03-03",
		"end": "2025-03-14"
	},
	"techniques": ["recon", "port-scan", "service-enumeration", "web-testing", "vulnerability-scan"],
	"rules": [
		{ "id": "web", "target": "example.com" },
		{ "id": "office", "target": "10.10.10.0/24", "protocols": ["tcp"] }
	],
	"allowSelfTest": true
}
```

Two things to get right:

- **A bare domain covers its subdomains.** `example.com` also authorizes
  `app.example.com`. Use `*.example.com` for subdomains only and
  `exact:example.com` for the host alone.
- **The technique list is a filter, not a formality.** A tool whose technique
  is not listed is refused before it runs. If the engagement forbids
  credential attacks, simply leave `password-audit` out of the list; the
  `cyber_password_audit` tool then refuses to run and says why.

Check that the scope parses and the counters look right:

```bash
cyberpi --check
```

### Step 3 — Start the harness

```bash
cyberpi
```

The launcher verifies the platform and starts Pi with the CyberPi package
loaded, inside the engagement directory. The status line shows the engagement
name, the number of hosts and services in the index and the current phase.

To work on an engagement from another directory, name it:

```bash
cyberpi --engagement ~/engagements/acme-web-2025-03
```

The launcher also accepts `--print` and `--json` for one-shot runs, and
`--theme <name>` to override the theme for that run.

### Step 4 — Work the phases

Use the slash commands for the standard phases (see [§4](#4-slash-commands)),
or drive the tools directly:

```
/recon example.com
/scan 10.10.10.0/24
```

```
Enumerate the open ports on 10.10.10.5 with cyber_portscan, then run
cyber_service_scan on the open ports and tell me which services look outdated.
```

The agent calls the tools, the tools check the scope, run the scanner, parse
its structured output, write an artifact and update the index. The transcript
gets a summary, not a wall of raw JSON.

### Step 5 — Record the findings

```
Record a finding: critical, Apache Log4j2 RCE on https://app.example.com,
CVE-2021-44228, confirmed by the request in .cyberpi/artifacts/poc-<timestamp>.txt.
```

Each finding becomes a Markdown file with frontmatter in
`.cyberpi/findings/`, already half written for the report:

```markdown
---
id: F-001
title: "Apache Log4j2 remote code execution via JNDI lookup"
severity: critical
cvss: 10
cve: CVE-2021-44228
cwe: CWE-502
target: "https://app.example.com"
status: confirmed
tags: ["rce", "java", "injection"]
references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
createdAt: 2025-03-04T10:22:31.000Z
updatedAt: 2025-03-04T10:22:31.000Z
---

# Apache Log4j2 remote code execution via JNDI lookup

## Description

The application logs the `User-Agent` header unfiltered and the server runs
Log4j2 2.14.1.

## Impact

Remote code execution as the application user.

## Reproduction

```bash
curl -s -o /dev/null -w '%{http_code}\n' 'https://app.example.com/?x=${jndi:ldap://127.0.0.1:1389/a}'
```

## Evidence

- Response code 400 with a `JndiLookupException` in the response body
- Raw output: `.cyberpi/artifacts/poc-<timestamp>.txt`
```

Findings are numbered `F-001`, `F-002`, ... and sorted by severity when
rendered.

### Step 6 — Generate the report

```
/report
```

The report is assembled from the findings, the surface index and the journal,
and written under `.cyberpi/reports/`. The same deliverable can be rendered
outside the agent:

```bash
cyberpi-report                                   # Markdown on stdout
cyberpi-report --format html --output report.html
```

### Step 7 — Resume tomorrow

```bash
cd acme-web-2025-03
cyberpi            # starts Pi in the engagement directory
```

`cyberpi` is a launcher around Pi: it checks the platform and then hands over
to Pi with the same arguments. To continue the most recent session in this
directory, use Pi's own flag:

```bash
pi --continue
```

Everything the next session needs is on disk: the scope, the index, the
journal, the findings and the cache.

---

## 3. Using the tools directly

The tools are ordinary Pi tools, so you can call them by name. Inside a
session, ask for them in plain language; the agent picks the tool and the
arguments. Outside a session, use print mode:

```bash
cd ~/engagements/acme-web-2025-03
cyberpi --print "Enumerate the open ports on 10.10.10.5 with cyber_portscan and summarise the result"
```

`cyberpi --print` runs Pi once and exits; `cyberpi --json` produces the JSONL
event stream instead, which is what you want when the run is part of a
pipeline.

Every tool follows the same rules:

- the target comes from the arguments (`target`, `host`, `url`, `domain`, `ip`,
  ...);
- the technique is checked against the scope allowlist;
- the binary is checked before the run, and a missing binary produces the
  `apt-get` line that installs it;
- the output is truncated for the transcript and the full output is written to
  a timestamped file in `.cyberpi/artifacts/`;
- the action is appended to the journal.

### The tool set

| Tool | Technique | Needs | What it does |
|---|---|---|---|
| `cyber_subdomain` | recon | subfinder | Passive subdomain discovery. |
| `cyber_dns` | recon | dig | DNS record lookups (A, AAAA, MX, NS, TXT). |
| `cyber_whois` | recon | whois | Registration data for a domain or address. |
| `cyber_portscan` | port-scan | naabu | Fast SYN port scan. |
| `cyber_service_scan` | service-enumeration | nmap | Service and version detection. |
| `cyber_capture` | recon | tcpdump | Packet capture to an artifact file. |
| `cyber_http_probe` | recon | httpx | HTTP probe: status, title, technology, web server. |
| `cyber_crawl` | web-testing | katana | Crawls the application for endpoints. |
| `cyber_dir_enum` | web-testing | ffuf | Directory and file brute force. |
| `cyber_vuln_scan` | vulnerability-scan | nuclei | Template-driven vulnerability scan. |
| `cyber_sqli` | web-testing | sqlmap | SQL injection testing. |
| `cyber_xss` | web-testing | dalfox | Cross-site scripting testing. |
| `cyber_exploit_search` | exploit | searchsploit | Search the exploit database. |
| `cyber_exploit_run` | exploit | msfconsole | Run a Metasploit module. |
| `cyber_poc` | exploit | curl | Single request proof of concept. |
| `cyber_hash_id` | password-audit | hashcat | Identify a hash format. |
| `cyber_hash_crack` | password-audit | hashcat | Offline password cracking. |
| `cyber_password_audit` | password-audit | hydra | Online credential audit. |
| `cyber_secret_scan` | password-audit | trufflehog | Secret scanning in a repository or directory. |
| `cyber_ad_enum` | active-directory | ldapdomaindump | Domain and enumeration data. |
| `cyber_ad_attack` | active-directory | impacket-smbserver | Relay, named-pipe and SMB attacks. |
| `cyber_wireless_scan` | wireless | airodump-ng | Wireless reconnaissance. |
| `cyber_wireless_crack` | wireless | aircrack-ng | WPA key recovery. |
| `cyber_iot_scan` | iot-hardware | nmap | IoT device discovery. |
| `cyber_firmware_analysis` | iot-hardware | binwalk | Firmware extraction and analysis. |
| `cyber_hid_attack` | iot-hardware | hidrd | HID and USB descriptor analysis. |
| `cyber_pivot` | pivot | chisel | Tunnel through a compromised host. |
| `cyber_cloud_enum` | cloud-enumeration | aws | Cloud storage and identity enumeration. |
| `cyber_cve_lookup` | vulnerability-scan | python3 | Look up a CVE in the local database. |
| `cyber_cve_sync` | vulnerability-scan | python3 | Sync the local CVE database. |
| `cyber_exploit_map` | exploit | python3 | Map a CVE to known exploits. |
| `cyber_record_finding` | — | — | Record a finding. |
| `cyber_report` | — | — | Render the engagement report. |
| `cyber_journal` | — | — | Read the engagement journal. |
| `cyber_surface` | — | — | Read the attack surface index. |

The four report tools carry no technique, so they are never refused by the
scope allowlist.

---

## 4. Slash commands

CyberPi ships twelve slash-command prompt templates in `prompts/`. The file
name becomes the command name, so `prompts/recon.md` is `/recon`.

| Command | Purpose |
|---|---|
| `/cyber` | The dashboard: scope, surface index, findings, journal tail. |
| `/status` | Summarise the engagement so far: scope, surface, findings by severity, recent activity. |
| `/recon <target>` | Passive and active reconnaissance; populates the surface index. |
| `/scan <target>` | Port scan followed by service and version enumeration. |
| `/webtest <url>` | Crawl and test a web application; records confirmed issues as findings. |
| `/exploit <cve-or-target>` | Exploit research, KEV/EPSS assessment and a non-destructive proof of concept. |
| `/privesc <focus>` | Local privilege escalation surface and validation. |
| `/cve <query>` | CVE intelligence for a product, a version or a CVE id. |
| `/ad <domain>` | Active Directory assessment and privilege paths. |
| `/wireless <interface>` | Wireless survey and key recovery on authorized networks. |
| `/iot <range>` | IoT discovery, default-credential check and firmware analysis. |
| `/harness <topic>` | Explain the harness: its tools, the scope and how to drive it. |
| `/report [format]` | Build the deliverable from the findings and the journal. |

The first five are the ones used in most engagements. Inside Pi, type `/` to see
every command — the templates are listed next to Pi's own commands.

Pi's own commands still work: `/model`, `/thinking`, `/settings`, `/reload`,
`/compact`, `/new`, `/resume`, `/tree`, `/fork`, `/export`, `/quit`.

---

## 5. A worked engagement

Engagement `acme-web-2025-03`: an external web application test against
`example.com` (production) and `10.10.10.0/24` (the office network segment
that hosts the staging estate). Scope allows `recon`, `port-scan`,
`service-enumeration`, `web-testing` and `vulnerability-scan`.

### 5.1 Reconnaissance

```
/recon example.com
```

`cyber_subdomain` runs `subfinder -json -silent -d example.com` and parses
its JSON lines:

```json
{"host":"www.example.com","input":"example.com","source":"crtsh"}
{"host":"app.example.com","input":"example.com","source":"crtsh"}
{"host":"staging.example.com","input":"example.com","source":"dnsdumpster"}
```

The transcript gets the count and the host list, and the complete list is
written to an artifact:

```
Found 3 subdomains for example.com (sources: crtsh, dnsdumpster)

www.example.com
app.example.com
staging.example.com
Full host list: /home/kali/engagements/acme-web-2025-03/.cyberpi/artifacts/subdomains-example.com.txt
```

The hosts are merged into the index, and `cyber_dns` resolves them:

```
example.com.        A     93.184.216.34
www.example.com.    A     93.184.216.34
app.example.com.    A     93.184.216.34
```

`cyber_whois` returns the registration record. The summary line the transcript
sees is one line per tool; the raw output is in the artifact file.

### 5.2 Port scan

```
Scan 10.10.10.0/24 for open TCP ports.
```

`cyber_portscan` runs `naabu -host 10.10.10.0/24 -json -silent -Pn -rate 1000`
and parses one JSON object per open port:

```json
{"host":"10.10.10.5","ip":"10.10.10.5","port":22,"protocol":"tcp"}
{"host":"10.10.10.5","ip":"10.10.10.5","port":443,"protocol":"tcp"}
{"host":"10.10.10.12","ip":"10.10.10.12","port":8080,"protocol":"tcp"}
```

What reaches the transcript is the summary and a short body, not the raw JSON:

```
naabu found 3 open ports on 10.10.10.0/24

open ports (3):
10.10.10.5:22/tcp
10.10.10.5:443/tcp
10.10.10.12:8080/tcp
```

Every open port is also written to the surface index. The full output is in
`.cyberpi/artifacts/portscan-10.10.10.0-24-<timestamp>.txt`.

### 5.3 Service enumeration

```
/scan 10.10.10.5
```

`cyber_service_scan` runs `nmap -sV -Pn -T3 -oX -` and parses the XML:

```
nmap found 2 open services on 10.10.10.5

open services (2):
22/tcp open ssh — OpenSSH 9.2p1 Debian 2+deb12u2
443/tcp open ssl/http — nginx 1.22.1
```

### 5.4 Web probing

```
Probe the web hosts in the index.
```

`cyber_http_probe` runs `httpx` and parses its JSON:

```json
{"url":"https://app.example.com","host":"93.184.216.34","status_code":200,"title":"Acme Portal","webserver":"nginx","tech":["nginx","PHP"],"content_length":18422}
```

The endpoint is merged into the index as an endpoint, so the next question
("what runs on app.example.com?") is answered from `surface.json`.

### 5.5 Vulnerability scan

```
/scan https://app.example.com
```

`/scan` covers the port scan and the service enumeration. For the
vulnerability pass, ask for it directly:

```
Run cyber_vuln_scan against https://app.example.com and summarise the matches.
```

`cyber_vuln_scan` runs `nuclei` and parses one JSON object per match:

```json
{
	"template": "http/cves/2021/CVE-2021-44228.yaml",
	"template-id": "CVE-2021-44228",
	"info": {
		"name": "Apache Log4j2 RCE",
		"severity": "critical",
		"tags": ["cve", "cve2021", "rce", "oast"]
	},
	"type": "http",
	"host": "https://app.example.com",
	"matched-at": "https://app.example.com/api/v1/orders"
}
```

### 5.6 Intelligence

```
Look up CVE-2021-44228 and check whether it is in the KEV catalog.
```

`cyber_cve_lookup` answers from the local database in milliseconds: the CVSS
score and vector, the CWE, the publication and modification dates, the
references, the KEV flag (CISA Known Exploited Vulnerabilities) and the EPSS
probability of exploitation. `cyber_exploit_map` adds the exploit database
entries for the same CVE.

### 5.7 Validation

```
Validate the Log4j finding with a single request and keep the raw response.
```

`cyber_poc` runs `curl` and stores the response in an artifact:

```bash
curl -s -o /dev/null -w '%{http_code}\n' 'https://app.example.com/?x=${jndi:ldap://127.0.0.1:1389/a}'
```

The raw response (including the stack trace that proves the lookup was
attempted) is written to `.cyberpi/artifacts/poc-<timestamp>.txt`; the transcript gets the
status line and the path to the file, not the whole body.

### 5.8 Record the finding

```
Record a critical finding for the Log4j RCE on https://app.example.com,
evidence in .cyberpi/artifacts/poc-<timestamp>.txt, references the NVD entry.
```

`.cyberpi/findings/F-001.md` is written (see the format in
[§2, step 5](#step-5--record-the-findings)).

### 5.9 Report

```
/report
```

The report lists the findings by severity, the engagement scope, the surface
summary and the action count from the journal, and it points at the artifacts
as evidence. It is written under `.cyberpi/reports/`.

### What the engagement directory looks like at the end

```
acme-web-2025-03/.cyberpi/
├── scope.json
├── surface.json
├── journal.jsonl
├── artifacts/
│   ├── subdomains-example.com.txt
│   ├── portscan-10.10.10.0-24-<timestamp>.txt
│   ├── nmap-10.10.10.5-<timestamp>.txt
│   ├── httpx-app.example.com-<timestamp>.txt
│   ├── nuclei-app.example.com-<timestamp>.txt
│   └── poc-<timestamp>.txt
├── findings/
│   └── F-001.md
└── reports/
    └── report-2025-03-04T10-30-00-000Z.md
```

The report tool writes a timestamped file by default and returns the path it
wrote. It renders Markdown or HTML, and the journal appendix can be left out
with the tool's `include_journal` option.

---

## 6. The dashboard

```
/cyber
```

The dashboard renders the engagement in the `cyber` palette:

- the **engagement name**, the client and the authorization window,
- the **scope summary**: the authorized targets and the allowed techniques,
- the **surface counters**: hosts, services, distinct ports and endpoints,
- the **findings**, grouped by severity, with the CVSS score where known,
- the **journal tail**: the last actions with their severity colour.

`cyber_surface` returns the same index as structured data, and `cyber_journal`
returns the journal entries, so the agent can answer questions about the
engagement without touching the files by hand.

---

## 7. The CVE database

CyberPi keeps a local SQLite mirror of the NVD, the CISA KEV catalog and the
FIRST EPSS scores, so a lookup takes milliseconds and works offline.

The database lives at `~/.cyberpi/cve.db` (override with `CYBERPI_CVE_DB`) and
is queried through `tools/cvedb/cvedb.py`, which uses only the Python standard
library.

```bash
python3 tools/cvedb/cvedb.py sync                 # incremental update
python3 tools/cvedb/cvedb.py sync --full          # full rebuild
python3 tools/cvedb/cvedb.py get CVE-2021-44228 --json
python3 tools/cvedb/cvedb.py search --product log4j --cvss-min 9 --json
python3 tools/cvedb/cvedb.py by-cpe 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*' --json
python3 tools/cvedb/cvedb.py kev --limit 20 --json
python3 tools/cvedb/cvedb.py stats --json
```

Every command prints one JSON object to stdout. The `sync` command pulls from
the NVD 2.0 API, the CISA KEV catalog and the FIRST EPSS service; a full sync
of the NVD takes a while, so run it once and then use the incremental sync.

A lookup returns the CVE with its KEV and EPSS annotations:

```json
{
	"ok": true,
	"command": "get",
	"found": true,
	"cve": {
		"id": "CVE-2021-44228",
		"published": "2021-12-10T10:15:09.143Z",
		"modified": "2023-04-03T20:15:07.000Z",
		"lastModified": "2023-04-03T20:15:07.000Z",
		"description": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features ...",
		"cvss_score": 10.0,
		"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		"severity": "critical",
		"cwes": ["CWE-502", "CWE-400"],
		"products": ["log4j", "log4j2"],
		"references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
		"kev": true,
		"kev_entry": {
			"vendor": "Apache",
			"product": "Log4j2",
			"vuln_name": "Apache Log4j2 Remote Code Execution Vulnerability",
			"date_added": "2021-12-10",
			"due_date": "2021-12-24",
			"ransomware": "Known"
		},
		"epss": { "score": 0.94365, "percentile": 0.98731, "date": "2025-02-14" }
	}
}
```

A CVE that is not in the local database comes back with `"found": false` and a
message telling you to run the sync.

From inside the agent:

```
Sync the CVE database.
Look up CVE-2021-44228 and tell me whether it is in the KEV catalog.
Which CVEs with a critical score affect Apache Log4j?
```

`cyber_cve_sync`, `cyber_cve_lookup` and `cyber_exploit_map` map to the three
workflows above.

---

## 8. The journal

`.cyberpi/journal.jsonl` is the append-only record of the engagement: one JSON
object per line.

```json
{"ts":"2025-03-04T10:04:12.512Z","tool":"cyber_portscan","action":"cyber_portscan","target":"10.10.10.0/24","command":"naabu -host 10.10.10.0/24 -json -silent -Pn -rate 1000","exitCode":0,"durationMs":8412,"summary":"exit 0","severity":"info","artifact":"/home/kali/engagements/acme-web-2025-03/.cyberpi/artifacts/portscan-10.10.10.0-24-2025-03-04T10-04-12-512Z.txt"}
{"ts":"2025-03-04T10:07:55.108Z","tool":"cyber_http_probe","action":"blocked","target":"10.10.20.7","summary":"target 10.10.20.7 is not in the authorized scope of engagement \"acme-web-2025-03\". Add it to .cyberpi/scope.json if the client authorized it.","severity":"info"}
```

Note the second entry: refused actions are journalled too. That is what makes
the engagement record defensible — it shows what was attempted, not only what
succeeded.

Read it from the agent:

```
Show me the journal for today.
Which commands failed?
```

Or directly:

```bash
head .cyberpi/journal.jsonl
jq -r 'select(.exitCode != null and .exitCode != 0) | .command' .cyberpi/journal.jsonl
```

`cyber_journal` returns the entries and the per-tool and per-severity counts.

---

## 9. Multi-session usage

A session is bound to the directory Pi runs in, and the engagement directory
*is* that directory. Sessions in the same engagement share the state on disk.

```bash
cd acme-web-2025-03
cyberpi                  # new session
pi --continue            # continue the most recent session here
```

Inside Pi:

```
/session      # current session information
/resume       # pick another saved session
/fork         # branch from an earlier message
/compact      # shrink the context, keep the findings on disk
/tree         # navigate the session tree
```

Practical rules for a long engagement:

- **One phase per session.** A recon session, a web-testing session and a
  reporting session keep the context small and the transcript readable.
- **The state is on disk, not in the context.** The scope, the index, the
  journal and the findings are read from `.cyberpi/`, so `/compact` never
  loses engagement state.
- **Name the sessions** so they are findable later: `/name recon-2025-03-04`.
- **Work on the engagement from anywhere** with `CYBERPI_ENGAGEMENT`:

  ```bash
  CYBERPI_ENGAGEMENT=~/engagements/acme-web-2025-03 pi
  ```

  The tools read and write the engagement directory, while the session itself
  is grouped by the current working directory.
- **Keep the engagement directory in version control** if the client allows it.
  `.cyberpi/findings/` and `.cyberpi/journal.jsonl` are the evidence; the
  artifacts directory usually is not worth committing.

---

## 10. Performance

### Caching

Identical tool calls hit the cache in `.cyberpi/cache/results.json` and return
in milliseconds instead of re-running the scanner. Each tool declares its own
time-to-live, so a port scan is cached for minutes while a slow enumeration
expires sooner. A cached result is marked as such in the tool output, so you
always know whether you are looking at fresh data.

The cache is per engagement. Deleting `.cyberpi/cache/results.json` forces the
next call to run the scanner again — useful when the target changed.

### The surface index

`surface.json` is the merged view of everything the reconnaissance found:
hosts, services and endpoints, each with the tool that discovered it. Ask the
agent about the target instead of re-scanning it:

```
What ports are open on 10.10.10.5?      # answered from the index
```

Answers that come from the index are instant and cost nothing. Answers that
need a new scan are the ones that take time — so ask for the index first.

### Parallel scans

A single tool call can run several commands at once. Port scanning a /24,
probing many web hosts and running nuclei over a list of URLs overlap instead
of queueing. Ask for the work in one sentence and the agent batches it:

```
Scan 10.10.10.0/24 for ports, then probe every web host you find.
```

Long commands have a timeout and a cancellation path: interrupting a scan in
Pi stops the process, journals it as a timeout and leaves the partial output
in the artifact file.

### Other speed levers

- **Ask for structured output.** The tools parse `-json` and summarise, so the
  transcript stays small and the model stays informed. Asking for "the table
  of open ports" is cheaper than asking for "all the output".
- **Skills load lazily.** Pi advertises a skill by name and description and
  reads the body only when the task needs it, so the system prompt stays small
  at session start.
- **The CVE database is local.** A lookup does not touch the network and does
  not wait for an API key.
- **Scope your work.** Narrow rules mean fewer refused attempts, and a refused
  attempt still costs a tool round trip.

---

## 11. Quick reference

| Task | Command |
|---|---|
| Create an engagement | `cyberpi new <name> [--client <name>]` |
| Start the harness | `cyberpi` (inside the engagement directory) |
| Work on an engagement elsewhere | `cyberpi --engagement <dir>` |
| One-shot run | `cyberpi --print "<instruction>"` |
| Continue the last session | `pi --continue` |
| Check the installation | `cyberpi-doctor` |
| Check the engine | `cyberpi --check` |
| Render the report outside the agent | `cyberpi-report [--format markdown\|html] [--output <file>]` |
| Sync the CVE database | `python3 tools/cvedb/cvedb.py sync --full` |
| Look up a CVE | `python3 tools/cvedb/cvedb.py get CVE-2021-44228 --json` |
| Read the journal | `cat .cyberpi/journal.jsonl` |
| Read the index | `cat .cyberpi/surface.json` |
| Read a finding | `cat .cyberpi/findings/F-001.md` |
| Find a refusal | `jq -r 'select(.action=="blocked") \| .summary' .cyberpi/journal.jsonl` |

When something refuses to run, the message names the reason: a missing binary
comes with the `apt-get` line, a scope refusal names the file to edit, and a
technique refusal names the allowlist. If none of those explains it, see
[TROUBLESHOOTING.md](TROUBLESHOOTING.md).
