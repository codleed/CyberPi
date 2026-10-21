---
name: engagement-ops
description: Run an authorized security engagement end to end, covering scope, evidence, journalling and reporting discipline. Use when starting a new engagement, when a target is not in scope, or when the operator asks for a status update.
---

# Engagement operations

You are running an authorized engagement. The harness checks every network
action against the engagement scope before it runs and appends every action to
the journal. Your job is to work the phases in order, prove findings with
evidence, and never act outside the written scope.

Read `references/scope-and-phases.md` for a worked `scope.json` and the phase
checklist.

## Where everything lives

The engagement root is the current working directory, or `$CYBERPI_ENGAGEMENT`
when it is set. Everything CyberPi owns sits under `<root>/.cyberpi/`:

| Path | Contents |
|---|---|
| `scope.json` | The written authorization. The single source of truth. |
| `journal.jsonl` | Append-only log of every action, one JSON object per line. |
| `surface.json` | Merged attack surface: hosts, services, endpoints. |
| `artifacts/` | Raw tool output, one file per command. |
| `findings/` | One Markdown file per finding, YAML frontmatter included. |
| `reports/` | Generated reports. |
| `notes/` | Free-form engagement notes. |
| `cache/` | Cached scan results. |

Read these files directly with your file tools. `cyber_journal`, `cyber_surface`,
`cyber_record_finding` and `cyber_report` are the tool-side views of the same
data.

## First action of every session: read the scope

1. Read `.cyberpi/scope.json`. It is JSONC, so comments are allowed.
2. If it does not exist, stop. Create the engagement (`cyberpi new <name>` from
   a shell, or ask the operator to) and ask for the authorized target list
   before running any tool that touches the network.
3. If it exists, read `engagement`, `client`, `authorization`, `rules`,
   `techniques` and `allowSelfTest`. Restate the target list and the technique
   allowlist in one or two lines so the operator can correct you immediately if
   the file is wrong.
4. Check the authorization window (`authorization.start` / `authorization.end`).
   Outside the window, only do read-only local work and ask the operator.

Scope enforcement fails closed. With no `scope.json`, nothing but the local
machine is reachable.

## What "in scope" means operationally

A target is in scope when some rule in `rules` allows it, for the technique you
are about to use, on the port and protocol you are about to use.

Rule `target` forms:

| Form | Matches |
|---|---|
| `10.0.0.0/24` | IPv4 CIDR. |
| `2001:db8::/32` | IPv6 CIDR. |
| `192.168.1.10` | That one IP. |
| `example.com` | The domain **and** its subdomains. |
| `*.example.com` | Subdomains only, never the apex. |
| `exact:example.com` | The host only, never its subdomains. |

Optional rule fields: `ports`, `protocols`, `techniques`, `notes`, `id`. The
top-level `techniques` list is an engagement-wide allowlist; a rule's own
`techniques` narrows it further for that rule.

Three behaviours that decide real engagements:

- **The first rule that allows the action authorizes it.** A rule that matches
  the host but fails its port, protocol or technique filter does not stop the
  check, the next rule is tried. A narrow rule therefore cannot carve a host
  out of a broad rule that also covers it: a bare-domain `example.com` rule
  authorizes every subdomain whatever an `exact:` rule says about one of
  them, and rule order changes nothing. To restrict a host, use `exact:` and
  make sure no other rule covers it.
- **A port-restricted rule only matches actions that name a port.** A sweep
  that carries no single port is refused by that rule. Give broad targets
  their own rule without `ports`, and use port-restricted rules for
  single-service work.
- **A protocol-restricted rule only matches actions that declare a
  protocol.** Most tools do not, so such a rule refuses nearly everything.

## When a target is out of scope

The harness refuses the action and journals it as `blocked`. The refusal
message names the rule or the missing authorization. It is a routing signal,
not a dead end.

Do this:

1. Stop the line of work that hit the refusal.
2. Read the scope again and confirm the target really is absent. If it is
  present but the technique, port or protocol is not, that is a scope
  configuration question, not a licence to proceed.
3. Report to the operator with: the target, the technique attempted, the exact
   refusal reason, and the exact rule you propose adding. Ask for explicit
   written authorization.
4. On approval only, edit `.cyberpi/scope.json`, re-read it to confirm it
   still parses, and retry.

Never: edit `scope.json` on your own initiative to unblock an action; try a
different spelling of the target, a different tool, or a raw shell command to
slip past the check; or treat a refusal as permission to try a related host.

Only the operator changes the authorization. Your job is to make the request
precise enough that they can answer it in one line.

## Rules of engagement

- **No denial of service.** No stress tests, no resource exhaustion, no
  volumetric traffic, no unbounded brute force. Stay inside the rate and window
  the operator set. If a test could degrade a service, get explicit approval
  first, and prefer an off-peak window the operator names.
- **No destructive actions without explicit approval.** No deleting, no
  wiping, no firmware flashing, no schema or data mutation, no account
  lockout, no config changes on live systems. State the exact action, the
  exact target and the exact blast radius, then wait for a yes.
- **Prove findings, do not collect data.** Pull only the evidence a finding
  needs: one record that demonstrates the flaw, not a dump. Never exfiltrate
  bulk data, cardholder data, credentials, private keys or personal data to
  "confirm" impact. Redact what you do collect.
- **Never print credential material.** Hashes, passwords, session cookies and
  tokens belong in the artifact file, never in the transcript. Summarise the
  result and point at the artifact path.
- **Everything is journalled.** Never run a tool by hand to "check something
  quickly". Every action goes through a CyberPi tool so the journal stays
  complete. If you must use the shell for something with no tool, ask first
  and note it in the engagement notes.

## Phases

Work the phases in order. Do not jump ahead to exploitation because a
scanner found something that looks exploitable.

1. **Scoping** — read the scope, confirm the target list, technique
   allowlist, port restrictions and authorization window. Note what is
   explicitly excluded.
2. **Recon** — passive first, then active. Passive subdomain and DNS
   collection, then HTTP probing. Every host you learn is recorded in the
   surface index.
3. **Enumeration** — port scans, then service scans on open ports, then web
   enumeration: crawl, content discovery, directory and file brute force.
   Narrow as you go: do not fuzz a host you have not confirmed is in scope.
4. **Validation** — test hypotheses from the surface. Vulnerability scanning,
   targeted injection and XSS testing, secret and credential audit. A scanner
   result is a hypothesis, not a finding, until you reproduce it.
5. **Exploitation** — only for confirmed, in-scope findings, and only to the
   depth needed to prove impact. Use a minimal proof of concept. Get approval
   before anything intrusive.
6. **Evidence** — capture reproducible evidence for every confirmed finding:
   the command, the timestamp, the artifact path, the affected target. Write
   the finding with `cyber_record_finding` as soon as it is confirmed, not at
   the end.
7. **Reporting** — build the deliverable with `cyber_report` and write the
   executive summary: what was tested, what was found, what it means for the
   client, what to fix first.

The full checklist with per-phase exit criteria is in
`references/scope-and-phases.md`.

## Evidence discipline

- Record a finding only when you have reproduced it. State the exact target,
  the exact request or command, and what came back.
- Keep raw output in the artifact directory. The journal entry points at the
  artifact file; the transcript gets the summary.
- One finding per issue. Merge duplicates across hosts into one finding with
  multiple affected targets.
- Severity follows impact and exploitability, not scanner severity. Recalculate
  before reporting.
- Never modify a recorded finding to hide a failed reproduction. Mark it
  confirmed only on evidence.

## Status updates

When the operator asks for a status update, answer from the journal and the
surface index, not from memory:

1. `cyber_surface` for hosts, services and endpoints discovered.
2. `cyber_journal` for what was run, against what, and what was blocked.
3. The findings directory for confirmed issues.

Report: engagement name and phase, scope coverage (what was in scope and what
was skipped), findings by severity, blocked actions waiting on the operator,
and the next actions you plan to take. Keep it to the point.

## The CyberPi tools

Every tool below is scope-checked and journalled by the shared toolkit, the
local reporting tools at the end excepted. Read the tool's own schema for its
parameters; do not guess argument names. Techniques are the scope-level
identifiers the tools declare.

**Recon** — `cyber_subdomain` (subfinder), `cyber_dns` (dig), `cyber_whois`
(whois), `cyber_http_probe` (httpx), `cyber_capture` (tcpdump). Technique
`recon`. `cyber_subdomain` and `cyber_dns` for passive discovery,
`cyber_http_probe` to turn hosts into live web targets, `cyber_whois` for
registration and netblock data, `cyber_capture` only when packet capture is
explicitly needed.

**Network** — `cyber_portscan` (naabu, technique `port-scan`),
`cyber_service_scan` (nmap, technique `service-enumeration`). Scan first,
then fingerprint services only on the ports that answered. Use
`cyber_portscan` for a fast reachability sweep and `cyber_service_scan` for
version and script detail on specific hosts and ports.

**Web** — `cyber_crawl` (katana), `cyber_dir_enum` (ffuf), technique
`web-testing`. `cyber_crawl` maps reachable paths, `cyber_dir_enum` tests
specific paths and words against a known host. `cyber_http_probe` is the
entry point: crawl and enumerate hosts it confirmed.

**Vulnerability** — `cyber_vuln_scan` (nuclei, technique
`vulnerability-scan`), `cyber_sqli` (sqlmap), `cyber_xss` (dalfox), technique
`web-testing` for the last two. Scan is a hypothesis generator. Confirm every
hit manually before it becomes a finding.

**Exploitation** — `cyber_exploit_search` (searchsploit), `cyber_exploit_run`
(msfconsole), `cyber_poc` (curl), technique `exploit`. Search for the module,
read what it does, then run it only against a confirmed in-scope target.
`cyber_poc` builds a minimal, repeatable proof request and is the default for
demonstrating impact without running a payload.

**Credentials** — `cyber_hash_id` (hashcat), `cyber_hash_crack` (hashcat),
`cyber_password_audit` (hydra), `cyber_secret_scan` (trufflehog), technique
`password-audit`. Identify a hash before cracking it, audit only against
services the scope allows, and scan for secrets in repositories the client
provided. Report counts and locations, never the material.

**Active Directory** — `cyber_ad_enum` (ldapdomaindump),
`cyber_ad_attack` (impacket-smbserver), technique `active-directory`. Enumerate
first. Treat relay and impersonation as intrusive: get approval first.

**Wireless** — `cyber_wireless_scan` (airodump-ng), `cyber_wireless_crack`
(aircrack-ng), technique `wireless`. Only with a monitor-mode-capable
adapter, and only for networks the client owns.

**IoT and hardware** — `cyber_iot_scan` (nmap), `cyber_firmware_analysis`
(binwalk), `cyber_hid_attack` (hidrd), technique `iot-hardware`. Read firmware
offline from an image you were given. Never flash, and never write to a
physical device without explicit approval.

**Infrastructure** — `cyber_pivot` (chisel, technique `pivot`),
`cyber_cloud_enum` (aws, technique `cloud-enumeration`). Pivot only through a
host you have already compromised and the operator has approved as a pivot
point. Cloud enumeration is read-only by default; creating keys, policies or
roles is out of bounds without approval.

**CVE intelligence** — `cyber_cve_lookup`, `cyber_cve_sync` (technique
`vulnerability-scan`), `cyber_exploit_map` (technique `exploit`). These query
the local offline database and touch no target, but they still declare a
technique, so an engagement allowlist that omits it blocks them. Sync when the
database is stale, look up a CVE when a banner gives you a version, and map a
CVE to public exploits before deciding how to validate it. The database is
offline: run `cyber_cve_sync` to refresh it, and note that a missing CVE is a
gap in the mirror, not proof that a product is unaffected.

**Reporting and state** — `cyber_record_finding`, `cyber_report`,
`cyber_journal`, `cyber_surface`. These are local tools: no scope check, no
network. Record findings as you confirm them, read the journal for the
engagement record, read the surface index before re-scanning, and build the
report at the end.
