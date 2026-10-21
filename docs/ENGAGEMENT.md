# CyberPi engagement manual

## 1. Purpose

This is the operating manual for a client engagement run with CyberPi. It
covers the work from the first scoping call to the closure of the engagement:
the rules of engagement, the scope definition, evidence handling, the
communication plan, the daily and final reporting formats, and the closure
checklist.

It is written for a professional consulting team — engagement manager,
technical lead and tester. It assumes the team is competent and the client is
a business, not a hobbyist. Where a practice is a legal or contractual
requirement rather than a preference, it says so.

CyberPi does not replace any of this. The harness is an instrument; the
engagement is a professional process that the instrument serves. The scope
file (`.cyberpi/scope.json`) is the machine-readable form of the Rules of
Engagement — if the two disagree, the RoE wins and the scope file is wrong.

Pair this document with `docs/SECURITY.md`, which covers the security model of
the harness itself, and `docs/TOOL-REGISTRY.md`, which is the authoritative
list of what the tools do.

## 2. Roles

| Role | Owns | Does not own |
|---|---|---|
| **Engagement manager (EM)** | The RoE, the client relationship, the authorization letter, the daily and final reports, the commercial timeline. | Technical execution. |
| **Technical lead (TL)** | The scope file, the method and intensity, the finding severity ratings, the review of every finding before it goes to the client. | The commercial relationship. |
| **Tester** | Running the harness, keeping the journal and artifacts, capturing findings as they are proven. | Deciding what is in scope — the tester proposes, the TL and EM approve. |
| **Client sponsor** | Business acceptance of the findings, prioritisation of remediation, the decision to disclose. | Technical validation. |
| **Client technical contact** | Day-to-day operational questions, approvals for individual actions, escalation of false positives. | The commercial relationship. |

**Rule:** no tester changes the scope. If the work requires a target, a
technique or a window that is not in the signed RoE, the tester stops, records
the request, and the EM obtains written approval from the client sponsor.
Approved additions are added to the RoE and to `scope.json` before the action
is taken, never after.

## 3. Engagement lifecycle

| Phase | Typical duration | Outcome |
|---|---|---|
| 0. Scoping and authorization | 1–2 weeks | Signed RoE, completed scope worksheet, engagement plan. |
| 1. Environment preparation | 1–2 days | Harness installed, toolchain verified, engagement directory created, scope file reviewed. |
| 2. Passive reconnaissance | 1–2 days | External asset inventory from sources that generate no traffic to the client. |
| 3. Active reconnaissance and enumeration | 2–4 days | Port, service and application inventory; `surface.json` populated. |
| 4. Vulnerability analysis and validation | 3–5 days | Findings confirmed by hand, severity agreed, CVE and CWE assigned. |
| 5. Controlled exploitation (if authorized) | 1–3 days | Proof of impact, under a controlled technique allowlist. |
| 6. Reporting | 2–3 days | Draft report, client walkthrough, final report. |
| 7. Closure | 1 day | Evidence handover, credential revocation, retrospective, destruction schedule. |

Phases 2 and 3 are where most of the engagement's value is produced and where
most of the accidental risk is. Phases 4 and 5 are where the report is won
or lost, and where scope discipline matters most.

## 4. Rules of engagement

The RoE is a document the client signs. It is not a checklist the team ticks
off; it is the contract under which every network packet is sent.

### 4.1 Required contents

Every engagement has a written RoE containing at least:

1. **Authorization.** A statement of what the client authorizes, the name and
   role of the person granting it, the date, and the engagement reference.
2. **Scope.** The targets, ports, protocols and techniques authorized, using
   the same vocabulary as the scope worksheet in section 5.
3. **Time window.** Start and end date and time, in the client's timezone.
   Testing outside the window is testing without authorization.
4. **Out of scope.** Explicitly named exclusions, especially third parties.
5. **Third parties.** Hosting providers, CDNs, SaaS platforms, upstream
   suppliers and any shared infrastructure the client's assets depend on.
6. **Permitted techniques.** Enumerated by the harness's technique vocabulary.
7. **Prohibited actions.** A closed list. Default prohibitions are: denial of
   service, social engineering of client staff, physical testing, testing of
   third-party systems, and exfiltration of bulk personal data.
8. **Data handling.** Where evidence is stored, who may access it, the
   retention period, and the destruction method.
9. **Communication plan.** The contacts, channels, cadence and escalation
   route in section 7.
10. **Emergency and stop conditions.** Section 4.4.

### 4.2 Safe harbour

The RoE should contain a safe-harbour statement in the client's words, or
close to it. The purpose is to protect the client and the team from being
treated as attackers by the client's own monitoring, IDS, ISP or cloud
provider. The client should be asked to allow-list the testing source
addresses for the duration of the window, and to suppress or annotate the
resulting alerts.

A safe-harbour clause does not help if the team is operating outside the
scope. Scope compliance *is* the safe harbour.

### 4.3 Techniques

The harness's technique vocabulary is fixed. These are the values that go
into the `techniques` array of the scope file:

| Technique | Covers |
|---|---|
| `recon` | Subdomain discovery, DNS, WHOIS, passive work, HTTP probing, packet capture. |
| `port-scan` | Port discovery (TCP/UDP sweeps). |
| `service-enumeration` | Service and version detection on open ports. |
| `web-testing` | Crawling, content discovery, injection and XSS testing. |
| `vulnerability-scan` | Automated vulnerability scanners, CVE lookup and correlation. |
| `exploit` | Exploit search, execution, proof-of-concept development. |
| `password-audit` | Credential audits: password policy review, hash identification and cracking, secret scanning. |
| `privilege-escalation` | Local privilege escalation attempts. |
| `active-directory` | AD enumeration and AD attack paths. |
| `pivot` | Pivoting and tunnelling into segmented networks. |
| `wireless` | Wireless network assessment. |
| `iot-hardware` | IoT device, firmware and HID testing. |
| `cloud-enumeration` | Cloud asset enumeration. |
| `forensics` | Forensic analysis of supplied media and images. |
| `social-engineering` | Phishing and human-factor testing. |

**Default posture:** authorize `recon`, `port-scan`, `service-enumeration` and
`web-testing` on every engagement. Everything else is opt-in, per technique,
with a named justification in the RoE. `exploit`, `password-audit`,
`social-engineering` and `privilege-escalation` are never enabled by default.
`pivot` requires an explicit network diagram and an explicit statement about
which segments are reachable.

Note that the technique allowlist is a *ceiling*, not a permission. A target
that is not in scope is refused even when the technique is allowed, and a
technique that is not on the list is refused everywhere.

### 4.4 Stop conditions and emergency procedures

The RoE must state what happens when something goes wrong. The default
CyberPi posture is:

- **Stop and notify, do not self-correct.** If a scan causes an outage, a
  performance degradation, a data loss, or an alert in a client monitoring
  system that the client has not been told to expect, the tester stops
  testing against that target, preserves the evidence, and notifies the
  client technical contact immediately — not at the next daily report.
- **Do not remediate.** The team finds and reports; it does not patch, restart,
  reboot or reconfigure client systems, even when the fix is obvious and the
  client would welcome it. An unauthorized change is a change nobody
  authorized.
- **Out-of-window is a stop.** If the window closes, testing stops. A window
  extension is a written amendment, not a verbal one.
- **Unexpected third-party contact is a stop** for that line of testing.
  A target that turns out to be hosted on a third party's infrastructure, or
  that resolves to a third party's address, is not automatically in scope.
  Note it, stop touching it, and ask.
- **Production impact thresholds.** Agree numeric thresholds in advance:
  maximum request rate, maximum concurrent connections, maximum data volume,
  maximum CPU/load on the target that the team will tolerate. When a
  threshold is reached, back off and re-validate with the client.

### 4.5 Prohibited by default

| Action | Why |
|---|---|
| Denial of service, stress testing, resource exhaustion | Availability risk; almost never necessary to prove a finding. |
| Social engineering of client employees | Employment and privacy exposure; requires a separate written agreement. |
| Physical security testing | Separate skill set and separate authorization. |
| Testing third-party or shared infrastructure | The client usually cannot authorize it. |
| Persistence installation, ransomware simulation, destructive payloads | Risk to the client's operations that no finding justifies. |
| Bulk exfiltration of personal data | Data-protection exposure for the client. Prove access, do not harvest. |
| Testing production outside the window | Contractual breach. |

## 5. Scope definition worksheet

This worksheet is completed **with the client**, during scoping, and becomes
section 2 of the RoE. The right-hand column is how the same thing is expressed
in `.cyberpi/scope.json`.

### 5.1 Targets

| Field | Value |
|---|---|
| Client legal name | |
| Engagement name (use as the directory name) | |
| Engagement reference / PO | |
| Primary target(s) | |
| Secondary targets (other environments, staging, subsidiaries) | |
| IP ranges owned by the client | |
| Domains owned by the client | |
| Wildcard scope (subdomains of which domain?) | |
| Explicitly excluded hosts within the client's estate | |
| Number of targets expected | |

Notes on the forms that matter:

- A bare domain such as `acme.example` covers the apex **and every
  subdomain**. That is frequently wider than the client intends. Prefer
  `*.acme.example` (subdomains only) plus `exact:acme.example` (apex only)
  when the intent is to be precise.
- CIDR notation such as `10.20.0.0/24` covers an entire range. Confirm the
  range with the client's network team; a `/24` of "spare" addresses in a
  customer's cloud account is not the client's to scan.
- Exclusions are as important as inclusions. Write them into the rules as
  notes and keep them out of the target list; the harness has no deny list.

### 5.2 Ports and protocols

| Field | Value |
|---|---|
| Ports in scope | |
| Ports explicitly excluded | |
| Protocols in scope (tcp, udp) | |
| Full TCP sweep (1–65535) authorized? | |
| UDP scanning authorized? (expensive, noisy) | |
| Source address for the test (static or NAT egress) | |
| Rate limit agreed (packets per second, requests per second) | |
| Any source ports or destination port ranges reserved by the client | |
| Non-standard ports in use that are not obvious | |

### 5.3 Applications and protocols

| Application | In scope | Notes / constraint |
|---|---|---|
| Web (HTTP/HTTPS) | | Production, staging, APIs, admin consoles? |
| APIs (REST, GraphQL, gRPC) | | Authentication handling — are tokens issued per environment? |
| Email (SMTP/IMAP/POP) | | |
| DNS | | Authoritative nameservers only, or recursors too? |
| Remote access (RDP, SSH, VPN) | | |
| Databases exposed to the internet | | |
| File transfer (SFTP, FTP) | | |
| Cloud storage (S3, Azure Blob, GCS) | | |
| Authentication / SSO providers | | Usually third party — see 5.6. |
| IoT / OT / ICS | | Often a separate engagement and a separate safety plan. |
| Active Directory | | |
| Wireless | | Requires a site visit; usually a separate scope. |

### 5.4 Authentication testing

| Question | Answer |
|---|---|
| Are default and weak credentials in scope for testing? | |
| Is password spraying authorized? (one password against many accounts) | |
| Is password spraying rate-limited or single-domain only? | |
| Is credential auditing of hashes in scope? | |
| Which accounts may be targeted: domain, local, SaaS, database, network device? | |
| Are production user accounts in scope, or only test accounts? | |
| Are lockout thresholds known, and what is the client-side impact of a lockout? | |
| Is MFA bypass / relay testing in scope? | |
| May credentials be used to authenticate to other in-scope systems? | |
| Must recovered credentials be revoked at the end? | |

### 5.5 Time window and intensity

| Field | Value |
|---|---|
| Start date and time (client timezone) | |
| End date and time (client timezone) | |
| Permitted days and hours | |
| Blackout periods (change windows, freezes, board meetings) | |
| Maintenance window usage permitted? | |
| Maximum request rate | |
| Maximum concurrent connections | |
| Maximum data volume transferred | |
| Agreed target-side impact ceiling | |
| Weekend / out-of-hours testing permitted? | |

### 5.6 Third parties and dependencies

This section prevents the most common source of accidental out-of-scope
traffic. Complete it with the client, and do not assume.

| Third party | Relationship | In scope? | Action required |
|---|---|---|---|
| Cloud provider (AWS/Azure/GCP) | Hosts client assets | | Ask the client for a read-only role or a test account; never use production credentials. |
| CDN / WAF provider | Fronts client web assets | | Do not scan the CDN edge; scan the origin. |
| DNS registrar / authoritative DNS | | | |
| Certificate authority | | | |
| SaaS tenants (Okta, Auth0, Salesforce, Workday) | | | Usually out of scope. |
| Payment processor | | | |
| CDN-hosted assets on shared infrastructure | | | |
| Managed service providers (MSP) | Operates client estate | | Confirm the MSP's own rules; the client may not control the upstream. |
| Internet transit / ISP | | | |
| Open source dependencies / upstream projects | | | Report upstream, do not test upstream. |

### 5.7 Out of scope (explicit)

| Item | Reason | Notes |
|---|---|---|
| | | |
| | | |
| | | |

### 5.8 Translating the worksheet into `scope.json`

```jsonc
{
  "engagement": "acme-web-pentest-2025-03",
  "client": "Acme Corp",
  "authorization": {
    "statement": "Authorization letter AC-2025-03 signed by J. Doe, CISO, dated 2025-03-01.",
    "authorizedBy": "J. Doe, CISO",
    "start": "2025-03-10T00:00:00Z",
    "end": "2025-03-21T23:59:59Z"
  },
  "techniques": ["recon", "port-scan", "service-enumeration", "web-testing", "vulnerability-scan"],
  "allowSelfTest": true,
  "rules": [
    { "id": "web-tier", "target": "10.20.0.0/24", "ports": [80, 443, 8080, 8443], "protocols": ["tcp"], "notes": "Production web tier" },
    { "id": "staging", "target": "*.staging.acme.example", "notes": "Staging subdomains" },
    { "id": "apex", "target": "exact:acme.example", "notes": "Corporate apex, no subdomains" }
  ],
  "notes": "Public IP range 198.51.100.0/24 excluded by client request. No UDP scanning."
}
```

**Review gate:** the technical lead compares this file line by line against
the signed RoE, and the engagement manager confirms it against the
authorization letter, **before the first packet is sent**. A second pair of
eyes is the cheapest control in the entire process.

The harness enforces the file, but only the humans ensure the file is right.
An over-broad scope file is enforced perfectly and is still a breach.

## 6. Evidence handling

### 6.1 What counts as evidence

| Type | Where it lands | Notes |
|---|---|---|
| Raw tool output | `.cyberpi/artifacts/<label>.txt` | Written when the tool labels its run plan. This is the primary evidence. |
| Action log | `.cyberpi/journal.jsonl` | The audit trail: what ran, against what, when, with what exit code. |
| Findings | `.cyberpi/findings/F-00N.md` | The written record of what was proven. |
| Surface index | `.cyberpi/surface.json` | The reconciled inventory: hosts, services, endpoints. |
| Notes | `.cyberpi/notes/` | Free-form working notes, screenshots referenced, reasoning. |
| Reports | `.cyberpi/reports/` | Generated deliverables. |
| Captures | `.cyberpi/artifacts/` | Packet captures. Git-ignored as `*.pcap`/`*.pcapng`; treat as high sensitivity. |

### 6.2 Handling rules

1. **Collect only what is needed.** Preserve the artifact that demonstrates the
   finding, not the entire scan output of a five-hour engagement. Over-
   collection is a data-protection problem for the client.
2. **Never collect personal data beyond what a finding requires.** If a
   directory listing exposes a page of customer records, capture the listing,
   not the records.
3. **Never put credentials in the transcript, in a finding, or in a report.**
   The rule, its rationale, and the consequences are in `docs/SECURITY.md`
   section 8. A finding says *what* was found and *where*; the value stays in
   the evidence store.
4. **Chain of custody.** Record the collection time, the tool that produced
   the artifact, and the operator. The journal carries the first two
   automatically. Keep a copy of the artifact in the client's evidence store
   before it can be altered.
5. **Preserve originals, work on copies.** Do not reformat, trim or
   "clean up" a raw artifact. Derived material goes in a separate file with a
   name that says so.
6. **Hash the deliverables.** When the final report is issued, record its
   SHA-256 in the handover record, so the client can prove which version they
   received.
7. **Do not upload evidence to third-party services.** No paste sites, no
   personal cloud storage, no shared links. Evidence goes to the client's
   system or the agreed consulting store, and nowhere else.
8. **The engagement directory is the working set, not the archive.** At the
   end of the engagement the directory is handed over or destroyed per the
   RoE; it is not left on a laptop.

### 6.3 The engagement directory

```
acme-web-pentest-2025-03/
└── .cyberpi/
    ├── scope.json        # the authorization, machine-readable
    ├── journal.jsonl     # the audit trail, append-only
    ├── surface.json      # the reconciled inventory
    ├── artifacts/        # raw tool output, packet captures
    ├── findings/         # F-001.md, F-002.md, ...
    ├── notes/            # working notes
    ├── reports/          # generated reports
    └── cache/            # cached results; clear before archiving
```

Set `umask 077` before creating it, and confirm the directory is not inside a
Git working tree that the team pushes to a shared remote.

## 7. Communication plan

### 7.1 Contacts

| Role | Name | Organization | Email | Phone | Availability |
|---|---|---|---|---|---|
| Client sponsor | | | | | |
| Client technical contact | | | | | |
| Client security operations | | | | | |
| Client legal / contracts | | | | | |
| Engagement manager (ours) | | | | | |
| Technical lead (ours) | | | | | |
| Tester (ours) | | | | | |

### 7.2 Channels

| Channel | Use | Notes |
|---|---|---|
| Email | Authorizations, approvals, the daily report, the final report. | The record of record. Anything not in email did not happen. |
| Chat / phone | Day-to-day coordination, urgent operational issues. | Never the channel for an authorization or an approval; follow up in email. |
| Ticketing system | Findings during and after the engagement, if the client uses one. | Contains client-confidential data — check where it is hosted. |
| Encrypted file transfer | Evidence handover. | Confirm the client's accepted mechanism in advance. |

**Never** use a consumer messaging application for client evidence, findings or
credentials, and never use a personal account for client communications.

### 7.3 Cadence

| Rhythm | What | Who |
|---|---|---|
| Daily report | End of each testing day (section 8) | EM to client sponsor, cc technical contact |
| Daily internal sync | 15 minutes, end of day | Team only |
| Kick-off meeting | Before testing starts | All parties |
| Mid-engagement check-in | Around 50% of the window | EM, TL, client sponsor |
| Findings walkthrough | Before the final report | TL, client technical contact |
| Final report presentation | At the end of the window | EM, TL, client sponsor |

### 7.4 Escalation

| Level | Trigger | Action | Timeframe |
|---|---|---|---|
| **L1 — Tester** | Tool failure, unexpected output, a target that looks out of scope | Stop that line of testing, record it, ask the TL | Immediately |
| **L2 — Technical lead** | Proposed scope extension, technique change, a suspected false positive the scanner cannot settle | Decide and document; request EM approval for scope changes | Same day |
| **L3 — Engagement manager** | Scope extension request, client impact, a reportable event, a change to the timeline | Contact the client sponsor | Same day, or immediately for impact |
| **L4 — Client sponsor** | Anything affecting production, any incident, any legal question | Direct contact, with the EM | Immediately |

**Contact the client first.** If testing causes an outage, the client's
operations team hears about it from the client, not from their own monitoring
alert. That single rule prevents most escalations from becoming incidents.

### 7.5 Notifications to the client

The client must be told, promptly and by the agreed channel, when:

- a target is found to be outside the intended scope;
- a third party is contacted, or appears to be affected;
- production performance is degraded by the testing;
- the client's monitoring or IDS generates alerts attributable to the test;
- credentials, tokens, keys or personal data are found;
- the window is about to close with work outstanding;
- any stop condition in section 4.4 is triggered.

## 8. Daily report format

One report per testing day. It is short, factual, and written for a manager
who was not in the room. It is written even on days when nothing was found —
"no findings, all planned work completed" is a report.

```markdown
# Daily Report — <Engagement Name>

**Date:** 2025-03-12 (day 3 of 10)   **Prepared by:** <name>   **Classification:** Client Confidential

## 1. Summary
Two to four sentences. What was found, whether anything needs the client's
attention today, and whether the plan is still on track.

## 2. Client attention required
| Item | Severity | What we need | By when |
|---|---|---|---|
| Credential found for svc_backup on db-01 | High | Client to confirm the account is active and rotate it | 2025-03-13 |

If there is nothing, write "None." Do not omit the section.

## 3. Work completed
- Passive reconnaissance: 412 subdomains enumerated across 4 domains, 38
  confirmed as in scope (source: subfinder, cert transparency).
- Port scan of 10.20.0.0/24 (tcp/1-1024, 800 pps): 6 hosts, 14 open ports.
- Service enumeration on 6 hosts: Apache 2.4.29, nginx 1.22, OpenSSH 8.4p1.
- HTTP probing of 22 endpoints; 3 flagged for further analysis.
- Directory enumeration on app.acme.example (rate 50 req/s, wordlist
  dirbust-medium): 4 paths of interest.

## 4. Findings to date
| ID | Title | Severity | Target | Status | Notes |
|---|---|---|---|---|---|
| F-001 | Default credentials on management console | High | mgmt.acme.example | Confirmed | Evidence in artifacts/mgmt-console.txt |
| F-002 | TLS certificate expired | Low | acme.example | Confirmed | Not validated for exploitability |
| F-003 | Server version disclosure | Info | 10.20.0.11 | Open | Awaiting validation |

## 5. Scope notes and deviations
- 10.20.0.44 redirects to 198.51.100.20 (third-party hosted service).
  Not tested. Requested client guidance.
- Requested and received approval to extend the port range to 1-65535 on
  10.20.0.11 only (EM, 2025-03-12).

## 6. Coverage
| Target | Recon | Ports | Services | Web | Auth | Vuln scan |
|---|---|---|---|---|---|---|
| 10.20.0.0/24 | Complete | Complete | Complete | Complete | Not in scope | Complete |
| *.staging.acme.example | Complete | Complete | Partial (time) | Complete | Not in scope | Pending |

## 7. Next 24 hours
- Validate F-001 manually and capture evidence.
- Complete service enumeration on the remaining staging hosts.
- Re-test certificate expiry remediation (client expects a fix today).

## 8. Notes / blockers
- Scanner rate held to 800 pps per the agreed ceiling. No client complaints.
```

Rules for the daily report:

- **Never include credentials, tokens, keys or personal data.** Refer to the
  finding ID and the artifact path.
- **State what was not done.** Coverage gaps are the first thing a client
  asks about and the last thing a team volunteers.
- **Deviations go in section 5, the same day.** A deviation discovered on
  day 8 must not appear for the first time in the final report.
- **No finding enters the report without a status of `open` or `confirmed`
  and an evidence path.** The technical lead owns the severity rating.
- Keep it under two pages. Detail belongs in the findings and the journal.

## 9. Severity rating

### 9.1 Method

Findings are rated with **CVSS v3.1 base score** as the technical anchor, and
a **business impact rating** as the engagement anchor. The final severity is
the higher of the two, except where the CVSS vector is not applicable (for
example a purely procedural weakness), in which case the business impact
rating alone determines the severity.

CVSS is used because it is comparable, defensible, and familiar to the client.
It is not used alone because CVSS has no concept of the client's business, and
a well-CVSS-scored finding on an asset nobody uses is not a high-severity
finding for that client.

### 9.2 CVSS v3.1 qualitative rating scale

| Score | Rating | CyberPi `severity` |
|---|---|---|
| 0.0 | None | `info` |
| 0.1 – 3.9 | Low | `low` |
| 4.0 – 6.9 | Medium | `medium` |
| 7.0 – 8.9 | High | `high` |
| 9.0 – 10.0 | Critical | `critical` |

The harness uses exactly this vocabulary for `severity`, so the rating in the
report and the rating in the finding file are the same word.

### 9.3 Rating rules

- Score the **base vector only**. Do not modify the vector to reflect
  environmental or temporal metrics. If the client's environment changes the
  real risk, express that in the business impact column, not in the vector.
- Score the vulnerability **as it exists on the client's system**, with the
  client's actual configuration — not the vendor's default. An endpoint
  manager that patches within 48 hours is a different finding from one that
  never patches.
- If the finding is **not exploitable as configured**, say so in the
  description and score the underlying weakness. Do not inflate a finding
  that was not proven.
- A finding that could not be validated is rated `open` and carries a
  provisional severity, marked as provisional in the report.
- **Informational findings** (version disclosure, missing headers) are rated
  `info` and are aggregated in the report rather than listed individually,
  unless the client asked otherwise. Do not use `info` findings to pad the
  report.

### 9.4 Severity and business impact matrix

| Severity | CVSS | Typical examples | Business impact | Client response |
|---|---|---|---|---|
| **Critical** | 9.0 – 10.0 | Unauthenticated remote code execution; SQL injection leading to full database access; authentication bypass on a customer-facing application. | Compromise of the client, its data and potentially its customers. Regulatory notification likely. | Fix immediately. 24-hour remediation plan. Consider temporary mitigation. |
| **High** | 7.0 – 8.9 | Authenticated RCE; privilege escalation to domain admin; stored XSS in an authenticated application; default credentials on an internet-facing management interface. | Significant breach of a system or a tier of data; lateral movement. | Fix within 7 days, or mitigate. Retest. |
| **Medium** | 4.0 – 6.9 | Reflected XSS; missing security headers on sensitive pages; weak cipher suites; information disclosure of internal hostnames; password policy weaknesses. | Exploitation requires a condition the client may or may not have. Limited direct breach. | Fix within 30 days. Prioritise if the affected asset is sensitive. |
| **Low** | 0.1 – 3.9 | Verbose error messages; missing cookie flags with limited impact; version disclosure; clickjacking on a low-value page. | Minimal direct impact. Useful to an attacker in combination with other findings. | Fix within 90 days or accept. |
| **Info** | 0.0 | Hardening observations; best-practice deviations; no demonstrated weakness. | No direct impact. | Backlog. |

**Business impact rating** — assign one to every finding, and use it to raise
the CVSS anchor where the client's context demands it. The final severity is
the higher of the two; a business impact *below* the CVSS rating is recorded
as context in the report, not used as a downgrade:

| Rating | Definition |
|---|---|
| **Severe** | The finding alone leads to compromise of the client, its data, or its customers; or it exposes a regulated data class at scale. |
| **Significant** | The finding compromises an important system, a tier of internal data, or a substantial number of users. |
| **Moderate** | The finding compromises a limited asset, requires a precondition the client is unlikely to meet, or affects non-sensitive data. |
| **Minimal** | The finding is a hardening gap with no demonstrated path to compromise. |
| **None** | Informational. |

The mapping is: `critical`/`high`/`medium`/`low`/`info` are the CyberPi
severity vocabulary, and the business impact maps as Severe→Critical,
Significant→High, Moderate→Medium, Minimal→Low, None→Info.

### 9.5 Worked example

> **F-001: Default credentials on the internet-facing management console**
> Target: `mgmt.acme.example:8443`
> CVSS v3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` → **9.1 — Critical**
> Business impact: **Severe**. The console manages the production web tier,
> so a compromise is a compromise of the tier, not of a side system.
> Final severity: **Critical**
> Evidence: `artifacts/mgmt-console.txt` (screenshot of the authenticated
> dashboard), `artifacts/mgmt-console-repro.txt` (login transcript).
> Note: the credential itself is **not** in the finding, the report or the
> daily report. The client has been notified separately and has confirmed it
> has been rotated.

### 9.6 Recording a finding

Findings are Markdown files with YAML frontmatter in `.cyberpi/findings/`,
allocated sequentially as `F-001`, `F-002`, … The harness writes this format
and the report generator reads it, so a finding captured during the session is
already half of the final report.

````markdown
---
id: F-001
title: "Default credentials on the internet-facing management console"
severity: critical
cvss: 9.1
cwe: "CWE-798"
target: "mgmt.acme.example:8443"
status: confirmed
tags: ["authentication", "default-credentials", "critical"]
references: ["https://cwe.mitre.org/data/definitions/798.html"]
createdAt: "2025-03-12T14:22:05.000Z"
updatedAt: "2025-03-12T14:22:05.000Z"
---

# Default credentials on the internet-facing management console

## Description

The management console at `mgmt.acme.example:8443` accepted a vendor default
credential pair on 2025-03-12 without a lockout counter and without MFA. The
console provides full administrative control over the production web tier.

## Impact

An unauthenticated attacker with knowledge of the default credential can take
full administrative control of the production web tier, including deployment
configuration and the ability to inject content into customer-facing
applications.

## Reproduction

```bash
cyberpi new acme-web-pentest-2025-03
# set the target in .cyberpi/scope.json, then:
# authenticate to https://mgmt.acme.example:8443 using the documented
# vendor default credential and observe the administrative dashboard.
```

## Evidence

- artifacts/mgmt-console.txt
- artifacts/mgmt-console-repro.txt
````

Fields the client relies on:

| Field | Rule |
|---|---|
| `title` | A short noun phrase naming the weakness, not the tool that found it. Never "nuclei found an SSTI". |
| `severity` | The final severity from section 9.4. |
| `cvss` | The base score, to one decimal, with the vector written in the description. |
| `cve` / `cwe` | Assigned when the weakness maps to a public identifier. `cwe` is usually more useful than `cve` for a configuration weakness. |
| `target` | The exact host, and the port where relevant. |
| `status` | `open` (reported by a scanner, not validated), `confirmed` (validated by hand), `reported` (accepted into the final report). |
| `description` | What the weakness is, on this system, in plain language. No CVSS vector string in place of prose. |
| `impact` | What an attacker gains, in the client's terms. |
| `reproduction` | The steps, as a command block, that a competent third party can follow. |
| `evidence` | Paths to the artifacts, relative to the engagement directory. |
| `references` | Public references for the weakness class. |

## 10. Final deliverable checklist

The final report is the deliverable. A finding the client cannot act on is
not delivered work. Before issuing, confirm every item.

### 10.1 Content

- [ ] Executive summary written for a non-technical reader: what was
      assessed, what was found, what it means for the business, what to do
      about it.
- [ ] Scope statement, matching the signed RoE, including what was
      **not** tested and why.
- [ ] Methodology, described at the level of "what was done", not a tool
      inventory.
- [ ] Findings, one section per finding, in severity order, each with
      description, impact, evidence reference, reproduction, and a
      recommendation.
- [ ] Every finding has a severity, a CVSS vector, and a business impact
      rating — and the two are consistent with section 9.4.
- [ ] Every finding has a real, reachable evidence path. Dead evidence
      references are a credibility failure.
- [ ] No credential material, tokens, keys, cookies or personal data in the
      report body, in an appendix, or in an embedded screenshot.
- [ ] Screenshots reviewed individually for accidental disclosure before
      inclusion.
- [ ] Informational findings aggregated into a single section, with a total
      count.
- [ ] A prioritised remediation plan: what to fix in 24 hours, 7 days,
      30 days, and what to accept.
- [ ] A section on what was out of scope and what remains untested, so the
      reader does not over-trust the result.
- [ ] Limitations of the assessment stated plainly (rate limiting, access
      constraints, untested environments, unauthenticated coverage).
- [ ] Appendices: the scope file, the tool inventory, and an evidence index
      (finding ID → artifact path).

### 10.2 Quality

- [ ] Every finding has been read by the technical lead, and every severity
      rating is agreed.
- [ ] The client technical contact has walked through the reproduction steps
      for every high and critical finding and confirmed they reproduce.
- [ ] False positives have been removed, not softened.
- [ ] A spot check of the reproduction steps has been performed from a clean
      session, against the stated evidence.
- [ ] Internal consistency check: the summary counts match the findings
      table; the CVSS vector matches the score; the dates in the journal match
      the report.
- [ ] Spell-check, and the client's product names written as the client
      writes them.
- [ ] The report does not describe the harness's internals, the AI workflow,
      or the scanner names beyond a brief methodology note. The client asked
      for an assessment, not a product tour.
- [ ] Confidentiality marking applied; distribution list agreed with the
      client.
- [ ] File name and version match the delivery register; SHA-256 recorded.

### 10.3 Delivery

- [ ] Delivered through the agreed channel, to named recipients, before the
      agreed date.
- [ ] Delivery acknowledged in writing by the client.
- [ ] A hard copy of the final report archived in the engagement record
      alongside the RoE, the journal and the evidence index.
- [ ] The client has the finding list in their ticketing system, if they use
      one, with the correct statuses.

## 11. Closure checklist

Closure is the part that gets skipped and the part that is remembered. The
engagement is not over when the report is delivered; it is over when the
credentials are rotated, the evidence is handed over, and the working
environment is clean.

### 11.1 Client-side actions to confirm

- [ ] Every credential, key, token or secret found during the engagement has
      been rotated, revoked or disabled — confirmed by the client in writing.
- [ ] Default accounts and vendor accounts that were found are removed or
      have their credentials changed.
- [ ] Accounts that were locked out by credential testing are unlocked.
- [ ] Any persistence, listener or test service the team deployed has been
      removed (impacket SMB server, chisel tunnels, test web servers).
- [ ] Source IP allow-listing added for the test window has been removed.
- [ ] IDS/WAF exclusions and suppressions added for the test have been
      reverted.
- [ ] Logs and alerts generated during the engagement are retained or
      discarded at the client's discretion.

### 11.2 Evidence handover

- [ ] The complete engagement directory is handed to the client's evidence
      store, or to the agreed consulting store, with a handover record.
- [ ] The handover record lists every artifact by path with its SHA-256 hash.
- [ ] The client's acceptance of the evidence transfer is recorded.
- [ ] Any evidence the client asked to be withheld is removed and the
      removal is recorded.
- [ ] The final report, its SHA-256 and the delivery date are in the handover
      record.
- [ ] A retention period and a destruction date are agreed and recorded for
      the consulting copy.

### 11.3 Internal wrap-up

- [ ] The journal is exported and archived with the engagement record.
- [ ] The scope file as it existed at the end of the engagement is archived
      (it is the authoritative record of what was authorized when).
- [ ] The finding set is reconciled against the delivered report.
- [ ] Time, expenses and subcontractor costs are recorded and invoiced.
- [ ] The retrospective is held: what went well, what went badly, what
      changed in the method, and which tools did or did not earn their keep.
- [ ] Generic findings and techniques that were reusable are added to the
      team's knowledge base, with client data stripped.
- [ ] The client is asked for a reference, and for feedback on the
      engagement.
- [ ] Any tooling gap the engagement exposed is raised as a work item.

### 11.4 Environment hygiene

- [ ] The engagement directory is removed from the operator's workstation, or
      moved to the agreed archive.
- [ ] `.cyberpi/cache/` is cleared, so cached tool output does not linger.
- [ ] The dedicated operating-system account used for the engagement is
      removed.
- [ ] The disposable VM or container used for the engagement is destroyed.
- [ ] Any credential the team used for the engagement itself (provider key,
      cloud role) is revoked.
- [ ] No client data remains on any personal device, personal cloud storage
      or chat history.

### 11.5 Closure record

| Field | Value |
|---|---|
| Engagement name | |
| Client | |
| Engagement reference | |
| Authorized window | |
| Actual testing dates | |
| Report issued (date, version) | |
| Evidence handed over (date, to whom) | |
| Credentials rotated confirmed by (name, date) | |
| Retention / destruction date | |
| Engagement manager | |
| Technical lead | |

## 12. Appendix — command reference

| Task | Command |
|---|---|
| Create the engagement directory | `cyberpi new <engagement-name>` |
| Start the harness | `cyberpi` (from the engagement directory) |
| Review the scope before testing | read `.cyberpi/scope.json`; confirm with the TL |
| Check the toolchain | `bin/cyberpi-doctor` |
| Dashboard: scope, surface, findings, journal | `/cyber` |
| Reconnaissance | `/recon <domain>` |
| Service enumeration | `/scan <cidr-or-host>` |
| Exploit research for a CVE | `/exploit CVE-2021-44228` |
| Generate the report | `/report` |
| View the journal | `cyber_journal` (or `cat .cyberpi/journal.jsonl`) |
| View the reconciled surface | `cyber_surface` (or read `.cyberpi/surface.json`) |
| Record a finding | `cyber_record_finding` |
| Refresh the CVE database | `cyber_cve_sync` |
| Clear the result cache | `rm -rf .cyberpi/cache` |
| Render the report outside the agent | `bin/cyberpi-report` |

The authoritative list of tools, their techniques and the binaries they
require is in `docs/TOOL-REGISTRY.md`. A tool that is refused because its
binary is missing names the package to install; `bin/cyberpi-doctor` reports
the whole toolchain at once.
