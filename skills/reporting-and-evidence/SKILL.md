---
name: reporting-and-evidence
description: Turn a finished assessment into a client-ready deliverable — record findings with reproducible proof, rate severity with justification, collect and cite evidence, build the report, and audit the action journal for a complete record. Use when writing up results, recording or correcting a finding, rating a vulnerability, gathering evidence for a claim, generating the final report, or checking what was actually run.
---

# Reporting and evidence

The deliverable of an engagement is a set of findings, each backed by evidence
someone else can check, and a report a non-technical reader can act on.
CyberPi keeps both: findings in `.cyberpi/findings/`, the actions that
produced them in `.cyberpi/journal.jsonl`, the raw tool output in
`.cyberpi/artifacts/`. The report is generated from that record, so the report
is only as good as the findings written before it.

Four tools do the work, and none of them touches the network, so none of them
is refused by the scope check:

| Tool | What it does |
| --- | --- |
| `cyber_record_finding` | Writes one finding to `.cyberpi/findings/<id>.md` and journals it with its severity. |
| `cyber_report` | Builds the report (Markdown or HTML) from the findings, the scope file and the journal. |
| `cyber_journal` | Reads the action journal: what ran, against what, what was refused. |
| `cyber_surface` | Reads the attack surface index: hosts, services, endpoints. |

Read the tool's own schema for its parameters; do not guess argument names.

## The order of work

1. **Confirm before you write.** A scanner hit is a hypothesis. Reproduce it
   by hand, once, with the exact request or command. Only a reproduced issue
   becomes a finding.
2. **Record it immediately**, while the target, the command and the artifact
   are in front of you. `cyber_record_finding` is journalled, so the record
   of the finding itself becomes part of the engagement record.
3. **Rate the severity and justify it in the text.** A label without a reason
   is not defensible.
4. **Cite the evidence**: the artifact path plus the one line of it that
   proves the claim.
5. **Review the journal and the surface index** before writing the report, so
   the coverage gaps are known before they are described.
6. **Build the report** with `cyber_report` and read the generated file
   before handing it over.
7. **Run the final checklist** below. A finding that fails one item is not
   ready.

## Recording a finding

```
cyber_record_finding:
  title: "Stored XSS in the support ticket subject field"
  severity: "high"
  target: "https://app.example.com/support/tickets"
  description: "The subject field of a new ticket is stored unencoded and rendered as HTML in the agent console. Confirmed by creating a ticket whose subject was <img src=x onerror=alert(1)> and reading it back in the agent view."
  impact: "Any user who can open a ticket can execute script in the browser of every support agent who views it, and read that agent's session."
  reproduction: "curl -sk -X POST 'https://app.example.com/support/tickets' -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'subject=<img src=x onerror=alert(1)>'"
  evidence:
    - ".cyberpi/artifacts/web-xss-ticket-2025-03-14.txt"
    - "The agent console renders the subject as raw HTML (element <img> present in the response body)."
  cvss: 8.2
  cwe: "CWE-79"
  references:
    - "https://owasp.org/www-community/attacks/xss/"
  tags: ["web", "xss"]
```

`title` and `severity` are required. `severity` is one of `info`, `low`,
`medium`, `high`, `critical`. Everything else is optional but should be filled
for a finding that will be delivered.

`id` is optional: omit it and the harness allocates the next sequential id
(`F-001`, `F-002`, …). Pass an existing id to **update** that finding — the
file is replaced in place, so keep the id stable and re-record the whole
finding, not just the changed field.

The harness stamps the status of a recorded finding itself, so confirmation
lives in the reproduction and the evidence: once the issue is reproduced,
re-record the finding with the same id so the stored record carries the
proof. A finding that never reproduced must be corrected or removed before
the report is built. Do not soften a finding to hide a failed reproduction.

## The finding template

Every finding has the same shape. Fill it in completely, then record it:

| Field | What belongs there | Common mistake |
| --- | --- | --- |
| Title | One specific, singular claim: what is wrong, where. | A category ("XSS issues") instead of a claim. |
| Severity | The rating, with the reason stated in the description. | Copying the scanner's severity. |
| CVSS | The base score, when you scored it. | Leaving it blank on a rated finding. |
| CVE / CWE | The identifiers, when the issue maps to them. | Naming a CVE you did not verify against the observed version. |
| Target | Host and port, or the exact URL. | "The web server" or a hostname with no port. |
| Description | The condition, where it is, how it was observed, and the proof. | A restatement of the title. |
| Impact | What an attacker gains, from what, and with what effort. | "Could lead to compromise". |
| Reproduction | The exact steps, in order, re-runnable by a third party. | A paraphrase of the request. |
| Evidence | Artifact paths and the line that proves the claim. | A summary of the artifact instead of the path to it. |
| References | The advisory or documentation URL. | A search-result URL. |
| Tags | Grouping labels (`web`, `ad`, `wireless`). | Free-text noise. |

The full template, with the field guidance and a worked example, is in
`references/finding-template.md`.

## Rating severity

Rate the impact **in this environment**, not the CVE's global score. A CVE
rated critical everywhere is a high finding when the affected host is a lab
machine with no path to production. Severity follows impact and
exploitability, never the scanner's opinion.

| Severity | CVSS v3.1 | Use it when |
| --- | --- | --- |
| Critical | 9.0 – 10.0 | Unauthenticated remote code execution, an authentication bypass into an administrative interface, a verified path to the domain controller or the crown-jewel data set, or a live production secret that grants broad access. No user interaction required. |
| High | 7.0 – 8.9 | Authenticated remote code execution, injection that reaches real data, stored cross-site scripting in an authenticated portal, a recovered privileged credential, a management interface exposed to the internet, or an end-of-life service still in production. |
| Medium | 4.0 – 6.9 | Sensitive information disclosure, reflected cross-site scripting, an authorization flaw that crosses a trust boundary without administrator rights, weak or outdated TLS with a practical attack, or a recovered low-privilege credential. |
| Low | 0.1 – 3.9 | Version disclosure, verbose errors without sensitive data, missing hardening headers with no demonstrated path, enumeration of usernames or internal hostnames. |
| Informational | 0.0 | Observations and hardening advice with no demonstrated security impact. |

Rules for the rating:

- The description must justify the label. If the text does not support the
  severity, the severity is wrong.
- When two ratings are arguable, take the lower one and say what would raise
  it: "would be high if the endpoint were internet-facing".
- One issue, one rating. A finding that mixes severities is two findings.
- Do not rate what you could not test. "MFA was not enforced" without a login
  attempt is a limitation, not a finding.
- The same issue on many hosts is one finding with the affected targets
  listed, not twenty findings.

## Collecting evidence

- Every finding cites at least one artifact file, plus the single line from
  it that proves the claim. Artifacts are written by the tools into
  `.cyberpi/artifacts/`; read the file before citing it.
- Re-run the reproduction once, fresh, and confirm it still reproduces. If it
  does not, the finding is not confirmed.
- The journal entry is the provenance of the proof. The table shows the
  timestamp, the tool, the action, the target and the summary; with
  `format: "json"` the entries also carry the command line, the exit code,
  the duration and the artifact path.
- Take the minimum evidence that demonstrates the flaw — one record, not a
  dump. Redact what you quote.
- For a CVE-backed finding, record the exact product version observed, the
  CVE, the CWE and the advisory URL in `references`.
- Keep each entry of `evidence` to one line: a path, or a quoted line.

## Never print credential material

Hashes, passwords, cookies, session identifiers, private keys, tokens and
personal data stay in the artifact file. The finding records that the
material exists, where it is, and what it would give an attacker — the
material itself is never transcribed into the finding, the report or the
transcript. For a recovered credential, record the account, the privilege
level, the artifact path and a redacted excerpt such as `NTLM hash, 16 bytes`.

## Writing rules

- The title is the claim, not the category: "Stored XSS in the support ticket
  subject field", not "XSS issues".
- Describe what you observed, not what you assume. "The response body
  contains the marker `7c3f1a`" — not "the server is probably vulnerable".
- Say how you know: the tool, the command, the request. A reader must be able
  to repeat it.
- The impact paragraph is for a reader who does not run tools. State what an
  attacker can do, what is at stake and what it would take. Leave the request
  mechanics to the reproduction.
- Do not speculate as fact. Mark anything unverified explicitly: "impact could
  not be verified without privileged access".
- One claim per finding, one finding per claim.
- No filler, no hedging boilerplate, no "as an AI". Write the way a senior
  consultant writes to a client.
- Use the client's vocabulary and their language. Expand the jargon the first
  time it appears.
- Do not pad a report with observations to look thorough. An informational
  note that proves nothing belongs in the appendix, or nowhere.

## Review the record before writing

`cyber_journal` reads the append-only action log. Use it before the report
and again after it:

```
cyber_journal:
  limit: 100
  action: "blocked"     # optional: filter by action, tool or severity
  format: "table"       # or "json"
```

The limit keeps the most recent entries, and the summary line always states
how many of the total were shown. Check for:

- Actions that failed and were never retried.
- Scope refusals (`action` is `blocked`). They belong in the record: they
  show what was attempted and why it was not authorized, and they often
  explain a coverage gap that the report has to disclose.
- Long gaps in the timeline, or a phase that produced no entries.

Then compare the record with the findings: a target that was scanned but
produced no finding is either clean or untested. Decide which, and say which
in the report. Never drop it silently.

`cyber_surface` reads the attack surface index. Compare it with the scope:
an in-scope host that was never assessed is a gap you must disclose in the
report's limitations, not a gap you leave out.

```
cyber_surface:
  host: "example.com"   # optional substring filter
  port: 443             # optional exact filter
  kind: "services"      # all | hosts | services | endpoints
  format: "table"       # or "json"
```

## Building the report

```
cyber_report:
  format: "markdown"     # or "html"
  output_file: "acme-web-2025-03-report.md"   # optional; relative names go to .cyberpi/reports/
  include_journal: true
  title: "Acme Corp - External Penetration Test, March 2025"
```

The report is built from the recorded findings, the scope file and the
journal. It contains the engagement metadata, the executive summary, the
severity breakdown, one section per finding (attribute table, description,
impact, reproduction, evidence, references), Appendix A (scope and
authorization) and Appendix B (the action journal).

- Build the report **after** the last finding is recorded and the last
  correction is made. The report is a snapshot; regenerate it whenever a
  finding changes.
- Keep `include_journal` on unless the client asked for a report without the
  appendix. The journal is the evidence that the assessment was authorized,
  scoped and methodical.
- Read the generated file before delivering it. Check that the executive
  summary matches the findings, that no section is empty, and that no
  placeholder text survived.
- Deliver the file path, the finding counts by severity, and the limitations:
  what was not tested, what was out of scope, what was blocked.

## Final checklist

Run this before the report is delivered. Every line is a yes or no question.

1. Every finding has a title, a severity, a target, a description, an impact,
   a reproduction, and at least one piece of evidence.
2. Each severity is justified in the text, not only in the label.
3. Every reproduction was re-run and still worked.
4. Every evidence path exists in the engagement and proves the claim it is
   attached to.
5. No raw credentials, cookies, tokens, session identifiers, private keys or
   personal data in any finding, the report or the transcript.
6. No unproven claims: everything is reproduced, or explicitly labelled as an
   observation.
7. The journal was reviewed: failures explained, scope refusals accounted
   for, no unexplained gaps in the timeline.
8. Every in-scope target that was assessed either has a finding or is
   explicitly reported as clean.
9. The surface index was checked; unassessed in-scope hosts and services are
   listed in the limitations.
10. The report was generated after the final finding was recorded, and the
    file path is known.
11. The generated report was read end to end: no placeholders, no "TBD", no
    empty sections, no contradictory severity counts.
12. The delivery states the file path, the counts by severity, the
    limitations, and the recommended first remediation.

## Reference

- `references/finding-template.md` — the fill-in template, the field guidance
  and a worked example.
