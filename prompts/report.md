---
description: Generate the engagement report from the recorded findings and the journal
argument-hint: "[format]"
---
Generate the engagement report from the recorded findings and the journal, in ${1:-markdown} format.

## Arguments

- Format: $1
- Extra instructions: $@

## Steps

1. `cyber_journal` - read the engagement journal: every action that was run, against which target, with which command and with which result. This is the evidence backbone of the report.
2. `cyber_surface` - read the attack surface index: the hosts, services and endpoints that were discovered, and where each one came from.
3. Read the findings stored under `.cyberpi/findings/`. Those are the confirmed issues, already written in the finding format.
4. `cyber_report` - generate the report from the findings and the journal. Pass the format from the argument in `format` when the tool supports it, otherwise take the default. Turn on `include_journal` so the action log is appended as the appendix, and set `title` to the engagement name.
5. Review the generated report against the journal and the findings, and correct what is wrong: an action in the journal that deserves a finding but has none, a finding with no evidence behind it in the journal, and any severity that the evidence does not support.

## Rules

- The report is a deliverable to the client. It may contain only what the journal and the findings actually support. Never state an unverified issue as confirmed.
- Keep raw credential material, session cookies and tokens out of the report. Reference the artifact file instead.
- Do not invent CVSS scores, dates, target names or actions. Every claim in the report traces back to a finding or a journal entry.
- Where a section has no evidence behind it, write "not assessed" rather than leaving it implied.

## Report back

- The path of the generated report and what it contains.
- The finding count by severity.
- The coverage gaps: what was scanned, what was not, and what the operator should authorize or schedule next.
- Anything the report could not state because the engagement never recorded it.
