---
name: forensics-and-ir
description: "Collect, preserve and report evidence during a CyberPi engagement: capture packets, preserve volatile and disk evidence without modifying the source, hash and track every item in a chain of custody, triage a suspected-compromised host, reconstruct a timeline from logs, memory and packet captures, examine artifacts, and write the result up as an incident report. Use when the operator asks to preserve or collect evidence, to triage an incident or a compromised host, to answer 'what happened and when', or to produce an incident/forensic report."
---

# Forensics and incident response

You are doing evidence work: collecting it, proving it is intact, and telling
the story it tells. The evidence is the deliverable. A conclusion without
reproducible evidence is an opinion, and an opinion that destroys evidence is
unrecoverable.

Read `references/evidence-handling.md` for the chain-of-custody form, the
acquisition procedures and the artifact-triage checklists. Read it before the
first acquisition, not after something goes wrong.

## The eight rules

These are not style preferences. Breaking one of them destroys the value of
the engagement.

1. **Never modify the source.** Mount evidence read-only, image rather than
   browse, and work on a verified copy. No `chmod`, `chown`, `touch`, `sed -i`,
   editors, or any tool that writes metadata onto a live system.
2. **Hash on acquisition, verify before analysis.** SHA-256 every image, dump,
   capture and copied file the moment it lands on your storage. Record the hash
   in the manifest *before* you look at the content, then re-verify the hash
   after analysis. A hash recorded after the fact proves nothing.
3. **Never reboot, power off, or "clean" a live host** until memory and
   volatile state are captured. This is the one irreversible mistake in
   incident response, and the decision belongs to the client, not to you.
4. **Chain of custody.** Every acquisition, transfer, copy and analysis step
   gets a line in the evidence manifest: item id, description, source, method,
   operator, UTC timestamp, size, SHA-256, storage location. If you cannot say
   who touched an item and when, the item is not evidence.
5. **Document commands verbatim.** Put the exact command line in the case
   notes. Never paraphrase what you ran, and never describe an action you did
   not run. The report is a legal and contractual document.
6. **Keep secrets out of the transcript.** No raw credentials, session
   cookies, tokens, private keys or personal data in the chat. Summarise, point
   at the artifact file, and let the report carry the detail behind a
   redaction.
7. **Stay inside the authorized scope.** The scope engine fails closed and
   journals refusals as `blocked`. A refused capture is a reportable fact, not
   an obstacle to route around. Never edit `scope.json` on your own initiative.
8. **UTC everywhere.** Record timestamps in UTC and note the host's local
   timezone next to them. "3am" with no timezone is not a fact.

## Where everything lives

Everything sits under `<engagement>/.cyberpi/`:

| Path | Contents |
|---|---|
| `scope.json` | The written authorization: targets, ports, protocols, techniques. |
| `journal.jsonl` | Append-only log of every action CyberPi took. |
| `artifacts/` | Raw tool output and packet captures. |
| `notes/` | Case notes, the evidence manifest, timelines. |
| `findings/` | One Markdown file per finding. |
| `reports/` | The generated incident report. |

Read those files directly with your file tools. `cyber_journal`,
`cyber_record_finding` and `cyber_report` are the tool-side views of the same
data.

Keep the per-incident working material in one place: case notes and the
manifest in `.cyberpi/notes/<incident-id>.md` and
`.cyberpi/notes/evidence-manifest.md`. Tool output and packet captures land
directly in `.cyberpi/artifacts/` under generated names — copy anything you
want to keep for the case into a per-incident subfolder and hash it there.

## Tools

| Tool | Use it for | Returns |
|---|---|---|
| `cyber_capture` | Packet capture with tcpdump against an in-scope target, on the wire of the engagement host. | The pcap path in `.cyberpi/artifacts/`, the packet count, the duration, the interface and the filter that was applied. |
| `cyber_journal` | The engagement action history: what ran, against what, what was blocked, and when. | Journal entries for the engagement, or a filtered slice of them. |
| `cyber_record_finding` | Store a verified finding in the engagement as soon as it is confirmed. | The finding id and the file it was written to. |
| `cyber_report` | Build the deliverable from the recorded findings, the scope and the journal. | The rendered report path under `.cyberpi/reports/`, plus the finding counts by severity. |

Parameters, as the tools declare them:

- **`cyber_capture`** — `target` (host or IP to filter the traffic on), `port`,
  `duration_seconds`, `interface`. The capture is written to
  `.cyberpi/artifacts/capture-<target>-<timestamp>.pcap`. It needs raw
  privileges: run CyberPi under `sudo` on Kali, or the capture comes back
  empty.
- **`cyber_journal`** — `limit`, `action`, `tool`, `severity`, and `format`
  (`table` or `json`).
- **`cyber_record_finding`** — `title` and `severity` are required (one of
  `info`, `low`, `medium`, `high`, `critical`); the rest are optional:
  `target`, `description`, `impact`, `reproduction`, `evidence` (list),
  `references` (list), `cvss`, `cve`, `cwe`, `tags` (list) and `id`
  (allocated automatically when omitted). The finding is written to
  `.cyberpi/findings/<id>.md`.
- **`cyber_report`** — `format` (`markdown` or `html`), `output_file`,
  `include_journal`, `title`. The document is written to `.cyberpi/reports/`.

Tool parameter names are shown in the tool list; check the tool's schema before
calling it, and do not guess argument names. The list above is a summary, not
a substitute for the schema.

`cyber_capture` declares the `recon` technique, so the engagement's technique
allowlist must contain `recon` for it to run. Host-level forensics against a
system you are already on is local work and is not gated by the scope engine,
but the authorization still has to exist: confirm the host is named in
`scope.json` before you touch it.

## Triage flow

Work the phases in order. The order exists because the evidence decays — a
live host's memory holds the attacker's processes, a network connection and a
loaded module that a disk image will not.

### 0. Intake and authorization

1. Read `.cyberpi/scope.json`. Confirm the engagement name, the client, the
   authorization window and that the affected host or segment is covered by a
   rule. If it is not, stop and ask the operator for written authorization —
   the report will have to name the authorization anyway.
2. Read the case facts from the operator: what was observed, when it was first
   observed, who reported it, what the host is (server, workstation, domain
   controller), and the business criticality of the system.
3. Open the case notes and record the incident id, the reported time and its
   timezone, the reporter and the hypothesis. Write down what you believe
   happened *before* you collect anything, so the evidence can confirm or
   refute it instead of confirming what you hoped.
4. If the host is still running and might be compromised, ask the operator for
   the decision on containment now, and make clear that rebooting ends the
   volatile evidence.

### 1. Preserve volatile state (host still up)

Order matters; capture in this sequence and hash each item as it lands:

1. **Memory.** LiME or AVML, writing to the evidence volume, then hash. This
   is the most volatile item and the most valuable one.
2. **Live network state.** Connections and listening sockets, ARP and
   neighbour tables, routing table, DNS cache, and the interface counters.
   `cyber_capture` gives you the packets for the target conversation; the
   socket table tells you what the process was talking to.
3. **Process state.** Running processes with start times and full command
   lines, parent/child relationships, loaded modules, open files, the login
   session list, and the `utmp`/`wtmp` records of who was logged in.
4. **Recent log state.** Copy, do not read in place, the logs that are still
   being written to (`/var/log`, journald) and the persistence locations
   (`cron`, `systemd` units, `authorized_keys`, shell profiles).

`references/evidence-handling.md` has the exact command list for each step.

### 2. Preserve disk evidence

1. Identify the volume: `lsblk -o NAME,SIZE,TYPE,MOUNTPOINTS,SERIAL,MODEL`,
   and record the device, size and serial in the manifest.
2. Image it. `dc3dd` for a clean, forensically-sound copy; `ddrescue` for
   damaged media; a live acquisition (`dc3dd` with `conv=noerror,sync`) when
   the system must keep running. Never work on the original device.
3. Hash the image, record the hash, and note the acquisition tool and
   version.
4. Mount the image read-only (`mount -o ro,noload,noatime`) and work from
   there. Analysis never writes back to the image.

### 3. Build the timeline

Three timelines have to be merged:

- **Host timeline** — file create/modify/change times, from the image and the
  live copy.
- **Log timeline** — authentication, privilege, service and audit events, with
  the source log and its line reference.
- **Network timeline** — connections and DNS from the packet capture, with the
  capture file and the frame reference.

Then subtract the operator's own activity. `cyber_journal` is the record of
what *you* did; anything in the journal is CyberPi's footprint and must be
excluded from the adversary's timeline and disclosed separately in the report.
Leaving your own scan in the timeline is how an incident report turns into
evidence against the assessor.

Every timeline entry carries: UTC time, the source artifact and line/frame
reference, the event, and the host it happened on.

### 4. Triage the artifacts

Work the standard IR questions in order: initial access, execution,
persistence, credential access, discovery, lateral movement, collection,
exfiltration, impact. For each question, say what you looked for, where you
looked, and what you found — a negative result with a search method is a
result worth reporting.

Look for: new or modified user accounts, `authorized_keys`, new cron jobs and
systemd units, modified service binaries, unusual listening ports, new
scheduled tasks, recent shell history, `sudoers` changes, new SUID files, and
files whose timestamps were altered (a modification time before their creation
time, or a timestamp at a round hour with a nanosecond value of zero, is a
common tamper signal).

Memory analysis answers the questions disk cannot: which process held the
network connection, what was injected into another process, and whether the
host was rooted. `references/evidence-handling.md` lists the Volatility 3
plugins that answer each IR question.

### 5. Record findings as you confirm them

Do not batch findings to the end of the session. A finding that is confirmed
at 14:05 and written at 18:00 is a finding whose evidence may already be
stale.

`cyber_record_finding` takes the finding title, severity, target,
description, impact, the reproduction steps, the evidence list and the
references. For a forensic finding:

- The **target** is the asset, with its identifier (hostname, IP, or image
  name with the hash).
- The **description** states the observed behaviour and the time window.
- The **reproduction** is the command an examiner can run against the image
  to see it again, not a description of what you saw.
- The **evidence** entries are paths and log references, with the SHA-256 of
  the artifact they came from.
- The **severity** reflects impact to the client, not the drama of the event.

### 6. Write the incident report

`cyber_report` renders the scope, the findings and the journal into the
deliverable. The journal is appended as an appendix by default; leave
`include_journal` on for a forensic report, because the action record is part
of the evidence. Before you run it, the case notes must contain the parts a
report cannot invent: the incident summary, the timeline, the evidence
inventory with hashes, the chain of custody, and the containment and
remediation advice.

The report structure and the pre-delivery checklist are in
`references/evidence-handling.md`. A forensic report is read by people who
were not there: it has to stand on its own, and every claim has to point at
something an examiner can re-check.

## Working rules

- **Preserve before you analyse.** When in doubt, capture first and think
  later. Analysis is repeatable; the evidence is not.
- **One claim, one artifact.** Keep the transcript small: the tool returns a
  summary, the artifact holds the detail, the finding cites the artifact.
- **Say "not found" clearly.** Absence of evidence in a documented search is
  a reportable result; vagueness is not.
- **Do not clean up.** You are not remediating. Containment and eradication
  are the client's decisions, recorded as recommendations.
- **Do not over-collect.** Take the evidence the question needs. Do not copy a
  whole user home directory because one file was relevant.
- **Never invent a timeline.** If the log is missing, the gap is a gap. Say
  that the activity window is bounded by the surrounding events.
- **Do not report speculation as fact.** Mark a conclusion as assessed or
  confirmed, and say which evidence supports it.
