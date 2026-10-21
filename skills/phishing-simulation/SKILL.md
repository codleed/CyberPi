---
name: phishing-simulation
description: Plan, run and report an authorized phishing awareness simulation with GoPhish against a simulated staff population — stand up the campaign infrastructure, craft a safe test message, measure click and credential-submission rates, and record the outcome as a training metric rather than a vulnerability. Use when the request involves a phishing simulation, phishing campaign, security awareness exercise, spear-phishing training exercise, simulated credential-capture campaign, or measuring click-through and credential-submission rates for staff training.
---

# Phishing simulation

An awareness-training exercise, run like an engagement: planned, authorized, scoped,
measured and reported. This skill covers building the simulation with GoPhish,
crafting the test message, measuring the outcome, and reporting the result as a
**training metric**.

Two operating modes:

- **Sandbox (default).** The population is synthetic. Messages are caught by a
  local SMTP sink, clicks and submissions are produced by a scripted harness on
  the local machine, and no real person is contacted. This is how the simulation
  is rehearsed, how the message is client-approved, and how the harness itself
  is proven before it ever touches a mailbox.
- **Authorized live pilot.** A real subset of staff receives the message. This
  requires every item in *Legal prerequisites* (section 2) signed off in
  writing first, and the results are then a real measurement of real people.

The line between a training exercise and a real attack is exactly the list in
*Guardrails*. Everything below is written on the training side of it.

## Guardrails

These are limits, not style. If the request would break one, the request is out
of scope for this skill no matter who asks — say so plainly, offer the
alternative that stays inside the line, and continue with the rest of the work.

- **No real credentials.** The capture form must never be a working login form
  for anything. Either capture a non-secret identifier (employee ID, training
  code) or label the field unambiguously — "Training password — this is a
  simulation, do not enter your real password" — and destroy the value at
  teardown. Submitted usernames and passwords are never printed into the
  transcript: report counts, point at the artifact file.
- **No real malware.** Attachments are inert: a text file, a PDF with no
  macros, a link to a training page. No executables, no scripts, no macros, no
  "double-click to run" shortcuts, no live payload of any kind.
- **No live third-party brands.** Do not impersonate a real bank, retailer, IT
  vendor, delivery company or government body — no logos, no brand colours, no
  real login page, no real support number. The sending domain and landing host
  belong to the client or are clearly fictional. If the client specifically
  wants a third-party brand simulated, that is the engagement lead's decision
  to escalate, not the agent's to make.
- **Written authorization for the targeted population.** The authorization must
  name the campaign, the exact population, the dates, the sending infrastructure
  and the fact that simulated credential capture is included. No authorization,
  no simulation.
- **Data minimisation and destruction.** The population list, the click log and
  any captured value are engagement data: keep them inside the engagement
  directory, restrict access, delete them on the agreed retention date, and
  delete captured values at teardown.
- **The client sees aggregates.** Awareness reporting is per-cohort or
  per-department at most. Individual results are handed over only when the
  authorization explicitly says so, and then as a separate restricted
  artifact, never in the transcript and never in the general report.

## 1. Planning flow

Work through this before GoPhish is touched. The output is a simulation plan —
use the template in `references/simulation-plan.md` and keep the filled copy at
`.cyberpi/notes/simulation-<campaign>.md`.

1. **Fix the objective and the decision it supports.** "Do finance staff
   recognise a payroll-invoice lure before it reaches a credential form?" is a
   decision. "Run a phishing test" is not — a simulation with no decision
   attached produces a number nobody can act on.
2. **Fix the metric and its denominator *before* the campaign runs.** Choosing
   the metric after seeing the numbers is how awareness reports get gamed.
   Formulas, denominators and a worked example are in the reference file.
3. **Choose the mode** — sandbox or live pilot — and record why.
4. **Define the population.** Size, roles, sampling method, and the exclusion
   list (new hires, contractors, anyone on leave, anyone who already reported a
   phish this quarter, anyone under an HR or legal hold). In sandbox mode the
   population is generated synthetically from a fixed seed so the run is
   reproducible.
5. **Plan the infrastructure.** GoPhish instance, sending host and sending
   domain (SPF/DKIM), landing host, SMTP path, artifact locations, and the
   public hosts that must be added to the engagement scope.
6. **Set the kill switch and the escalation path.** How a campaign is stopped
   mid-send, who is called, and the conditions that stop it automatically
   (a real complaint from a recipient, a leaked URL, an unintended recipient).
7. **Write the plan, get it signed** (section 2), then execute.

### Scope and the journal

CyberPi checks every tool call against `.cyberpi/scope.json` and appends every
action to `.cyberpi/journal.jsonl`.

- The simulation's public hosts (landing host, sending host) must appear as
  scope rules, and the technique allowlist must permit the techniques the
  tools use — `recon` for `cyber_http_probe`. If the allowlist is non-empty and
  does not include the technique, the tool refuses and journals the refusal.
- The GoPhish admin API on `127.0.0.1:3333` and the local SMTP sink are
  loopback, covered by the self-test allowance — no rule needed.
- Anything that leaves the machine (a public landing URL, a real send) is the
  part that needs a scope rule, and the part that needs the written
  authorization.

## 2. Legal prerequisites

Checklist to be signed by the engagement lead before the first message is sent.
The signed copy belongs with the engagement, not in the transcript.

- [ ] **Written authorization** naming: client, engagement, campaign name, the
      exact population, the send window (dates and hours), the sending domain
      and host, the landing host, and the explicit statement that simulated
      credential capture is part of the exercise. Signed by someone with
      authority to authorize it.
- [ ] **Population list and provenance** — where the list came from, who it
      covers, and the exclusions applied. A list that nobody has approved is
      not a population.
- [ ] **Privacy basis** for processing the list and the click log (personal
      data): lawful basis, retention period, who may see the results, and the
      explicit rule that per-person results are not given to line managers
      without a separate clause.
- [ ] **Data handling** — results stay inside the engagement directory, access
      is restricted, everything is destroyed on the retention date, and
      captured credential values are destroyed immediately at teardown.
- [ ] **No third-party impersonation** — the client confirms in writing that no
      real brand will be simulated and that the sending domain is theirs.
- [ ] **Notification** — HR, internal comms and the service desk are briefed;
      recipients are told a simulation may arrive; the "how to report a
      phishing message" channel is live *before* the send.
- [ ] **Abuse handling** — a scripted reply for anyone who reports the
      simulation, and no reply-to address that swallows a complaint.
- [ ] **Rules of engagement** — a named operator, a hard end date, the kill
      switch, and the escalation contacts.

The first line is the one that matters: without written authorization for the
targeted population, this is a criminal phishing campaign against the client's
own employees, and the fact that the request came from the client does not
change what it is. If the authorization is missing, ambiguous or expired, stop
and ask the engagement lead — do not start the campaign, and do not start it
"just to test the tooling" against a real mailbox.

## 3. Build the simulation

### 3.1 Stand up GoPhish

GoPhish provides the campaign server, the sending profile, the tracked landing
page and the per-recipient result map. Install it on Kali, run it bound to
loopback, and take the API key from its own config file — never paste the key
into the transcript.

The exact commands, the API endpoints, the local SMTP sink and the payload
shapes are in `references/simulation-plan.md`. The flow is:

1. Start GoPhish on `127.0.0.1:3333` (admin) and the local landing port.
2. Read the API key from `~/.config/gophish/config.json` into an environment
   variable inside the shell, and use `-H "Authorization: $GOPHISH_API_KEY"`.
   The key is a secret: it never appears in output, in the journal, or in a
   report.
3. Create the sending profile, the landing page, the recipient group and the
   campaign, and confirm the created objects by reading them back from the API.
4. Sandbox mode only: point the sending profile at the local SMTP sink so
   nothing can reach a real mailbox, even by accident. A misconfigured profile
   that points at a real relay is exactly the failure that turns a simulation
   into a mailing list — the sink is the guardrail, not a convenience.

### 3.2 Infrastructure checks with `cyber_http_probe`

Before the send, prove the infrastructure works from outside the harness —
that is what `cyber_http_probe` is for. Probe:

- the landing URL (and the tracked link shape) — it must answer, redirect
  correctly and serve the training content;
- the sending and landing hosts — TLS valid, host reachable, no leftover
  default page.

The probe is scope-checked, so the hosts must be in `.cyberpi/scope.json`
first; a refusal here is the scope engine working, and the fix is the scope
file (or a smaller simulation), not a different tool.

```
cyber_http_probe({ target: "https://training.internal.example.com/login", follow_redirects: true })
```

Pass the endpoint as the tool's `target` parameter. Probe the tracked form (the
URL GoPhish rewrites per recipient) too, not only the bare landing page: a
broken redirect is the most common way a campaign ends up measuring nothing.
`follow_redirects` matters for the tracked link, and `screenshot: true` gives
you a picture of the landing page for the deliverable when the host has a
browser available.

The DNS side of the check (SPF, DKIM, DMARC for the sending domain) is
optional and only applies to a live send — `cyber_dns` with the sending
domain and a `TXT` record type reads the SPF and DKIM records. Skip it
entirely in sandbox mode, where nothing is really sent.

### 3.3 Craft the test message

The message is the deliverable the client actually approves, so treat it as a
written artifact:

- **Framing.** State plainly that it is a training simulation and name the
  training team that runs it. A simulation that deceives the recipient
  completely teaches them to be deceived by the next one, and it is the
  fastest way to lose the organization's trust in the program.
- **A plausible but harmless lure** — a fake internal payroll notice, a fake
  password-expiry notice, a fake shared-document request — that carries one
  tracked link and nothing else. One link. No second link, no attachment and a
  link.
- **No live brand.** Generic wording, no logo, no real corporate colour, no
  real support number, no real login page. The landing page content is
  training content, and the form is labelled as a training capture.
- **No payload.** If the scenario needs an attachment, it is a text file or a
  macro-free PDF that says the same thing as the body.
- **Mobile-first.** Staff read this on a phone. Keep the message readable at
  small width, and test the landing page there too.

The GoPhish email template, the landing page HTML and a worked message example
are in the reference file.

## 4. Measure the outcome

Take the numbers from GoPhish's own result map, not from impressions, and
save the raw JSON as an engagement artifact so the report can be re-derived
later.

- In **sandbox mode**, the scripted harness produces the clicks and
  submissions against the local landing page, and the local SMTP sink confirms
  what was "delivered". The harness is in the reference file.
- In **live mode**, GoPhish records the same fields per recipient after the
  real people acted; wait for the campaign to finish, then read the results
  endpoint.

The four numbers that matter: delivered, opened, clicked, submitted. From
them: click rate, credential-submission rate over the whole population, and
credential-submission rate over the people who clicked. The formulas, the
denominator traps (`sent` is not `delivered`, `opened` is not `read`) and a
worked example are in the reference file.

Report the numbers with their denominators, always. "42% clicked" without
"42 of 200 simulated recipients" is not a measurement.

## 5. Reporting flow

### 5.1 Freeze and summarise

Save the raw result JSON and the message source as artifacts under
`.cyberpi/artifacts/`, write a short human summary to
`.cyberpi/notes/simulation-<campaign>.md`, and confirm the numbers reproduce
from the saved file before writing anything into the finding.

### 5.2 Record the outcome with `cyber_record_finding`

The outcome is a **training metric, not a vulnerability**. It is recorded as a
finding so it lands in the engagement record and the deliverable, but it must
read like one:

- **severity** — `low` when the credential-submission rate is above the
  threshold agreed in the plan, `info` otherwise. Never above `low`: a
  simulation is not a vulnerability, and inflating it corrupts the client's
  vulnerability tracking and buries the real findings.
- **no CVSS, no CVE, no CWE** — a training metric has no CVSS vector.
- **title** — what was measured, e.g. "Phishing simulation training effectiveness — payroll lure (sandbox)".
- **description** — objective, mode, dates, population size and how it was
  sampled, the message theme, and the metric definitions used.
- **impact** — the rates with their denominators, e.g. "6.0% of the simulated population (12/200) submitted a credential; 29.3% of clickers (12/41) did".
- **evidence** — the artifact paths. Not the raw result rows.
- **tags** — `training`, `phishing-simulation`, `social-engineering`, plus the
  campaign name.

```
cyber_record_finding({
  title: "Phishing simulation training effectiveness — payroll lure (sandbox)",
  severity: "low",
  target: "training.internal.example.com",
  description: "Sandbox simulation, 200 synthetic recipients, message theme: internal payroll-invoice notice. Primary metric: credential-submission rate over the delivered population.",
  impact: "Credential-submission rate 6.0% (12/200 delivered). Click rate 20.5% (41/200). Submission rate over clickers 29.3% (12/41). Sandbox population: no real staff contacted.",
  evidence: [".cyberpi/artifacts/gophish/campaign-1.json", ".cyberpi/artifacts/gophish/results-1.json"],
  tags: ["training", "phishing-simulation", "social-engineering", "payroll-lure"]
})
```

The argument names above follow the tool's schema — read `cyber_record_finding`
before calling it rather than trusting this example blindly.

### 5.3 Build the deliverable with `cyber_report`

`cyber_report` renders the deliverable from the recorded findings, the scope
and the journal. It takes `format` (`markdown` or `html`), an optional
`output_file` name, an optional `include_journal` flag and an optional
`title`:

```
cyber_report({ format: "markdown", title: "Phishing simulation — training effectiveness", include_journal: true })
```

The tool builds the engagement report from the findings, so the simulation
section is the finding you recorded in 5.2 — make sure its `description` and
`impact` carry the objective, the mode, the denominators and the caveats,
because that is what ends up in the document. The deliverable needs to answer
a reader who was not in the room:

- what was authorized and by whom (reference the authorization, do not restate
  personal data);
- the objective and the decision the result supports;
- the mode, the population, the sampling and the denominators;
- the message theme and the landing page behaviour, with a screenshot or the
  message source as evidence;
- the metrics, each with its numerator and denominator;
- the caveats: `sent` is not `delivered`, open rates are unreliable, a
  sandbox population is not a workforce;
- the recommended training actions, aimed at the behaviour the data shows —
  "31% of clickers submitted a credential" implies the training targets the
  second click, not the first;
- the teardown confirmation and the destruction date for the population list
  and the captured values;
- an explicit statement that no real credentials were collected and no
  personal data was processed, where that is true.

If the authorization permits per-person results, they go in a separate
restricted artifact. They do not go in the deliverable and they do not go in
the transcript.

## 6. Teardown

Teardown is part of the deliverable, not a follow-up task:

1. Stop the campaign if it is still sending, then stop GoPhish.
2. Delete the captured credential values from GoPhish (they are fake, but they
   are still personal data once a real pilot touches them).
3. Remove the population list and the click log, or move them into the
   restricted store with the agreed retention date.
4. Keep the aggregate artifacts and the report; record what was destroyed and
   when in the engagement notes.

## Reference

`references/simulation-plan.md` — the fill-in plan template, the GoPhish
cookbook (install, API endpoints, campaign creation, results, kill switch), the
local SMTP sink, the synthetic click-and-submission harness, the message and
landing page templates, the metric formulas with a worked example, and the
teardown checklist.
