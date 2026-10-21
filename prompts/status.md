---
description: Summarize the engagement so far - scope, surface, findings by severity and recent journal activity
argument-hint: "[detail]"
---
Summarize the engagement so far at ${1:-summary} detail: the scope, the surface, the findings by severity, and the recent journal activity.

## Arguments

- Detail level: $1
- Extra instructions: $@

## Steps

1. Read the engagement scope from `.cyberpi/scope.json`: the engagement name, the client, the authorized targets, the technique allowlist and the authorization window. State it as it is, and flag anything that looks wrong or is missing.
2. `cyber_surface` - read the attack surface index: how many hosts, services, endpoints and distinct ports have been recorded, and when it was last updated. Use `kind` to ask for one part of the index at a time.
3. Read the findings stored under `.cyberpi/findings/` and group them by severity: critical, high, medium, low and info. The severity and the target are in the frontmatter of each finding file.
4. `cyber_journal` - read the recent activity: which tools ran, against which targets, how many actions in total, and what was blocked by the scope or failed. Use `limit` for the most recent entries, and the `tool` and `severity` filters to narrow the view.

## Rules

- Report what is recorded, not what you expect. An empty journal or an empty surface means the engagement has only just started; say so instead of filling the gap with assumptions.
- Keep credential material, cookies and tokens out of the summary.
- If the operator asked for more detail in the extra instructions, expand the section that question is about. Otherwise keep every section to a few lines.

## Report back, in this order

- Engagement: name, client, the authorized targets and the techniques that are allowed.
- Surface: hosts, services, endpoints, distinct ports, and the time of the last update.
- Findings by severity, one line each with the id, the title and the target.
- Recent activity: the last several actions with tool, target and outcome.
- The blocked and failed actions, and what they mean for the coverage of the engagement.
- The next steps that the current scope allows.
