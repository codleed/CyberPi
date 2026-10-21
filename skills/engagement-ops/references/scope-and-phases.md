# Scope file and phase checklist

Reference for the `engagement-ops` skill. Read the scope file and the phase
checklist here while running an engagement.

## Worked scope file

`.cyberpi/scope.json` is JSONC: standard JSON plus `//` and `/* */` comments.
Keep the comments, they are where the authorization rationale lives.

```jsonc
{
	// Used in every refusal message and in the report header.
	"engagement": "acme-web-pentest-2025-03",
	"client": "Acme Corp",

	"authorization": {
		"statement": "External penetration test of the Acme web tier and the staging API, including authenticated application testing.",
		"authorizedBy": "Jane Doe, CISO, Acme Corp, under SOW-2025-114",
		"start": "2025-03-01T00:00:00Z",
		"end": "2025-03-15T23:59:59Z"
	},

	"rules": [
		{
			"id": "staging-api",
			"target": "exact:api.staging.acme.com",
			"techniques": ["recon", "web-testing", "vulnerability-scan"],
			"notes": "Staging API. Web testing only. No exploitation, no password audit."
		},
		{
			"id": "app-tier",
			"target": "app.acme.com",
			"notes": "Production web tier and every subdomain. Uniformly authorized for the engagement techniques."
		},
		{
			"id": "internal-test-range",
			"target": "10.20.30.0/24",
			"techniques": ["recon", "port-scan", "service-enumeration"],
			"notes": "Client-provided lab range. Discovery only, no exploitation."
		},
		{
			"id": "vendor-saas",
			"target": "exact:acme.myvendor.io",
			"techniques": ["recon", "web-testing"],
			"notes": "Vendor-hosted but client-owned. Logins only, no vulnerability scanning."
		}
	],

	// Engagement-wide technique allowlist. A technique that is not listed
	// here is refused everywhere, whatever the rules say.
	"techniques": [
		"recon",
		"port-scan",
		"service-enumeration",
		"web-testing",
		"vulnerability-scan",
		"exploit",
		"password-audit"
	],

	// Loopback and local interface addresses stay reachable for self-tests.
	"allowSelfTest": true,

	"notes": "No denial of service at any time. No production data exports. Findings only, no remediation access."
}
```

### Field notes

- `engagement` and `rules` are required. `rules` may be empty, but then
  nothing but self-testing is reachable.
- `techniques` at the top level is an allowlist, not a deny-list. Leave it out
  to permit every technique on the listed targets.
- `allowSelfTest` defaults to `true`. Set it to `false` to lock the harness
  down to the authorized targets only.
- `authorization.start` and `authorization.end` are documentation. The
  harness does not enforce the window; you do. Check it before the first
  network action.
- A rule may carry `ports`, `protocols` and `techniques` to narrow it.

### How a rule is matched

For each rule, in order, the harness asks three questions: does the rule's
`target` cover this host, is the technique allowed, is the port and protocol
allowed. The **first rule that answers yes to all of them authorizes the
action.**

Three consequences, all of which bite in real engagements:

**A rule that matches the host but fails a filter does not stop the check.**
The harness moves on to the next rule. A narrow rule therefore cannot carve a
host out of a broad rule that also covers it: if `app.acme.com` is a rule and
`exact:api.app.acme.com` is another, the host `api.app.acme.com` is authorized
by the broad rule whatever the narrow rule says, and whatever order the rules
are in.

To restrict a host, make sure no other rule covers it:

- use `exact:host` for hosts that need their own limits, and
- do not add a bare-domain rule that would match them. `app.acme.com` as a
  bare domain covers every `*.app.acme.com` subdomain, so it cannot coexist
  with a per-subdomain restriction.

In the worked example, `api.staging.acme.com` is a different subtree from
`app.acme.com`, so the staging rule really does narrow it, and
`acme.myvendor.io` and the lab CIDR are likewise uncovered by anything else.

**A rule with `ports` only matches actions that name a port.** A sweep that
carries no single port is refused by that rule. Give broad targets their own
rule without `ports`, and use port-restricted rules for single-service work.

**A rule with `protocols` only matches actions that declare a protocol.** Most
tools do not, so a protocol-restricted rule refuses almost everything. Use it
only when you intend to restrict one protocol-aware action, and expect
refusals elsewhere.

**A rule with `techniques` only matches actions that declare a technique.**
Every network tool declares one, so technique carve-outs work reliably.

### Target forms

| Form | Matches | Does not match |
|---|---|---|
| `10.20.30.0/24` | Any address in the CIDR. | Hostnames. |
| `192.168.1.10` | That address. | Its neighbours. |
| `example.com` | The domain **and** every subdomain. | — |
| `*.example.com` | Every subdomain. | The apex `example.com`. |
| `exact:example.com` | The host. | Its subdomains. |

A bare domain covers subdomains, so `example.com` already covers
`api.example.com`. Use `exact:` to name a single host, and remember that a
bare-domain rule elsewhere in the list will also cover it.

### Adding a target

Only after the operator authorizes it in writing. Add one rule, keep the
coverage rules above in mind, and keep the file valid JSONC.

```diff
 	"rules": [
 		{
 			"id": "staging-api",
 			"target": "exact:api.staging.acme.com",
 			"techniques": ["recon", "web-testing", "vulnerability-scan"],
 			"notes": "Staging API. Web testing only. No exploitation, no password audit."
 		},
+		{
+			"id": "legacy-portal",
+			"target": "exact:portal.acme.com",
+			"notes": "Added 2025-03-04 on operator approval, ticket OPS-1182."
+		},
 		{
 			"id": "app-tier",
 			"target": "app.acme.com",
```

`portal.acme.com` is not under `app.acme.com`, so the broad `app-tier` rule
does not cover it and the new rule is the one that authorizes it. Had it been
`portal.app.acme.com`, the broad rule would have covered it as well and the
new rule would have had no effect.

Then re-read the file and confirm it parses before retrying the blocked tool.

### Technique identifiers

The harness understands exactly these: `recon`, `port-scan`,
`service-enumeration`, `web-testing`, `vulnerability-scan`, `exploit`,
`password-audit`, `privilege-escalation`, `active-directory`, `pivot`,
`wireless`, `iot-hardware`, `cloud-enumeration`, `forensics`,
`social-engineering`.

A tool that declares a technique outside the engagement allowlist is refused
before it runs, and the refusal is journalled as `blocked`.

## Phase checklist

Work the phases in order. A phase is done when its exit criteria are met,
not when the tool returned output.

### 1. Scoping

- [ ] Read `.cyberpi/scope.json`; confirm `engagement`, `client`, window.
- [ ] List the authorized targets and the technique allowlist back to the
      operator.
- [ ] Note every explicit exclusion in the operator's instructions.
- [ ] Check which rules are narrow enough to refuse a sweep, and ask the
      operator to widen them if a sweep is authorized.
- [ ] Confirm the toolchain: `cyberpi-doctor` names any missing Kali package.
- [ ] Confirm the CVE mirror is fresh enough: `cyber_cve_sync`.

Exit: the operator has confirmed the target list, and any ambiguity in the
scope file has been resolved in writing.

### 2. Recon

- [ ] `cyber_subdomain` for passive subdomain discovery on the domain.
- [ ] `cyber_dns` for records on hosts that matter.
- [ ] `cyber_whois` for registration, netblock and ownership context.
- [ ] `cyber_http_probe` to find the hosts that actually serve HTTP.
- [ ] `cyber_capture` only if packet capture is genuinely required.
- [ ] Every discovered host lands in the surface index.

Exit: the surface index lists every in-scope host with its addresses, and
nothing discovered is outside the authorized set.

### 3. Enumeration

- [ ] `cyber_portscan` for reachability and open ports.
- [ ] `cyber_service_scan` on the hosts and ports that answered, for service
      and version detail.
- [ ] `cyber_crawl` on hosts confirmed by `cyber_http_probe`.
- [ ] `cyber_dir_enum` against a confirmed host, with a wordlist suited to
      the application.
- [ ] Narrow as you go. Do not enumerate a host you have not confirmed is in
      scope.

Exit: services and endpoints are indexed with versions, and each finding
candidate has a named target, port and service.

### 4. Validation

- [ ] `cyber_vuln_scan` for breadth, then read every hit critically.
- [ ] `cyber_sqli` and `cyber_xss` for the hypotheses the service inventory
      raised, one parameter at a time.
- [ ] `cyber_secret_scan` against client-provided repositories.
- [ ] `cyber_hash_id` before any cracking, so the mode is right.
- [ ] `cyber_password_audit` only against services the scope allows, with a
      rate the operator accepted.
- [ ] `cyber_cve_lookup` and `cyber_exploit_map` for every version in the
      inventory, to know which findings already have public exploit paths.
- [ ] Every scanner result is a hypothesis. Reproduce it by hand.

Exit: each candidate finding is either confirmed with evidence, or recorded
as unconfirmed and left out of the report.

### 5. Exploitation

- [ ] Only for confirmed, in-scope findings, only to the depth that proves
      impact.
- [ ] `cyber_exploit_search` then read the module before running it.
- [ ] `cyber_poc` for the default proof: a minimal, repeatable request.
- [ ] `cyber_exploit_run` only when the exploit is the point of the test and
      the operator has approved it.
- [ ] No DoS, no destructive payload, no persistence, no data mutation.
- [ ] Any intrusive step: stop and get explicit approval first.

Exit: each confirmed finding has a reproducible proof and the minimum
possible impact was used to get it.

### 6. Evidence

- [ ] `cyber_record_finding` for every confirmed issue, as it is confirmed.
- [ ] Each finding carries: the exact target, the exact request or command,
      the observed response, the artifact path, the timestamp.
- [ ] The transcript holds the summary; the artifact file holds the raw
      output.
- [ ] No credential, cookie, token or personal data in the finding text.
- [ ] Severity set from impact and exploitability, not from the scanner.
- [ ] One finding per issue, with all affected targets listed.

Exit: every finding can be re-verified from the recorded evidence by someone
who was not in the session.

### 7. Reporting

- [ ] `cyber_report` to build the deliverable.
- [ ] Executive summary: what was tested, what was found, what it means, what
      to fix first.
- [ ] Coverage section: what was in scope, what was skipped, what was
      blocked and why.
- [ ] Findings ordered by severity, each with impact, reproduction and fix.
- [ ] `cyber_journal` reviewed for blocked actions and for anything that was
      attempted and failed.
- [ ] Artefacts and the journal handed over as the engagement record.

Exit: the report stands on its own, and the journal tells the same story.

## Status update template

When the operator asks where things stand, answer from the artefacts, not
from memory:

1. `cyber_surface` for the host, service and endpoint counts.
2. `cyber_journal` for the actions run, their results, and anything blocked.
3. The findings directory for confirmed issues.

Then report, in this order:

- Engagement name and the current phase.
- Scope coverage: targets in scope, targets skipped, targets blocked.
- Findings by severity, with the affected target for each.
- Blocked actions waiting on the operator, each with the proposed scope rule.
- The next actions, and what they need.
