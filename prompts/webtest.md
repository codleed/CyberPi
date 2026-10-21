---
description: Test a web application for common weaknesses and record every confirmed issue as a finding
argument-hint: "[url]"
---
Test the web application at ${1:-the scoped URL} for common weaknesses and record every confirmed issue as a finding.

## Arguments

- Target: $1
- Extra instructions: $@

## Steps

1. `cyber_crawl` - crawl the target and record the URL structure, the parameters, the forms and the JavaScript endpoints. Raise `depth` and `concurrency` only as far as the scope allows.
2. `cyber_dir_enum` - run content discovery against the paths the crawl found, plus the usual backup, configuration and admin directories. Use the engagement wordlist in `wordlist`, and narrow the noise with `extensions` and `status_codes`.
3. `cyber_vuln_scan` - template scan the confirmed endpoints with nuclei for known issues.
4. `cyber_sqli` - test the parameters the crawl and the enumeration found for SQL injection. Stay with detection: no table drops, no data modification, no stacked queries.
5. `cyber_xss` - test the same parameters for reflected and DOM cross-site scripting.
6. `cyber_record_finding` - record every issue you actually confirmed as a finding: the target, the severity, a short description, the reproduction steps and the evidence. One finding per distinct issue. A template match that you did not verify by hand is a lead, not a finding.

## Rules

- Use only the CyberPi tools named above. Do not run sqlmap, dalfox, ffuf, katana or nuclei yourself.
- Never print session cookies, bearer tokens, API keys or other credential material into the transcript. Describe the value, where it was found and which artifact holds it.
- If a call is refused by the engagement scope, report the refusal and continue with the rest of the sweep.
- Do not submit forms that create accounts, send mail, place orders or trigger outbound notifications, unless the operator named them as in scope.

## Report back

- The URL map: the hosts, the paths, the interesting parameters and the endpoints worth attention.
- The confirmed findings, one line each, with the severity.
- The unconfirmed leads, clearly marked as unconfirmed, with what it would take to confirm them.
- The parameters that still deserve manual testing and why.
