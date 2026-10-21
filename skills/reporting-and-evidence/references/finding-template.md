# Finding template

Reference for the `reporting-and-evidence` skill. Copy the template for each
finding, fill every field, then record it with `cyber_record_finding`.

## The record

```
ID:        F-001
Title:     <one specific claim: what is wrong, and where>
Severity:  info | low | medium | high | critical
CVSS:      <0.0 - 10.0, optional>
CVE:       <optional>
CWE:       <optional>
Target:    <host:port or the exact URL>
Tags:      <grouping labels: web, ad, wireless, cloud, creds>
```

The record status is stamped by the harness when the finding is written, not
by you. Confirmation is expressed by the reproduction and the evidence below.

## Description

What the condition is, exactly where it is, and how it was observed. Include
the proof: the marker, the response code, the banner, the error. A reader
must be able to tell from this paragraph that the issue is real, and where
the boundary of your testing was.

## Impact

What an attacker gains, from what, and with how much effort. Name the asset
at stake (data, account, host, key) and the prerequisite (network access, a
user click, any credentials). If you could not verify the impact, say so
and say what would be needed to verify it.

## Reproduction

The exact steps, in order, re-runnable by a third party with the same tools.
Spell out the target, the credentials used and any prerequisite state. Keep
it to the minimum that demonstrates the issue — this is a proof, not a
tutorial. The field is rendered as a command block, so give the commands
themselves; a manual test is given as numbered steps on one line each.

```
<command 1>
<command 2>
```

## Evidence

- `.cyberpi/artifacts/<file>` — <the single line from it that proves the claim>

Keep each entry to one line: a path, or a quoted line. Never paste
credentials, cookies, tokens or personal data here; point at the artifact
and describe it instead.

## References

- <advisory or documentation URL>

## Recording it

```
cyber_record_finding:
  title: "<title>"
  severity: "<severity>"
  target: "<target>"
  description: "<description>"
  impact: "<impact>"
  reproduction: "<reproduction>"
  evidence:
    - "<artifact path or quoted line>"
  cvss: <score>
  cve: "<cve>"
  cwe: "<cwe>"
  references:
    - "<url>"
  tags: ["<tag>"]
```

Omit `id` to let the harness allocate the next one (`F-001`, `F-002`, …).
Pass an existing `id` to update that finding: the file is replaced, so
re-record the complete finding, not only the field that changed.

## Field guidance

| Field | What belongs there | What not to write |
| --- | --- | --- |
| Title | The claim, singular and specific: "Expired TLS certificate on edge.example.com". | "TLS issues", "Potential vulnerabilities". |
| Severity | The rating, justified in the description. | A number copied from a scanner, or the CVE's global score. |
| CVSS | The base score you computed, with the vector in the reproduction or the notes. | A score for a finding you did not verify end to end. |
| CVE / CWE | Identifiers that match the product version you actually observed. | A CVE that merely sounds related. |
| Target | `host:port` or the full URL, including the scheme. | "The web server", a hostname with no port. |
| Description | Condition, location, observation method, proof. | A restatement of the title, or a tool's raw output pasted in. |
| Impact | Attacker capability, asset at stake, prerequisite, effort. | "Could lead to compromise", "May result in data breach". |
| Reproduction | Ordered, minimal, re-runnable steps with the exact commands. | A paraphrase, or steps that need state you never created. |
| Evidence | Artifact path plus the one line that proves the claim. | A summary of the artifact, or a credential. |
| References | The advisory URL, the vendor fix, the standards reference. | A search result, a blog aggregator. |
| Tags | Grouping labels used in the report and in the dashboard. | Free-text notes. |

## Worked example

A finding recorded against a web application, in the shape the report
renders it:

```
ID:        F-002
Title:     Reflected XSS in the search parameter on /search
Severity:  medium
CVSS:      6.1
CVE:       -
CWE:       CWE-79
Target:    https://app.example.com/search
Tags:      web, xss

## Description

The `q` parameter of /search is reflected into the HTML response without
encoding. Sending `q=<img src=x onerror=alert(document.domain)>` returns a
200 response whose body contains the payload verbatim inside the results
banner, and the Content-Type is text/html. The reflection is in a parameter
that requires no session, so any user who can be lured to a crafted link
executes the script in their own browser.

## Impact

An attacker who delivers a crafted /search link to an authenticated user of
app.example.com executes script in that user's session, and can read the
session data and issue requests with their privileges. The application
requires a session for the results area, so the practical impact is session
theft rather than direct access to the account of the attacker.

## Reproduction

1. curl -sk 'https://app.example.com/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E' -o /tmp/xss.html
2. grep -o '<img src=x onerror=alert(1)>' /tmp/xss.html
   The payload appears unencoded in the response body.

## Evidence

- .cyberpi/artifacts/web-xss-search-2025-03-14.txt - the response body line
  `<div class="results-banner">` contains the raw payload.

## References

- https://owasp.org/www-community/attacks/xss/
```

Recorded as:

```
cyber_record_finding:
  title: "Reflected XSS in the search parameter on /search"
  severity: "medium"
  target: "https://app.example.com/search"
  description: "The q parameter of /search is reflected into the HTML response without encoding. Sending q=<img src=x onerror=alert(document.domain)> returns a 200 response whose body contains the payload verbatim inside the results banner, and the Content-Type is text/html. The reflection is in a parameter that requires no session, so any user who can be lured to a crafted link executes the script in their own browser."
  impact: "An attacker who delivers a crafted /search link to an authenticated user of app.example.com executes script in that user's session, and can read the session data and issue requests with their privileges. The application requires a session for the results area, so the practical impact is session theft rather than direct access to the attacker's own account."
  reproduction: "curl -sk 'https://app.example.com/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E' -o /tmp/xss.html\ngrep -o '<img src=x onerror=alert(1)>' /tmp/xss.html"
  evidence:
    - ".cyberpi/artifacts/web-xss-search-2025-03-14.txt"
    - "The response body line <div class=\"results-banner\"> contains the raw payload."
  cvss: 6.1
  cwe: "CWE-79"
  references:
    - "https://owasp.org/www-community/attacks/xss/"
  tags: ["web", "xss"]
```

Note what the example does not contain: no credential, no session cookie, no
paste of a full response body, and no claim that was not reproduced. The
artifact holds the raw material; the finding holds the proof and the path.

## Merging and correcting findings

- The same issue on many hosts is one finding. List the affected targets in
  the description and name the range in the title ("... on 12 hosts of the
  app tier").
- To correct a finding, re-record it with the same `id`. The file is
  replaced, so send every field, not only the changed one.
- A finding that stopped reproducing is not a finding. Re-record it with the
  corrected text, or remove it, and say in the report that it was tested and
  did not reproduce.
