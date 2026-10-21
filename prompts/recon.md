---
description: Run a full reconnaissance sweep on a target and record the results in the surface index
argument-hint: "[target]"
---
Run a full reconnaissance sweep against ${1:-the target in the engagement scope} and record every result in the engagement surface index.

## Arguments

- Target: $1
- Extra instructions: $@

## Steps

1. `cyber_subdomain` - enumerate the subdomains of the target domain. Pass the domain in `domain`, and use `domain_list` when you already have several domains to work through.
2. `cyber_dns` - resolve the target domain. Pass the domain in `domain` and the record type in `record_type`; collect the A and AAAA records, the nameservers, the mail exchangers and the TXT records. Repeat the lookup for the apex domain and for every subdomain that step 1 discovered.
3. `cyber_whois` - collect the registration data for the target domain in `domain`: registrar, creation and expiry dates, nameservers, registrant contacts, country and netblocks.
4. `cyber_http_probe` - probe the discovered hosts over HTTP and HTTPS, following redirects. Capture the status code, the page title, the technology stack and any header that looks interesting.
5. `cyber_surface` - read the merged surface index and confirm that the hosts, services and endpoints from the steps above actually landed in it.

## Rules

- Use only the CyberPi tools named above. Do not run subfinder, dig, whois or httpx yourself.
- Every call is scope-checked and journalled. If a call comes back blocked, do not work around it. Report which target was refused and by which rule, then continue with the rest of the sweep.
- If the argument is empty, ask the operator for the target instead of guessing one.
- Keep raw scanner output out of the transcript. Summarise the counts and the notable values, and point at the artifact files under `.cyberpi/artifacts/`.

## Report back

- The subdomains discovered, as a count plus the list.
- The DNS records of interest: nameservers, mail exchangers, and any TXT record that reveals a cloud provider, a mail service or a verification token.
- The WHOIS summary: registrar, creation date, expiry date, nameservers, country, and any registrant data the client published.
- The live web endpoints: URL, status code, title and technology.
- Anything anomalous: dangling records, default hosts, staging or development subdomains, exposed admin panels, and certificate or DNS misconfiguration.
- The next three things worth scanning.
