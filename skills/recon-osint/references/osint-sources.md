# OSINT sources and the tool that reaches them

Reference for the `recon-osint` skill. Each section lists the public sources
behind one CyberPi tool, what each source actually gives you, and what to do
with it.

The rule that keeps this phase quiet: **one query per source, per target.**
Re-querying a source does not find more, it only gets the source to rate
limit the engagement's address.

---

## Source map

| Source | Public origin | Yields | Tool |
|---|---|---|---|
| Certificate transparency logs | crt.sh, certspotter, Google CT, Censys certificates | Subdomain names from issued certificates | `cyber_subdomain` |
| Passive DNS | SecurityTrails, DNSDB, CIRCL, RapidDNS, BufferOver | Historical A/AAAA records, first and last seen | `cyber_subdomain` |
| Web archives | Wayback Machine, Common Crawl | Hostnames found in archived URLs | `cyber_subdomain` |
| Search indexes | Bing, DuckDuckGo, Google cache, Yandex | Hostnames in indexed pages, directory listings | `cyber_subdomain` |
| Code hosts | GitHub, GitLab, Bitbucket, Gitea | Organisation repos, usernames, leaked config | `cyber_secret_scan` |
| Public package registries | PyPI, npm, RubyGems, crates.io, Maven Central | Typosquat targets, project usernames, leaked tokens | `cyber_secret_scan` |
| DNS zone data | Recursive resolvers, authoritative servers | A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, CAA, PTR | `cyber_dns` |
| Registry WHOIS / RDAP | IANA, RIRs (ARIN, RIPE, APNIC, LACNIC, AFRINIC), registrars | Registrant, registrar, dates, nameservers, netblock, ASN | `cyber_whois` |
| BGP routing data | Team Cymru whois, bgp.tools, RIPEstat, bgp.he.net | Origin ASN, announced prefixes, routing history | `cyber_whois` |
| Certificate SANs | Any TLS handshake | Alternate names on a certificate | `cyber_http_probe` |
| Live web services | The target's own web servers | Status, title, technologies, TLS, CDN | `cyber_http_probe` |
| Secret stores in code | Repositories, git history, CI configs, images, buckets | API keys, tokens, private keys, passwords | `cyber_secret_scan` |
| Search engine caches | Bing, Google, DuckDuckGo | Employee names, emails, document leaks | theHarvester (see below) |

---

## 1. Subdomain sources - `cyber_subdomain`

subfinder queries a set of passive sources. Which ones it uses is configured
in its own `sources.json`; some need an API key and are silently skipped
without one. Prefer a small set of sources that are fast, free and stable.

### Certificate transparency (the highest yield source)

CT logs are public append-only records of every certificate issued for a
domain. A certificate has to name its subject and its SANs, so a wildcard
certificate for `*.example.com` reveals the shape of the estate even when
the names themselves are not in the log.

| Source | Notes |
|---|---|
| crt.sh | Aggregates Google CT logs. `%.example.com` shows every issued name. Noisy: contains names from years-old certificates and from CT pre-certificates. |
| certspotter | Facebook CT aggregator. Cleaner than crt.sh, returns a compact name list. |
| Google CT | `transparencyreport.google.com` - the underlying log. crt.sh is the practical interface. |
| Censys certificate search | Rich, but needs an account; treat as a later step. |

What to do with a CT name: it may be dead, it may be a third-party host, and it
may be a name that was never deployed. Treat the CT list as a candidate list,
not a host list. Resolve before you trust it.

### Passive DNS

Historical resolution data shows what a name pointed at, and when. Useful
because a host that no longer resolves may still point at infrastructure that
does, and because a name that resolves to the client's netblock is
in-scope-by-ownership.

| Source | Notes |
|---|---|
| SecurityTrails, DNSDB, CIRCL | Account required, best historical coverage. |
| RapidDNS, BufferOver | Free, no account, good for a quick pass. |
| HackerTarget hostsearch | Free DNS lookup table, useful for a second opinion. |

### Web archives and search indexes

Wayback Machine and Common Crawl reveal hostnames that exist in URLs, which
covers internal-style names that were never public DNS records (`jira`,
`wiki`, `git`, `jenkins`, `vpn`). Search engines add directory listings and
error pages that leak internal hostnames.

### Noise to ignore

- Names in CT logs that resolve to a generic SaaS domain (`*.herokuapp.com`,
  `*.azurewebsites.net`) for every customer of that platform.
- Parked domains and Sedo/Afternic parking pages.
- Names from CT pre-certificates that were never deployed.
- `www` and `mail` in every list - they are noise unless something else in
  the record is interesting.

---

## 2. DNS records - `cyber_dns`

`dig` against a recursive resolver. One record type at a time, one host at a
time.

| Record | What it reveals | Actionable when |
|---|---|---|
| A / AAAA | Current address | The address is in the client's netblock, or in a cloud provider range. |
| CNAME | Where the name really lives | The target is a third-party tenant, a decommissioned service, or a bucket. Dangling CNAME = takeover candidate. |
| MX | Mail provider | SPF/DKIM/DMARC providers and mail-security posture follow from it. |
| NS | Where the zone is administered | The same account hosts other zones; the DNS host is often in scope. |
| TXT | SPF, DKIM selectors, DMARC, vendor verifications | `include:` targets name the SaaS vendors; stray verification tokens reveal staging hostnames. |
| SOA | Zone serial, admin contact, refresh timers | Serial numbers change when records move; a stale zone is a signal. |
| SRV | Service discovery (`_sip._tcp`, `_kerberos._tcp`, `_xmpp._tcp`) | Points at VoIP, directory or chat infrastructure. |
| CAA | Which CAs may issue for the zone | A missing CAA plus a hijacked registrar is a real path to a fraudulent certificate. |
| PTR | Reverse DNS | Forward-confirmed reverse DNS plus a matching TLS SAN is strong evidence a host is in scope. |
| DNSKEY / DS | DNSSEC status | An unsigned zone is a downgrade opportunity; note it, do not exploit it. |

**Dangling detection.** A CNAME points at a third-party resource
(`bucket.s3.amazonaws.com`, `gh-pages.io`, `herokuapp.com`) that no longer
exists. The name still resolves in CT logs, and the third party may still
accept the claim. Verify the resource is genuinely unclaimed before recording
a takeover finding, and never attempt to claim it - claiming it is an
unauthorized write against a third party.

**Split horizon.** A name that resolves publicly to a load balancer and
privately to an internal address is normal. Do not treat the public answer as
the whole estate.

---

## 3. Ownership, registry and ASN - `cyber_whois`

WHOIS gives the legal and technical ownership of a domain or an address
block. Run it once per registrable domain and once per netblock you need to
understand.

| Source | Query | Yields |
|---|---|---|
| IANA WHOIS | `whois.iana.org` | The authoritative pointer to the registry for a TLD. |
| Registry WHOIS | `whois.arin.net`, `whois.ripe.net`, `whois.apnic.net`, `whois.lacnic.net`, `whois.afrinic.net` | Registrant, registrar, dates, nameservers, netblock, abuse contact. |
| Registrar WHOIS | `whois.<registrar>` | Creation and expiry dates, status codes (`clientTransferProhibited`, `clientHold`), registrar contact, DNSSEC. |
| RDAP | `rdap.org` bootstrap, or the RIR's own RDAP endpoint | The same data as WHOIS over JSON, more reliable to parse and no port 43 rate limit. |
| Team Cymru whois | `whois.cymru.com` using the ` -v <prefix>` form | Origin ASN and prefix for an IP address. |
| bgp.tools / RIPEstat | HTTP | Prefix history, RPKI validation state, who announced the block and when. |
| bgp.he.net | HTTP | Searchable ASN and prefix history. |

### Reading the ownership record

- **Registrant versus registrar.** The registrant is often redacted (GDPR,
  registry privacy). The registrar, the nameservers and the netblock are
  usually not. Redacted registrant is not an unknown owner.
- **Dates.** Creation date inside the engagement window, or a very recent
  registration, is worth noting - a domain registered two weeks before the
  engagement is a possible decoy or a newly spun-up phishing target.
- **Status codes.** `clientHold` and `clientDelete` mean the domain is
  suspended or pending deletion. A suspended domain with a stale CT record
  and a dangling CNAME is a takeover candidate.
- **Netblock and ASN.** The netblock tells you which of the discovered
  addresses are the client's own. The ASN tells you the provider. A reseller
  or shared-hosting ASN means neighbouring addresses are other tenants and are
  out of scope even though they share the prefix.

### IP range and ASN discovery

1. Take the netblock from the domain WHOIS.
2. Take the ASN from the IP WHOIS.
3. Compare every discovered address against the netblock.
4. Report the addresses that fall outside the client's own range, and the
   ranges that look like hosted infrastructure the client may have forgotten.

Enumerating a whole netblock is a scanning action, not a recon action: it
belongs to `cyber_portscan` and needs its own scope rule for the CIDR.

---

## 4. Live web services - `cyber_http_probe`

httpx turns a host list into the list of things that actually answer. It is
active: it opens a TCP connection to every host, so it is scoped and
journalled like any other action.

| Signal | Source | Use |
|---|---|---|
| URL, status, method | The host's own HTTP server | The inventory of live services. Status 3xx with a login redirect is an access-control surface. |
| Title | The HTML `<title>` | Dashboard names, "Internal Use Only", employee names, framework defaults. |
| Technology | Header and body fingerprints | Product and version, which feeds the CVE phase. |
| TLS | Certificate chain | Issuer, expiry, SANs (more hostnames), protocol version. A weak protocol or an expired certificate is a finding on its own. |
| CDN / WAF | Response headers and CNAME | Cloudflare, Akamai, AWS CloudFront. A CDN front end is not the origin; find the origin before trusting the edge. |
| Favicon hash | The `/favicon.ico` body | Matches a shodan-style index of hosts running the same product. |
| Web server banner | Response headers | Product and version, often more precise than the technology guess. |
| Redirect chain | Each hop | Where a staging host redirects to a production host, and vice versa. |

Notes on noise: a host behind a shared CDN answers with the CDN's
characteristics, not the origin's. A wildcard redirect on a domain makes
every path look like a service. A captive portal or a parked page answers on
port 80 and is not a real service.

---

## 5. Secret exposure - `cyber_secret_scan`

trufflehog scans code, git history, files and buckets for credentials, and
reports the detector that matched plus the verification status.

### Detector families worth acting on

| Family | What it finds | Why it matters |
|---|---|---|
| AWS | Access key IDs, secret access keys, session tokens | Grants access to the client's own cloud account. |
| GCP / Azure | Service account JSON, storage keys | Same, in the other clouds. |
| GitHub / GitLab / Bitbucket | Personal access tokens, app tokens, deploy keys | Write access to the code, and from there to everything the pipeline can reach. |
| SSH / private keys | RSA, ECDSA, Ed25519, DSA, OpenSSH, PGP, Putty keys | Direct access to hosts the key was used on. |
| Generic API key / password | High-entropy strings in known key formats, password assignments | Needs context to judge; always read the surrounding code before reporting. |
| SaaS tokens | Slack, Stripe, Twilio, SendGrid, Mailchimp, Shopify, Datadog, npm, PyPI, Docker Hub, Sentry | The account is the finding; a mail API key can send phishing mail from the client. |
| Database and connection URIs | `postgres://`, `mongodb://`, `redis://`, `amqp://` with inline credentials | Direct database access. |

### Where to point it

| Target | Notes |
|---|---|
| A local clone | Runs over the working tree and the full git history. History is where deleted secrets live. |
| A public organisation or user | Needs a GitHub token; finds repositories the organisation owns, including ones it forgot. |
| A bare repository on disk | Useful when a repository was dumped locally. |
| Containers and images | Secrets baked into layers. |
| Cloud buckets | Needs cloud credentials for the account being tested - and those credentials must themselves be in scope. |
| Password files | A `.env`, a `credentials` file, a `wp-config.php`, a `settings.py`. |

### Related exposure that is not a secret detector's job

- Public repositories containing infrastructure definitions, IaC, or
  deployment configuration.
- CI workflow files that reference secrets by name - the name and the
  owning organisation are already useful to an attacker.
- `.git` directories left in web roots, `backup` files, `~` editor copies.
- Package registries: a published package that ships the client's
  configuration, or a typosquat of the client's package name.

### On leaked credential lookups

CyberPi does not query third-party breach databases. Those are other
customers' data on other people's systems, and a lookup against them is
neither authorized by this engagement nor relevant to the client's own
exposure. Exposure of the client's credentials is found where the client
actually leaks them: their repositories, their artifacts, their cloud
accounts. Once a credential is found, cracking a discovered hash or validating
a credential against a client-controlled service is the credential phase
(`cyber_hash_id`, `cyber_hash_crack`), not recon.

**Raw secret material never goes into the transcript.** Record the detector,
the file, the repository and the commit; point at the artifact file for the
value.

---

## 6. Email and employee harvesting

`theHarvester` is a Kali binary (`sudo apt install theharvester`) that queries
search engines and social platforms to collect email addresses, hostnames,
IP addresses and employee names for a domain. Its sources are the free search
endpoints - Bing, Google, DuckDuckGo, Baidu, Yandex, LinkedIn, Twitter - plus
certificate transparency and the DNS zone.

CyberPi does not currently wrap theHarvester in a tool, so it is run directly
on the Kali host, and the results are recorded by hand:

- Raw output into `.cyberpi/artifacts/` so it is part of the engagement
  record.
- The harvested hosts and addresses into the target list, and into the
  surface index.
- An address that resolves to a client-owned netblock is a host worth
  probing; an address at a public mail provider is a mail-only contact.

Emails gathered this way are for mapping, not for phishing. Sending anything
to them, or testing them against systems, is a separate authorization and a
separate phase. Password-reset or credential-stuffing attempts against
harvested addresses are the credential phase (`cyber_password_audit`) and
need the `password-audit` technique authorized.

---

## 7. Building the target list

Recon produces a target list, and the target list is what the next phase
consumes. Keep it as a file, one entry per line, with the source recorded:

```text
# .cyberpi/notes/targets.md
# host | ip | source | note
api.example.com | 192.0.2.10 | subfinder/ct | A record
dev.example.com | 192.0.2.11 | subfinder/ct | staging, Apache 2.4
```

Rules that keep the list usable:

- Only hosts that resolved, or that are explicitly worth resolving, belong in
  the list. A candidate list and a host list are different things.
- Record the source of every entry, so a later phase can weigh a
  certificate-transparency name differently from a name that appeared in a
  GitHub config.
- Record out-of-scope discoveries in the notes as well, clearly marked. The
  operator decides what to do with them; the agent does not touch them.
- The surface index (`.cyberpi/surface.json`, read with `cyber_surface`) is
  the machine-readable form of the same information. Recon should leave it
  populated, so the next phase reads it instead of re-scanning.

---

## 8. Source reliability

| Signal | Trust it | Do not trust it |
|---|---|---|
| CT name | That a certificate was issued for it | That the host exists now, or that it is the client's |
| Passive DNS | That the name pointed somewhere at some point | That it points there now |
| Search engine hit | That the string appears in indexed content | That the page is still up, or that the content is current |
| WHOIS registrant | The registrar, dates, nameservers, netblock | A redacted registrant, or an email address in the WHOIS record |
| HTTP title | That the page has a title | That the title describes the current function of the host |
| Tool-reported technology | A strong hint | A precise version - confirm it against a real banner |
| Public repository | That the code was public | That it is still the code that runs in production |
