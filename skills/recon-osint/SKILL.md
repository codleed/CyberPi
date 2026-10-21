---
name: recon-osint
description: Passive and active reconnaissance of an authorized engagement target - subdomain enumeration, DNS record mapping, WHOIS/ASN/netblock ownership, live HTTP service discovery, and secret or credential exposure hunting. Use when asked to recon a domain, enumerate subdomains, map DNS records, look up registrant or ASN ownership, find live web services, build a target list, or hunt for leaked API keys and exposed Git repositories.
---

# Reconnaissance and OSINT

Turn a domain into a defensible picture of the target: what hosts exist, what
they resolve to, who owns them, which web services are alive, and where
credentials or secrets are exposed. Reconnaissance is the phase that decides
what every later phase can attack, so it is worth doing once, carefully, and
recording properly.

CyberPi wraps five tools for this phase. Everything else in this skill is
sequencing and hygiene around them.

| Tool | Binary | Technique | Returns |
|---|---|---|---|
| `cyber_subdomain` | subfinder | `recon` | Subdomain names for a registrable domain, with the passive source that found each one |
| `cyber_dns` | dig | `recon` | Resolved records for a host (A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, CAA, PTR) |
| `cyber_whois` | whois | `recon` | Registration and network ownership: registrar, dates, nameservers, ASN, netblock |
| `cyber_http_probe` | httpx | `recon` | Live web services per host: URL, status, title, technologies, TLS and CDN hints |
| `cyber_secret_scan` | trufflehog | `password-audit` | Exposed secrets in code, git history, files and buckets, with the detector that matched |

`references/osint-sources.md` lists the public data sources behind each tool,
the records worth looking at, and the sources that are noise.

## Scope comes first

Every network action is checked against `.cyberpi/scope.json` before it runs,
and every action is written to the engagement journal. Scope rules behave like
this:

- A bare domain (`example.com`) covers that host **and** its subdomains.
- `*.example.com` covers subdomains only, not the apex.
- `exact:example.com` covers that host only.
- A CIDR (`192.0.2.0/24`) covers addresses, and the port/protocol/technique
  filters on the rule apply to every action inside it.

Two rules to respect:

1. If a call comes back **"Blocked by engagement scope"**, do not try another
   spelling, another tool or a different host form to get around it. Report
   the refusal verbatim and say which scope line would need to change. The
   operator amends the scope, not the agent.
2. The technique allowlist is separate from the target list. `cyber_secret_scan`
   carries the `password-audit` technique, so it needs that technique allowed
   even when the target is in scope. A block on the technique is a
   configuration change, not a problem to route around.

Prefer running a tool against a host that is already authorized over
widening the search. If a discovery turns up a host outside scope, record it
as a note and mention it to the operator - do not probe it.

## Workflow

Run the phases in this order. Each phase feeds the next, and every phase is
cheap because the previous one narrowed the list.

### Phase 0 - Normalize the target

Establish what the engagement is actually about before running anything: the
registrable domain (strip the subdomain for WHOIS and ownership work), the
known IPs, and any assets named in the scope file. Write this down first - it
becomes the target list.

### Phase 1 - Passive subdomain enumeration

```
cyber_subdomain  target: example.com
```

Passive sources first: certificate transparency logs, passive DNS, web
archives, search indexes. This touches third-party infrastructure, not the
client's, so it is the cheapest way to build breadth and the safest step in
the engagement.

Read the output for:

- Names that resolve to the client's own address space (the real estate).
- Names pointing at third-party SaaS - a dangling CNAME to a deprovisioned
  S3 bucket, an unclaimed GitHub Pages site, a stale Heroku app. These are
  takeover candidates, and they belong in the findings, not just the notes.
- Names that look like infrastructure (`dev-`, `staging-`, `uat-`, `vpn-`,
  `jenkins-`, `k8s-`, `*.internal`). They are the highest-value names to
  probe next.

Do not run a second enumeration pass with different flags unless the first one
came back suspiciously small. If it did, change one thing (a source, or the
wordlist) and note why.

### Phase 2 - DNS record mapping

Resolve the interesting names, not all of them:

```
cyber_dns  target: api.example.com  record: A
cyber_dns  target: example.com       record: MX
cyber_dns  target: example.com       record: TXT
```

Records that carry intelligence rather than just addresses:

- **TXT** - SPF `include:` targets reveal third-party mail and SaaS vendors;
  `_dmarc` reveals the mail posture; `include:` and `v=spf1` tokens are
  sometimes the only place a staging hostname is mentioned.
- **CNAME** - where the host lives. A CNAME into a public bucket, a
  vendor's tenant domain or a decommissioned service is a takeover lead.
- **MX** - the mail provider, and therefore the SPF/DKIM/DMARC providers.
- **NS** - the DNS host, which tells you where the zone is administered and
  which other names are in the same account.
- **SRV** - service discovery; `_sip._tcp` and `_kerberos._tcp` point at VoIP
  and directory services.
- **CAA** - which certificate authorities are allowed to issue for the zone.

A host that does not resolve is not an error; it is the interesting case, and
it is where dangling records hide.

### Phase 3 - Ownership, ASN and netblock

```
cyber_whois  target: example.com
```

Run WHOIS **once per registrable domain**, never per subdomain - the registry
record is the same for all of them and repeated lookups are pure noise.

From the WHOIS output you get the netblock and the ASN. Two things follow:

- Every discovered IP that falls inside the client's own netblock is in
  scope by ownership even when it was never named. Cross-check it against the
  scope file and report the ones that are not, instead of scanning them.
- The ASN identifies the hosting or cloud provider. A shared-hosting ASN
  means neighbouring hosts are other tenants and are out of scope; a cloud
  provider ASN with named prefixes suggests owned cloud assets worth
  enumerating separately.

### Phase 4 - Live web service discovery

```
cyber_http_probe  target: dev.example.com
cyber_http_probe  target: 192.0.2.10
```

Probe the hosts that resolved in phases 1 and 2, starting with the ones whose
names suggest they are interesting. httpx tells you, per host: which schemes
answer, the status code, the page title, the technology stack, TLS details
and the CDN in front of it.

Read it for:

- **Technologies** - the stack and version feed directly into
  `cyber_cve_lookup` and `cyber_exploit_map` later.
- **Status codes** - a 302 to a login page, a 403 on a host that should be
  public, a 500 on a dev instance, a 200 on something that should not be
  reachable.
- **Titles** - names, dashboards, staging banners, internal hostnames, and
  occasionally a personal name in a page title.
- **Cloud buckets and CDNs** - a title or URL that exposes a bucket name
  turns a hostname into a storage target.

A host that does not answer HTTP is still a host. It may only speak another
protocol; that is the port-scan phase, not this one.

### Phase 5 - Secret and credential exposure

```
cyber_secret_scan  target: /path/to/clone     # a repository or directory
cyber_secret_scan  target: github.com/org      # an organisation
```

Secret scanning is a `password-audit` technique, so it is separately
authorized - confirm the technique is allowed before running it.

Look for:

- Cloud keys (AWS access keys, GCP service account JSON, Azure storage
  credentials) that point at infrastructure the client owns.
- Repository and CI tokens (GitHub, GitLab, Slack) that give write access.
- Private keys committed to a repository, including in git history, not just
  in the current tree.
- `package-lock.json`, `Dockerfile`, `.env`, and CI workflow files that
  reference secrets by name, even when the value is not in the file.

**Never print the secret.** Do not paste a key, password, session cookie or
token into the transcript or into a finding's evidence. Summarise it - the
detector, the repository or path, the file, the kind of credential - and point
at the artifact file under `.cyberpi/artifacts/` that holds the raw value.
The credential is evidence, and evidence belongs in the engagement directory.

A credential found on a public source is a leak, not a proven compromise. Say
"exposed in a public repository" until it has been validated against a
client-controlled asset, and record it with `cyber_record_finding` once
validated.

### Phase 6 - Consolidate

Everything above is only useful if it lands somewhere durable. See
"Recording results" below. Reconnaissance is finished when the target list
and the surface index answer the question "what is there" without another
scan.

## Passive before active

Passive enumeration first, always. It costs the client nothing, it does not
touch their infrastructure, and it frequently returns 80 percent of the
host list in a fraction of the time. Only then probe the hosts that resolved.

If a client asks for speed, the answer is a smaller active phase, not a
noisier one.

## How to avoid noisy tools

Noise costs more than it looks: it slows the engagement, it burns the
client's tolerance, and it fills the journal with entries nobody can read.

- **Do not re-run what already ran.** Identical calls are cached by the
  toolkit and return instantly. A repeated scan with a changed flag is a
  fresh scan, so change one thing at a time and say what you changed.
- **Do not run brute-force resolvers here.** Wordlist DNS bruteforce and
  resolver hammering belong to a later, explicitly requested phase. The
  passive list plus a smart look at the names is enough for this phase.
- **Do not run the whole subdomain source set.** Enabling every passive
  source multiplies the query count for a handful of extra names. Pick the
  sources that matter for this target, and prefer CT logs and passive DNS.
- **Do not port scan from this skill.** Service enumeration is
  `cyber_portscan` and `cyber_service_scan`; recon only needs to know that
  a host is alive. Keep the phase boundary, it keeps the journal readable.
- **Do not brute force web paths.** No directory enumeration, no login
  guessing. `cyber_dir_enum` and the credential skills own that, and both
  need their own authorization.
- **Do not WHOIS every host.** One registry lookup per registrable domain.
  Use `cyber_dns` for the rest.
- **Do not re-probe the same host many times.** Probe 80/443 first, then
  expand on the hosts that answered.
- **Keep concurrency moderate.** Default thread counts on httpx and subfinder
  are sane. Raising them to "go faster" is what gets an engagement's source
  IP blocked, and a blocked IP ends the phase.
- **Do not add tools.** If the five wrappers cannot answer the question,
  say so and propose the additional source; do not shell out to something
  outside the registry, because that action would bypass scope checks and
  would not be journalled.
- **Do not report recon output as findings.** A list of subdomains is a
  result, not a vulnerability. Findings are for exposure with impact.

## Recording results

Three destinations, three different purposes.

1. **The journal** - automatic. Every command, target, exit code, duration
   and artifact path is appended to `.cyberpi/journal.jsonl`. Read it with
   `cyber_journal` when you need to show what was done or prove the order of
   operations. Never edit it.

2. **The surface index** - `.cyberpi/surface.json`, written through the
   tools. Hosts discovered by `cyber_subdomain` and resolved by `cyber_dns`
   become entries; live web services found by `cyber_http_probe` become
   services and endpoints. This is the answer to "what does this target
   have", and the next phase should read it with `cyber_surface` instead of
   re-running scanners. Merge the results; do not re-derive them.

3. **Findings** - `.cyberpi/findings/`, written with `cyber_record_finding`.
   File a finding when there is impact, not when there is data. Qualifying
   findings from recon:
   - a dangling CNAME or unclaimed third-party hostname that can be taken
     over;
   - a credential or key found in a public or reachable source;
   - an internal or development host exposed to the internet;
   - a host, bucket or repository outside the authorized scope that is
     owned by the client and reachable;
   - a public repository, backup file or directory listing holding sensitive
     material.

   Each finding gets the target, the impact, and a reproduction that a
   third party can follow. Evidence lines point at artifact files, not at
   inline secrets.

Keep the raw list of discovered names, emails and hosts in the engagement
notes (`.cyberpi/notes/`) as a target list, so the next phase starts from a
file rather than from a memory of a transcript. The target list is a working
document: one host or URL per line, with a note of how it was found.

## Handoff

- Live hosts and open ports -> the network phase (`cyber_portscan`,
  `cyber_service_scan`).
- Live URLs and the technologies httpx reported -> the web phase
  (`cyber_crawl`, `cyber_dir_enum`, `cyber_vuln_scan`).
- Products and versions -> the CVE phase (`cyber_cve_lookup`,
  `cyber_exploit_map`).
- Hashes or credential material -> the credential phase. Note that
  `cyber_secret_scan` finds secrets; cracking found hashes is
  `cyber_hash_id` and `cyber_hash_crack`.

## When a tool fails

- A non-zero exit is not a finding. Read the stderr before drawing a
  conclusion, and report the real error.
- A "Missing required tool(s)" message means the Kali package is not
  installed. Relay the install line and stop that phase; do not imitate the
  output of a tool that did not run.
- Output is truncated for the transcript. The full output is in the artifact
  file the journal points to - read the file when the summary is not enough.
- Nothing in this skill should ever produce a plausible-looking result for a
  command that did not run.
