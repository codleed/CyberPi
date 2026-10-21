---
name: service-enumeration
description: Port scanning and service identification with naabu and nmap. Use when the task is to find open ports, identify which services and versions are running, select or run NSE scripts, grab banners, scan UDP, or enumerate SMB, RDP, SSH, SNMP, MQTT, mail, database or TLS services on a scoped target. Triggers on "what is running on this host", "which ports are open", "identify the services on <ip>", "fingerprint the SSH/SMB server", "is SNMP open", "what is on port 8080".
---

# Service enumeration

Find the open ports on a scoped target, identify what is actually listening on them, and
fold the result into the engagement's surface index.

The order matters: a fast sweep first, then a targeted service scan on the ports that
answered. Running nmap's version detection across a whole /24 on all 65535 ports is slow
and noisy, and it usually finds nothing that a sweep plus a targeted scan would not.

## Tool contract

| Tool | Technique | Binary | Use it for |
|---|---|---|---|
| `cyber_portscan` | `port-scan` | naabu | Fast sweep to find which ports answer, TCP and UDP |
| `cyber_service_scan` | `service-enumeration` | nmap | Service/version detection and NSE scripts on known ports |
| `cyber_capture` | `recon` | tcpdump | Packet capture to prove what protocol a port really speaks |

Parameters and what they become:

| Tool | Parameters | Command |
|---|---|---|
| `cyber_portscan` | `target` (required), `ports`, `rate`, `top_ports` | `naabu -host <target> -json -silent -Pn -rate <rate>` plus `-p <ports>` or `-top-ports <n>` |
| `cyber_service_scan` | `target` (required), `ports`, `nse_scripts`, `timing` (`paranoid`/`normal`/`aggressive`), `version_only` | `nmap -sV -Pn -T<0\|3\|4> -oX -` plus `-p <ports>` and `--script <nse_scripts>` |
| `cyber_capture` | `target`, `port`, `duration_seconds`, `interface` | `tcpdump -U -w <artifact>.pcap` plus `-i <interface>` and the `host`/`port` filter |

Things to know about the wrapper:

- Version detection (`-sV`) and the host-discovery skip (`-Pn`) are always on for the
  service scan. There is no switch to turn version detection off, and host discovery is
  never performed, so a host that does not answer ping is still scanned.
- `timing` maps to nmap's `-T0`, `-T3` and `-T4`. Use `paranoid` for a fragile client
  device and `aggressive` for a lab host where you want the scan to finish quickly.
- `version_only` switches the scan to `--version-light` and skips NSE scripts entirely.
  Use it for a broad "what is this" pass, then a second scan with `nse_scripts` on the
  interesting ports.
- `nse_scripts` takes nmap's script syntax: `http-title,safe`, `smb-enum-*`, or a
  `category` such as `default` or `discovery`.
- The service scan parses nmap's XML output, so the structured result is in the tool
  details and the readable summary is in the transcript. The raw run is written to the
  engagement artifact directory.
- Always go through these tools. A raw `nmap` from the shell is not scope-checked and
  not journalled, which breaks the engagement record. If a recipe below needs something
  the tool cannot express, say so and hand the operator the exact command.
- Never print raw credentials, session cookies, keys or tokens into the transcript. If a
  script returns one, summarise the finding and point at the artifact file under
  `.cyberpi/artifacts/`.

## Decision flow

```
target known?
├─ no  → do not scan. Get the target from the operator or from the surface index.
└─ yes → is it in .cyberpi/scope.json?
         ├─ no  → STOP. Report the refusal and the rule that would cover it.
         └─ yes → 0. scope filters (ports/protocols) can refuse the sweep
                    │
                    ├─ refused → tell the operator, do not work around it
                    └─ allowed → 1. fast sweep (cyber_portscan)
                                  │
                                  ├─ no open ports → check host reachability, then a
                                  │                  targeted scan of the ports the
                                  │                  client expects (see below)
                                  └─ open ports found
                                         → 2. targeted service scan on those ports
                                           (cyber_service_scan)
                                            │
                                            ├─ unclear or odd service → 4. capture
                                            │                              (cyber_capture)
                                            ├─ identified services     → 3. read the
                                            │                             banners
                                            └─ UDP services in scope   → 5. NSE scripts
                                                                         and UDP
                                                                         → 6. surface
                                                                            index
                                                                         → 7. findings
```

### Step 0 — the authorization gate

Before the first packet, confirm:

1. The target matches a rule in `.cyberpi/scope.json`. A bare domain rule covers the
   domain and its subdomains; `*.example.com` covers subdomains only; `exact:example.com`
   covers the host alone; a CIDR covers the range.
2. The top-level `techniques` list allows `port-scan` and `service-enumeration`. If the
   list is empty, every technique is allowed for the listed targets.
3. Time window and client contact details, if the scope file records them. A closed
   window is a stop condition even when the target matches.

Two scope behaviours surprise people, and both end in a refusal that is journalled:

- A rule that restricts `ports` refuses the sweep tools, because the sweep cannot tell
  the engine which port it is about to touch. The refusal names the allowed ports.
  The fix is an operator decision: widen the rule, or run one scan per permitted port
  through `cyber_capture`-style targeted work. Do not work around it.
- A rule that restricts `protocols` refuses the sweep tools for the same reason — the
  protocol is unknown until the scan is under way. `cyber_capture` declares a port, so
  it is checked against a port filter; the sweep tools are not.

Do not attempt to defeat a refusal. Report the rule, the target and what it would take
to authorize the action, and let the operator decide.

### Step 1 — fast sweep

`cyber_portscan` (naabu) answers "which ports reply" in seconds.

- `target` accepts a host, an IP or a CIDR. A CIDR sweep is the normal way to cover a
  network segment.
- `ports` takes nmap/naabu port syntax: `1-1024`, `80,443,8080`, `22-25`. `top_ports`
  scans only the N most common ports instead — use it for a first look at a large
  segment.
- `rate` is packets per second. The harness default is 1000. On a WAN link or a fragile
  customer device, drop to 300–500: too high a rate produces dropped packets, false
  negatives, and noisy IDS alerts. On a lab LAN, 2000–5000 is fine.
- The sweep records every answering port in the surface index, with the protocol, but
  without a service name. The service scan fills in the product and version later.
- Exclude hosts behind Cloudflare or a WAF from a full-range sweep, otherwise you will
  "discover" a thousand CDN edges and chase a phantom attack surface.
- Reuse a sweep you already ran: identical calls are cached by the toolkit, so a repeat
  is free.

Do not skip the sweep. It gives you the port list, the host liveness and a clean
baseline before any version detection changes the picture.

### Step 2 — targeted service scan

Take the open ports from step 1 and scan exactly those with `cyber_service_scan`:

- One scan across all live hosts with the shared port list is much faster than one scan
  per host, and it keeps the results comparable.
- Version detection is always on, so the scan turns `http` into `Apache/2.4.29
  (Ubuntu)` on its own. The cost is one or two probes per port, which is cheap on a
  handful of ports and expensive on 65535.
- `nse_scripts` runs the scripts. Keep the first pass to `version_only` and add scripts
  on the second pass, once you know what is actually listening.
- `timing: "aggressive"` finishes faster on a lab host; `timing: "paranoid"` slows
  everything down for a device that drops packets under load.

Interpret the state column carefully:

| State | Meaning |
|---|---|
| `open` | The service answered. |
| `closed` | The host replied with RST — nothing is listening, firewall allowed the packet through. |
| `filtered` | No reply at all — the packet was dropped. A firewall is in the path. |
| `open\|filtered` | UDP only: no reply received. Treat as "maybe open", never as "closed". |
| `reason syn-ack` | Confirmed by a SYN/ACK. |
| `reason no-response` | Nothing came back; treat the port as filtered, not closed. |

### Step 3 — banner interpretation

Version detection already captures banners. A separate banner grab is only needed when
the version is unknown or the service is not text-based.

What to extract from a banner:

| Banner fragment | Reading | Next step |
|---|---|---|
| `SSH-2.0-OpenSSH_8.2p1` | Product and exact version | Look the version up in the CVE database; check the key exchange and host key algorithms |
| `SSH-1.99-...` | Protocol 1 or 1.99 negotiation — SSHv1 is enabled | Treat as a finding on its own |
| `220 (vsFTPd 3.0.3)` | vsftpd 3.x | 3.0.3 is the fixed version of the 2.3.4 backdoor; still check for weak TLS |
| `220 ProFTPD 1.3.5 Server` | ProFTPD 1.3.5 | mod_copy RCE (CVE-2015-3306) affects the 1.3.5 series |
| `220 Microsoft ESMTP` / `220 ... ESMTP` | Windows mail service | Check for open relay only if relay testing is authorized |
| `220 ProFTPD ... (test server)` | Non-production banner | Ask whether this host belongs to the engagement |
| `RFB 003.008` | VNC with a known problem version | Review the VNC authentication path |
| `HTTP/1.1 200 OK` + `Server: Apache/2.2.22` | Apache 2.2 is long end-of-life | Report as unsupported software |
| `SSH-2.0-OpenSSH_7.4` | Older OpenSSH | Check for the 7.x CVEs (user enumeration, agent forwarding) |
| `* Recv failure: Connection reset by peer` | The service drops the probe | Common on rate-limited or hardened SSH; do not treat as a scan failure |
| `220 ... MySQL 5.7.35` | MySQL with version | Check whether the instance accepts unauthenticated connections |
| Any framework or product string in a header | Technology disclosure | Feed the web testing phase, not this one |

General heuristics:

- A version number is the single most valuable thing in a banner. Feed it to
  `cyber_cve_lookup` (product and version) and to `cyber_exploit_map` before writing a
  finding — a version alone is not a vulnerability.
- Banners that leak a hostname, an internal domain, an internal IP or a build path are
  information disclosure findings in their own right.
- Banners that say "for internal use only", "test", "staging" or "dev" mean a non
  production system is reachable. Ask the operator whether it is in the engagement.
- A service on a non-standard port is not automatically a backdoor. Many deployments run
  SSH on 2222 or HTTP on 8080 legitimately.
- A port that answers but presents no recognisable service is more interesting than a
  well-known one. Capture it (step 4) and identify the protocol by hand.

### Step 4 — capture when the service is not what it claims

Use `cyber_capture` (tcpdump) when:

- nmap reports a service name that does not match the payload (a "web" port that
  answers with a binary protocol, a service that resets every probe).
- You need to prove a protocol for a report, for example that port 8080 speaks MQTT.
- The version scan is ambiguous and the exact negotiation matters (TLS version, SSH
  banner order, an HTTP/2 prior-knowledge server).
- You need to observe UDP traffic, since the service scan cannot scan UDP (step 5).

Capture narrowly: `target` and `port` narrow it to one host and one port, and
`duration_seconds` bounds the length. The pcap lands in the engagement artifact
directory and the tool reports the path and the packet count. A capture that is too
broad fills the artifact directory and leaks unrelated traffic into the engagement
record. `interface` selects the interface when the default is not the right one.

### Step 5 — NSE script selection and UDP

NSE scripts are the enumeration engine. Selection rules:

- Match the script to the service and to the question. Enumerating shares on SMB is a
  different question from fingerprinting the OS.
- Stay inside the categories the engagement authorizes:

| Category | Effect | Use when |
|---|---|---|
| `safe` | No side effects | Always |
| `discovery` | Enumerates, may open a session | Enumeration is in scope |
| `auth` | Attempts authentication | Credential testing is authorized |
| `brute` | Tries many credentials | Password auditing is explicitly authorized, and the lockout risk was accepted |
| `vuln` | Probes for known vulnerabilities | Vulnerability testing is authorized |
| `intrusive` | Can crash or destabilise the service | Only with explicit, per-service authorization |

- `vuln` and `intrusive` scripts are separate actions from enumeration. A service
  enumeration authorization does not cover them. If the scope does not include
  vulnerability testing, do not run them, and say why.
- Several enumeration scripts depend on a brute-force library and will attempt
  authentication as a side effect: `smb-enum-shares`, `smb-enum-users`,
  `smb-os-discovery`, `smb-system-info`, `smb-enum-domains`, `smb-enum-processes` all
  declare `smb-brute` as a dependency, and `snmp-sysdescr` declares `snmp-brute`. Know
  this before running them against a lockout-sensitive system.

Concrete script lists per service are in `references/nmap-recipes.md`.

#### UDP

UDP has no handshake, so an open port does not answer either. `open|filtered` is the
normal result and does not distinguish open from filtered.

The harness splits UDP work in two, because the two tools have different capabilities:

- **Discovery** goes through `cyber_portscan`. naabu understands a `u:` port prefix, so
  `ports="u:53,u:123,u:161,u:514,u:1900,u:4500,u:5353"` sweeps exactly those UDP
  services. naabu sends a probe (a service-specific one where it knows the port, an
  empty datagram otherwise) and reports the port only when the target answers.
- **Identification** does not go through `cyber_service_scan`. That tool always runs a
  TCP SYN scan with version detection; it has no UDP scan type, and nmap refuses to
  scan a `U:` port list without one ("Your ports include "U:" but you haven't specified
  UDP scan with -sU"). For the identifying pass, hand the operator the nmap command
  from `references/nmap-recipes.md` — `nmap -sU -p 161 --script snmp-info <target>` —
  and say what it will prove.

Report UDP honestly: a port that did not answer is inconclusive. Do not report it as
open without a positive response, and do not report it as closed either. SNMP (161)
deserves special attention because an open agent with a default community string leaks
a full network inventory.

### Step 6 — the surface index

Every service you identify belongs in `.cyberpi/surface.json`, the engagement's attack
surface index. Both scan tools merge what they find into it; the merge key is
`host:port/protocol`, so a repeat scan refreshes an entry instead of duplicating it.

- The sweep records the host, the port and the protocol, with `naabu` as the source.
  The service scan then adds the service name, the product and version string, the
  remaining nmap service attributes (extra info, OS type, configuration, method, CPE)
  and the state reason, with `nmap` as the source.
- Read the index back with `cyber_surface` to confirm the merge landed and to see the
  whole picture at once. It takes an optional `kind` (`all`, `hosts`, `services`,
  `endpoints`), an optional `host` or `port` filter, and `format` (`table` or `json`) —
  for example `cyber_surface(kind="services", host="10.0.0.5", format="json")`.
- If a service you clearly saw is missing from the index, re-run the scan with the same
  parameters and check `cyber_journal` for the action and its artifact path.
- The index is the input to the next phase: web testing, vulnerability scanning and
  exploitation should target the ports and versions recorded here, not a fresh guess.
- Keep the index accurate as you go. A stale index produces wrong findings later.

### Step 7 — from services to findings

1. Correlate each version with the CVE database: `cyber_cve_lookup` for a specific
   product and version, `cyber_exploit_map` to see what can be validated against it.
2. Validate before you report. A version that matches an advisory is not a finding until
   the vulnerable behaviour is confirmed — `cyber_vuln_scan` (nuclei) is the standard
   confirmation path for web services.
3. Record what you proved with `cyber_record_finding`, with the target, the evidence
   pointer (the artifact file) and the reproduction command.
4. Report the plain facts too: unsupported software versions, anonymous access, missing
   network segmentation, services exposed that the client believes are internal.

## When the sweep finds nothing

Do not conclude "no services" from an empty sweep. Work through this list:

- The host is up but every port is filtered — a firewall between you and it, or the
  ports are simply not reachable from your position. Check with a single connect to a
  port the client says is open.
- The host is down — no SYN/ACK, no ICMP, no ARP. Check routing, and whether you are on
  the right segment.
- The rate was too high for the link. Re-scan the port slowly before you contradict the
  client.
- You are on the wrong interface or behind a proxy. Check the source address of the
  probes.

## Pitfalls

- Version detection changes the service fingerprint. Take a plain sweep first so you
  have a clean baseline, then a version scan.
- A fast scan produces false negatives. If a port the client insists is open does not
  appear, re-scan that port slowly before you contradict the client.
- `open|filtered` in UDP is not "closed". Reporting it as closed is a false negative in
  a report.
- Do not scan hosts outside the scope just because they answer. A neighbour host that
  responds is not a finding; it is a scope violation.
- Do not run `vuln` or `intrusive` scripts during enumeration. They change the risk
  profile of the engagement and may crash a production service.
- Do not paste credential material into the transcript or into a finding body. Summarise
  it and reference the artifact file.
- Do not re-scan a target repeatedly to "make sure". The toolkit caches identical calls,
  and repeated scans are visible to the client.

## Reference

`references/nmap-recipes.md` — concrete nmap command recipes per service type: SMB, RDP,
SSH, SNMP, MQTT, web and TLS, mail, databases, DNS, NFS/RPC, FTP, telnet, VNC and the
rest, with the script categories and script arguments for each.
