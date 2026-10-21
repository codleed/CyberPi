# CyberPi tooling reference

This is the reference for the Kali toolchain that CyberPi wraps. It documents
what each tool is, which Kali package provides it, how CyberPi invokes it, what
it parses, how long it usually takes, and what to do when the binary is not
installed.

The authoritative list of CyberPi tool names, techniques and required binaries
is [`TOOL-REGISTRY.md`](./TOOL-REGISTRY.md). This document is the companion
that explains the tools behind those names. The exact flag set of a wrapper
lives in the tool file under `extensions/tools/`; what is recorded here is the
canonical flag and output contract that wrapper depends on, so that a change to
either side can be checked against the other.

## 1. How CyberPi drives the toolchain

Every CyberPi tool goes through `defineCyberTool` in
`extensions/lib/toolkit.ts`, which applies the same sequence to every action:

1. **Technique check** — the tool's `technique` is looked up in the engagement
	allowlist (`.cyberpi/scope.json`). A tool that is not allowed is refused and
	the refusal is journalled.
2. **Scope check** — the target is resolved from the parameters
	(`target`, `host`, `url`, `domain`, …) and matched against the scope rules.
	With no scope file, only the local machine is reachable.
3. **Binary check** — every name in the tool's `requires` list is looked up on
	`PATH`. A missing binary is a hard, actionable failure: the tool returns
	`Missing required tool(s): …` and names the apt command.
4. **Execution** — the command runs without a shell, so a target name or a
	wordlist path can never be interpreted as shell syntax. The default timeout
	is 120 s (`DEFAULT_TIMEOUT_MS` in `extensions/lib/exec.ts`); a tool that
	legitimately runs longer raises it with `timeoutMs`. In-memory output is
	capped at 32 KB, keeping the head and the tail.
5. **Artifact** — unless a tool opts out with `artifacts: false`, the full
	stdout+stderr is written to `.cyberpi/artifacts/<label>.txt`.
6. **Cache and journal** — results are cached for `cacheTtlMs` and every run
	is appended to `.cyberpi/journal.jsonl`.

Two consequences shape every entry below:

- **Structured output first.** Wrappers ask for JSON (`-json`, `-jsonl`,
	`-oX`, `--xml`, `--jsonfile`) and parse that. Scraping human-readable tables
	is a last resort.
- **Nothing secret reaches the transcript.** Tools that can produce hashes,
	passwords, cookies or tokens summarise them and point at the artifact file
	instead of printing the material.

## 2. Reading an entry

Each tool is described with the same fields:

| Field | Meaning |
|---|---|
| **Package** | The Kali/Debian package that installs the binary. |
| **Binary** | The executable name CyberPi puts in `requires` and on the command line. |
| **Purpose** | What the tool actually does. |
| **CyberPi tool** | The wrapper that drives it, or a note that none exists yet. |
| **Key flags** | The flags that matter, and what they change. |
| **Output parsed** | The machine-readable format the wrapper consumes. |
| **Typical runtime** | Order-of-magnitude wall clock, and what drives it. |
| **Safe default** | The invocation CyberPi should use by default. |
| **Risky options** | Options that change the target's behaviour, flood it, or escalate impact. |
| **If not installed** | The apt command, and what CyberPi does meanwhile. |

## 3. Quick index

| Tool | Package | Binary | CyberPi tool |
|---|---|---|---|
| nmap | `nmap` | `nmap` | `cyber_service_scan`, `cyber_iot_scan` |
| naabu | `naabu` | `naabu` | `cyber_portscan` |
| httpx | `httpx` | `httpx` | `cyber_http_probe` |
| katana | `katana` | `katana` | `cyber_crawl` |
| ffuf | `ffuf` | `ffuf` | `cyber_dir_enum` |
| nuclei | `nuclei` | `nuclei` | `cyber_vuln_scan` |
| sqlmap | `sqlmap` | `sqlmap` | `cyber_sqli` |
| dalfox | `dalfox` | `dalfox` | `cyber_xss` |
| nikto | `nikto` | `nikto` | alternative to `cyber_vuln_scan` |
| gobuster | `gobuster` | `gobuster` | alternative to `cyber_dir_enum` |
| feroxbuster | `feroxbuster` | `feroxbuster` | alternative to `cyber_dir_enum` |
| subfinder | `subfinder` | `subfinder` | `cyber_subdomain` |
| amass | `amass` | `amass` | alternative to `cyber_subdomain` |
| amass (intel mode) | `amass` | `amass intel` | alternative to `cyber_subdomain` |
| assetfinder | `assetfinder` | `assetfinder` | alternative to `cyber_subdomain` |
| theHarvester | `theharvester` | `theHarvester` | alternative to `cyber_subdomain` |
| dnsutils | `dnsutils` | `dig` | `cyber_dns` |
| whois | `whois` | `whois` | `cyber_whois` |
| traceroute | `traceroute` | `traceroute` | manual |
| mtr | `mtr-tiny` | `mtr` | manual |
| tcpdump | `tcpdump` | `tcpdump` | `cyber_capture` |
| tshark | `tshark` | `tshark` | capture artifact parser |
| wireshark | `wireshark` | `wireshark` | GUI only, not wrapped |
| searchsploit | `exploitdb` | `searchsploit` | `cyber_exploit_search` |
| msfconsole | `metasploit-framework` | `msfconsole` | `cyber_exploit_run` |
| msfvenom | `metasploit-framework` | `msfvenom` | manual |
| hashcat | `hashcat` | `hashcat` | `cyber_hash_id`, `cyber_hash_crack` |
| john | `john` | `john` | alternative to `cyber_hash_crack` |
| hydra | `hydra` | `hydra` | `cyber_password_audit` |
| trufflehog | `trufflehog` | `trufflehog` | `cyber_secret_scan` |
| gitleaks | `gitleaks` | `gitleaks` | alternative to `cyber_secret_scan` |
| ldapdomaindump | `ldapdomaindump` | `ldapdomaindump` | `cyber_ad_enum` |
| impacket-scripts | `impacket-scripts` | `impacket-*` | `cyber_ad_attack` |
| netexec | `netexec` | `netexec` | manual |
| responder | `responder` | `responder` | manual |
| bloodhound-python | `bloodhound-python` | `bloodhound-python` | manual |
| airodump-ng | `aircrack-ng` | `airodump-ng` | `cyber_wireless_scan` |
| aircrack-ng | `aircrack-ng` | `aircrack-ng` | `cyber_wireless_crack` |
| wifite | `wifite` | `wifite` | manual |
| hcxtools | `hcxtools` | `hcxpcapng` | manual |
| bettercap | `bettercap` | `bettercap` | manual |
| binwalk | `binwalk` | `binwalk` | `cyber_firmware_analysis` |
| radare2 | `radare2` | `r2` | manual |
| hidrd | `hidrd` | `hidrd` | `cyber_hid_attack` |
| chisel | `chisel` | `chisel` | `cyber_pivot` |
| ligolo-ng | `ligolo-ng` | `proxy`, `agent` | manual |
| proxychains4 | `proxychains4` | `proxychains4` | manual |
| socat | `socat` | `socat` | manual |
| awscli | `awscli` | `aws` | `cyber_cloud_enum` |
| gcloud | `google-cloud-cli` | `gcloud` | alternative to `cyber_cloud_enum` |
| az | `azure-cli` | `az` | alternative to `cyber_cloud_enum` |
| testssl.sh | `testssl.sh` | `testssl.sh` | manual |
| sslscan | `sslscan` | `sslscan` | manual |
| wafw00f | `wafw00f` | `wafw00f` | manual |
| seclists | `seclists` | — | wordlist source |
| wordlists | `wordlists` | — | wordlist source |

## 4. Reconnaissance and subdomain discovery

### subfinder

- **Package**: `subfinder`
- **Binary**: `subfinder`
- **Purpose**: Passive subdomain enumeration. Queries a large set of public
	passive sources (certificate transparency logs, search APIs, archives) and
	never sends traffic to the target, so it produces no log entries on the
	target side.
- **CyberPi tool**: `cyber_subdomain` (technique `recon`).
- **Key flags**:
	- `-d <domain>` — a single domain to enumerate.
	- `-dL <file>` — a list of domains, one per line.
	- `-all` — use every source, not just the default set. Much slower.
	- `-recursive` — also enumerate subdomains of the results.
	- `-silent` — print only hostnames, no banners.
	- `-json` — JSON Lines, one object per finding.
	- `-cs` — collect the source that produced each name.
	- `-o <file>` — write the list to a file as well.
- **Output parsed**: JSON Lines. Each record carries the hostname and, with
	`-cs`, the source names. The wrapper takes the hostname list and merges the
	hosts into the surface index.
- **Typical runtime**: 20 s to 2 min for one domain; `-all` and `-recursive`
	multiply that. Mostly bound by source rate limits, not by the target.
- **Safe default**: `subfinder -d <domain> -silent -json -cs`. Passive, no
	traffic to the target.
- **Risky options**: none intrinsically. `-all` is a large, noisy request
	volume to third-party APIs — a rate-limit and politeness concern rather than
	a risk to the client. Some sources behave like a port scan when they probe
	the target to resolve a name, so `-silent` alone is not a guarantee; check
	the source list if the engagement forbids active DNS.
- **If not installed**: `sudo apt install -y subfinder`. Until then
	`cyber_subdomain` refuses with the binary name and the apt command.

### amass (enum mode)

- **Package**: `amass`
- **Binary**: `amass` (`amass enum` in v4, `amass enum -d` in v3)
- **Purpose**: Subdomain enumeration with a large, configurable source list.
	Amass is heavier than subfinder and can be pointed at resolvers, so it
	answers "does this name resolve and where" as well as "what names exist".
- **CyberPi tool**: no dedicated wrapper; it is the richer alternative to
	`subfinder` for `cyber_subdomain`.
- **Key flags** (v4):
	- `amass enum -d <domain>` — enumerate a domain.
	- `-active` — resolve and validate names. This generates DNS traffic to the
	target's authoritative servers.
	- `-passive` — passive only (default behaviour when no mode is given).
	- `-b <sources>` — comma-separated source list.
	- `-maxns <n>` — names per source.
	- `-o <file>` — write results to a file.
	- `-json <file>` — JSON Lines output.
	- `-silent` — suppress the banner.
	- `-src` — include the source of each result.
- **Output parsed**: JSON Lines (v4) with `name`, `domain`, `addresses`,
	`sources` when `-src` is set. The text mode is a plain newline-separated
	hostname list.
- **Typical runtime**: 2 to 15 min per domain. The wide source list and the
	optional DNS validation dominate.
- **Safe default**: `amass enum -d <domain> -passive -json <file> -silent`.
- **Risky options**: `-active` and `-brute` generate real DNS load against the
	target's resolvers. `-brute` in particular can push thousands of queries per
	minute at the authoritative servers. Both should be behind an explicit
	decision, and both are visible in the client's DNS logs.
- **If not installed**: `sudo apt install -y amass`. Verify the version with
	`amass -h`: v3 and v4 use different sub-commands, and a flag that exists in
	one is silently rejected in the other.

### amass (intel mode)

- **Package**: `amass` — the same Kali package as above. There is no separate
	`amass-intel` Debian package; "amass intel" is the intelligence-gathering
	mode of the `amass` binary (v4) and the name of the equivalent v3 mode.
- **Binary**: `amass` (invoked as `amass intel`)
- **Purpose**: Wide but shallow collection — whois, ASN and reverse-IP data
	plus names from many sources — as opposed to `amass enum`, which focuses on
	one domain and goes deep. Good for footprinting an organisation rather than
	an application.
- **CyberPi tool**: none; a complement to `cyber_subdomain` for the recon
	phase.
- **Key flags**:
	- `amass intel -d <domain>` — start an intel run.
	- `-whois` — pull WHOIS records for the domain and its registrant.
	- `-asn <asn>` — enumerate an ASN.
	- `-active` — allow active sources.
	- `-brute` — enable brute-forcing (noisy against the target).
	- `-src` — include the source of each result.
	- `-o <file>` — output file.
- **Output parsed**: the same JSON Lines structure as `amass enum`, plus
	organisation, ASN and domain fields in v4.
- **Typical runtime**: 5 to 30 min, mostly waiting on third-party data.
- **Safe default**: `amass intel -d <domain> -o out.json`.
- **Risky options**: `-active` and `-brute` again. `-asn` sweeps are wide:
	the resulting target list must still pass the CyberPi scope check before
	anything else is run against it.
- **If not installed**: same as above, `sudo apt install -y amass`.

### assetfinder

- **Package**: `assetfinder`
- **Binary**: `assetfinder`
- **Purpose**: Small, fast, passive subdomain and IP discovery over a
	fixed set of sources. It is the quickest of the three passive enumerators
	and is often good enough for a first pass.
- **CyberPi tool**: none; the fast alternative to `cyber_subdomain`.
- **Key flags**:
	- `-d <domain>` — the domain to enumerate.
	- `-subs-only` — only subdomains, no other asset types.
	- `-ip-only` — only resolved IP addresses.
	- `-active` — also query the target's own DNS servers.
- **Output parsed**: plain text, one host, subdomain or IP per line. There is
	no JSON mode; the wrapper splits on whitespace and newlines.
- **Typical runtime**: 5 to 30 s.
- **Safe default**: `assetfinder -d <domain> -subs-only`.
- **Risky options**: `-active` (DNS traffic to the client's resolvers) and
	`-ip-only`, which turns the tool into a resolver and produces addresses
	that are in scope only if the scope file says so.
- **If not installed**: `sudo apt install -y assetfinder`.

### theHarvester

- **Package**: `theharvester`
- **Binary**: `theHarvester`
- **Purpose**: OSINT collection from search engines and certificate logs:
	hosts, subdomains, IP addresses, emails and employee names. It scrapes
	public indexes, so it is slow and rate-limited by the search providers.
- **CyberPi tool**: none; an OSINT complement to `cyber_subdomain`.
- **Key flags**:
	- `-d <domain>` — the domain to search for.
	- `-b <source>` — data source: `google`, `bing`, `linkedin`, `twitter`,
	`yahoo`, `duckduckgo`, and several others.
	- `-l <n>` — limit the number of results per source.
	- `-f <file>` — write the results to a file.
	- `--dns-resolve` — resolve every collected hostname.
	- `-v` — verify that the collected hosts resolve and are alive.
- **Output parsed**: sectioned plain text with `Hosts`, `Subdomains`, `IPs`,
	`Emails` and `Emails - Generic` blocks. The wrapper splits on the section
	headings.
- **Typical runtime**: 1 to 5 min per source. Search engines throttle hard;
	running many sources in one go is the most common way to get blocked.
- **Safe default**: `theHarvester -d <domain> -b google -l 100 -f out.txt`.
- **Risky options**: `-v` turns the collection into a liveness check against
	the target's addresses, which is active. Also note that the results include
	third-party addresses (CDNs, registrars, mail providers) that are almost
	never in scope — the scope check is what keeps them out.
- **If not installed**: `sudo apt install -y theharvester`.

## 5. DNS, WHOIS and network path

### dnsutils (dig)

- **Package**: `dnsutils` (BIND9 utilities)
- **Binary**: `dig`
- **Purpose**: Query DNS directly with full control over record type,
	resolver and flags. This is the tool behind the CyberPi DNS tool, and the
	one to reach for when the answer needs to be precise: zone transfers,
	delegation, DNSSEC validation, or a specific resolver.
- **CyberPi tool**: `cyber_dns` (technique `recon`).
- **Key flags**:
	- `+short` — print only the answer, one record per line. The default for
	programmatic use.
	- `+noall +answer` — answers only, keeping the record layout.
	- `+noall +authority` / `+noall +additional` — delegation and glue.
	- `@<server>` — query a specific resolver instead of the system one.
	- `<TYPE>` — `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `SRV`, `CAA`,
	`PTR`, `ANY`.
	- `+trace` — walk delegation from the root.
	- `+dnssec` — request and validate DNSSEC records.
	- `+retry=2 +time=3` — bound the wait per query; useful against a
	black-holed resolver.
	- `-x <ip>` — reverse lookup.
- **Output parsed**: the `+short` form, which is a bare list of records. For
	structured detail the wrapper prefers `+noall +answer` and parses the
	`NAME TTL CLASS TYPE RDATA` columns.
- **Typical runtime**: 1 to 5 s per query. `+trace` is slower (10 to 60 s)
	because it follows the delegation chain.
- **Safe default**: `dig +short <name> <TYPE> @<resolver>` with a short
	timeout, one query per record type.
- **Risky options**: `+trace` starts at the root and generates a burst of
	queries along the way; `ANY` is amplified by some resolvers and is often
	refused. A zone transfer (`AXFR`) against a misconfigured server is a real
	event for the client and belongs in the journal as its own action.
- **If not installed**: `sudo apt install -y dnsutils`.

### whois

- **Package**: `whois`
- **Binary**: `whois`
- **Purpose**: Registration data for a domain or IP: registrar, dates, name
	servers, registrant details, and abuse contacts.
- **CyberPi tool**: `cyber_whois` (technique `recon`).
- **Key flags**:
	- `-h <host>` / `--host=<host>` — the domain or IP to query. The host is
	also accepted as a bare argument.
	- `-p <port>` — query a whois server on a non-standard port.
	- `-H` — do not look the host up in the zone file first.
	- `--verbose` — show the full server exchange, including the contact ID.
- **Output parsed**: the raw registry text, which is not standardised. The
	wrapper extracts the labelled fields that appear in the common layout:
	`Registrar`, `Creation Date`, `Expiry Date`, `Updated Date`, `Name Server`,
	`Registrant`, `Registrant Country`, `Domain Status`, `DNSSEC`.
- **Typical runtime**: 2 to 15 s. Rate limited by the registry, which throttles
	repeated queries from one source.
- **Safe default**: `whois <host>`.
- **Risky options**: none technically. Operationally, whois servers rate-limit
	aggressively and a bulk whois sweep gets the operator's IP blocked for the
	rest of the day — which would also break the DNS and HTTP tools that come
	from the same address.
- **If not installed**: `sudo apt install -y whois`.

### traceroute

- **Package**: `traceroute`
- **Binary**: `traceroute`
- **Purpose**: Path and hop-by-hop latency to a destination.
- **CyberPi tool**: none. Useful while interpreting a pivot or a routing
	problem; the result is a diagram, not a finding.
- **Key flags**:
	- `-n` — no reverse DNS (much faster, no extra DNS traffic).
	- `-I` — ICMP echo (default on most systems).
	- `-T` / `-U` — TCP or UDP probe.
	- `-p <port>` — destination port for TCP/UDP probes.
	- `-m <n>` — maximum hops (default 30).
	- `-q <n>` — probes per hop (default 3).
	- `-w <s>` — seconds to wait for a response (default 5).
	- `-A` — annotate hops with AS numbers.
- **Output parsed**: the hop table, one line per hop, with `RTT` values and
	`*` for unanswered probes.
- **Typical runtime**: 10 to 60 s, dominated by `-w` on hops that never answer.
- **Safe default**: `traceroute -n -q 1 -w 1 <host>`.
- **Risky options**: none in the network sense, but each probe is a packet
	aimed at every router in the path, and the path may cross networks that
	are not in the engagement scope at all. Treat the path as out of scope
	unless the client owns it.
- **If not installed**: `sudo apt install -y traceroute`.

### mtr

- **Package**: `mtr-tiny`
- **Binary**: `mtr`
- **Purpose**: Continuous traceroute with per-hop loss and jitter. Combines
	traceroute and ping in one view, which makes intermittent routing problems
	visible.
- **CyberPi tool**: none.
- **Key flags**:
	- `-n` — numeric hosts.
	- `-r` — report mode: print the result once and exit.
	- `-c <n>` — number of cycles (use with `-r`).
	- `-i <s>` — interval between cycles.
	- `-b` — show both ICMP and TCP ping results.
	- `-T` / `-u` — use TCP or UDP for the ping part.
	- `-P <port>` — port for the TCP ping.
	- `-s <bytes>` — packet size.
	- `--report-wide` — widen the report to fit longer host names.
- **Output parsed**: the report-mode table, one row per hop with loss
	percentage and per-hop average.
- **Typical runtime**: as long as the cycle count. `-r -c 10 -i 1` is about
	10 s.
- **Safe default**: `mtr -n -r -c 10 <host>`.
- **Risky options**: the same scope caveat as traceroute, plus a continuous
	run (`mtr` without `-r`) sends packets indefinitely.
- **If not installed**: `sudo apt install -y mtr-tiny`.

## 6. Network and port scanning

### naabu

- **Package**: `naabu`
- **Binary**: `naabu`
- **Purpose**: A very fast SYN port scanner written in Go, with its own DNS
  resolver and an optional hand-off to nmap for service detection. It finds
  the open ports in seconds; nmap then explains them.
- **CyberPi tool**: `cyber_portscan` (technique `port-scan`).
- **Key flags**:
	- `-host <host>` — a host, a comma-separated list, or a CIDR.
	- `-list <file>` — a file of hosts, one per line.
	- `-p <ports>` — the port list: `top-100`, `1-1024`, `80,443,8080`, or
		`-` for every port.
	- `-rate <n>` — packets per second. The main throttle.
	- `-c <n>` — concurrent hosts.
	- `-json` — JSON Lines output. `-silent` — suppress the banner.
	- `-nmap` — feed the open ports into nmap for service detection.
	- `-Pn` — skip the host discovery ping.
	- `-config <file>` — a configuration file.
	- `-exclude-cdn` — skip addresses in CDN ranges.
	- `-timeout <ms>` and `-retries <n>` — per-host bounds.
	- `-randomize` — randomise the scan order.
	- `-o <file>` — write the results to a file.
- **Output parsed**: JSON Lines, one object per open port, with `host`, `ip`,
	`port` and `protocol`. With `-nmap` the service details from nmap are
	merged into the same record.
- **Typical runtime**: 1 to 10 s for a single host on the top ports. A /24
	over all 65 535 ports takes 2 to 15 min, depending entirely on `-rate`.
- **Safe default**: `naabu -host <host> -p top-100 -rate 1000 -c 25 -json
	-silent`.
- **Risky options**: `-rate` is the only lever that matters. At 10 000 pps
	a /24 becomes a flood rather than a scan, and the target's own rate
	limiting will answer with drops that look like closed ports. `-nmap` adds
	a full service-detection pass on every open port, which is far heavier
	than the port scan itself.
- **If not installed**: `sudo apt install -y naabu`. The SYN scan needs raw
	sockets, so naabu must run as root or with the `cap_net_raw,cap_net_admin`
	capabilities on the binary.

### nmap

- **Package**: `nmap`
- **Binary**: `nmap`
- **Purpose**: The reference host discovery, port scanning and service
	identification tool. It finds open ports, names the service behind them,
	recovers the version, and runs NSE scripts for deeper checks. It is also
	what naabu hands its results to.
- **CyberPi tool**: `cyber_service_scan` (technique `service-enumeration`).
	It is also the scanner behind `cyber_iot_scan` (technique `iot-hardware`),
	where it profiles embedded devices on unusual ports.
- **Key flags**:
	- `-Pn` — treat the host as up and skip the ICMP discovery ping. Almost
		always needed, and required for a large sweep.
	- `-sS` — SYN scan (the default when run as root). `-sT` — full TCP
		connect scan, which works without root but is noisier.
	- `-sU` — UDP scan. Slow, and the only reliable way to find open UDP
		services.
	- `-p <spec>` — the ports: `80`, `1-1024`, `-` for all, `U:53` for UDP.
	- `-sV` — service and version detection. `-sC` — the default script set.
	- `--open` — report only open ports. `--reason` — say why a port is in
		its state.
	- `-A` — aggressive: OS detection, version detection, scripts and
		traceroute together. **Noisy.**
	- `-T4` — the timing template. `--min-rate <n>` — a hard floor on the
		send rate.
	- `-n` — no DNS resolution. `-Pn -n` together is the fast, quiet
		combination.
	- `-oX -` — XML on standard output. `-oN -` — the normal text format.
	- `--script <expr>` — NSE scripts, e.g. `http-title`, `smb-vuln-*`.
	- `--script-args <args>` — arguments for those scripts.
	- `-iL <file>` — targets from a file. `--excludefile <file>` — exclusions.
	- `-D <decoys>` — decoy source addresses. `-S <addr>` — the source address
		to claim.
	- `--host-timeout <t>` and `--max-retries <n>` — bounds for a sweep.
	- `-6` — IPv6. `--resume <file>` — continue an interrupted scan.
- **Output parsed**: the XML tree from `-oX -`. The wrapper reads the
	`<host>` / `<address>` / `<ports>` / `<port>` elements: the port number,
	the protocol, the state, the service name, the product and version
	strings, and any `<script>` output. The plain-text output is only a
	fallback.
- **Typical runtime**: 5 to 60 s for one host with `-sV`; 10 to 30 min for a
	/24 over the full port range. `-A` roughly triples the time, and a UDP
	scan can take far longer than the whole rest of the engagement.
- **Safe default**: `nmap -Pn -n -sS -sV --open -p <ports> --min-rate 100
	-oX - <target>`. Add `-sC` only when the engagement calls for the default
	script set.
- **Risky options**:
	- `-A` sends OS-fingerprinting probes that intrusion detection systems
		flag, and it is rarely worth the extra load for a service inventory.
	- `-sU` is heavy: a full UDP sweep generates a burst of traffic, and on
		some stacks the target answers with ICMP port-unreachable messages
		that can knock over a poorly built firewall. Restrict it with `-p
		U:53,161,162` and `--top-ports`.
	- `--script vuln` is not a scan: those scripts send real exploit payloads,
		and some of them modify state.
	- `--script-args` with a brute-force script generates authentication
		attempts and account lockouts.
	- `-T5` overruns the target's rate limiting and turns a scan into a
		denial of service. Use `-T4`.
- **If not installed**: `sudo apt install -y nmap`. The `naabu -nmap` path
	also needs it, so a missing nmap breaks the port-scan workflow at its
	second step. `nmap` also needs its Nmap script database
	(`/usr/share/nmap/scripts/`) to be present for `-sC` and `--script`; a
	stripped installation has the binary but no scripts.


## 7. Web probing, crawling and content discovery

### httpx

- **Package**: `httpx` — this is ProjectDiscovery's httpx, **not** the Python
	`httpx` library. On Kali the Debian package `httpx` provides the Go binary;
	the Python library is `python3-httpx`. Verify with `httpx -version` before
	trusting the flags.
- **Binary**: `httpx`
- **Purpose**: Probe HTTP(S) endpoints and report status, title, web server,
	technologies, content length, CDN and open redirect. It is the fastest way
	to turn a hostname list into a live-web list with metadata.
- **CyberPi tool**: `cyber_http_probe` (technique `recon`).
- **Key flags**:
	- `-u <url>` — a single target. `-l <file>` — a list, one per line.
	- `-json` — JSON Lines output. `-silent` — suppress the banner.
	- `-td` — show the page title. `-tech-detect` — detect technologies.
	- `-sc` — show the status code. `-ip` / `-cdn` / `-asn` / `-cn` — network
	and CDN context.
	- `-t <n>` — threads. `-rl <n>` — requests per second.
	- `-follow-redirects` — follow redirects; `-irr` — follow on the input
	side.
	- `-H '<header>'` — extra request header. `-x <proxy>` — route through a
	proxy (a SOCKS pivot, for example).
	- `-random-agent` — vary the User-Agent.
	- `-screenshot` — capture a page image (writes files; heavy).
	- `-favicon` — hash the favicon to fingerprint the stack.
	- `-probe` — also probe for the well-known alive ports of a domain.
- **Output parsed**: JSON Lines. Each record carries `url`, `input`,
	`status_code`, `title`, `webserver`, `tech` (array), `content_length`,
	`time`, `a` (resolved addresses), `cdn`, `cnames`, `final_url`,
	`failed`. The wrapper takes the endpoint records and merges them into the
	surface index.
- **Typical runtime**: 1 to 5 s per host with a modest thread count. A
	thousand-host list at `-t 50 -rl 150` takes a few minutes.
- **Safe default**: `httpx -l hosts.txt -json -silent -sc -td -tech-detect
	-ip -cdn -follow-redirects -t 30 -rl 100`.
- **Risky options**: `-screenshot` downloads and stores full pages. `-favicon`
	and `-probe` add requests the target did not expect. A high `-rl` against a
	small target is a denial of service in practice — keep the rate at or below
	what a normal browser session would generate unless the client asked for
	load.
- **If not installed**: `sudo apt install -y httpx`. If the wrong httpx is on
	`PATH` (the Python one, which has no `-json`), uninstall the Python
	package in the virtual environment that CyberPi runs from, or call the
	binary by absolute path.

### katana

- **Package**: `katana` (ProjectDiscovery)
- **Binary**: `katana`
- **Purpose**: A modern web crawler. It parses JavaScript to find endpoints
	that a plain crawler misses, can collect known files and secrets in page
	source, and can detect reflected parameters.
- **CyberPi tool**: `cyber_crawl` (technique `web-testing`).
- **Key flags**:
	- `-u <url>` — a single target. `-l <file>` — a list of targets.
	- `-d <n>` — crawl depth (default 3).
	- `-jc` — JavaScript crawling: parse JS files for endpoints.
	- `-kf` — collect known files (robots.txt, sitemap.xml, …).
	- `-fs` — field scraping: collect form fields and their values.
	- `-fx` — detect reflected parameters (XSS-prone input points).
	- `-jsonl` — JSON Lines output. `-silent` — suppress the banner.
	- `-c <n>` — concurrency. `-rl <n>` — rate limit.
	- `-p <proxy>` — proxy. `-H '<header>'` — custom header.
	- `-aff` — show the affected (out-of-scope) URLs.
- **Output parsed**: JSON Lines. Each record has `request` (with `method`,
	`endpoint`, `page`, `raw`), `response` (with `status_code`, `headers`),
	`timestamp`, and `endpoint`/`source`. The wrapper extracts endpoints and
	their status codes.
- **Typical runtime**: 30 s to 10 min for a single site at depth 3. Crawling
	a large application can run for the full 120 s default timeout, so the
	wrapper raises `timeoutMs` and keeps the artifact.
- **Safe default**: `katana -u <url> -jsonl -silent -d 3 -jc -kf -c 5
	-rl 5`.
- **Risky options**: `-fx` and `-fs` interact with parameters in ways that can
	change application state, so they are only safe against read-only surfaces.
	A high depth or concurrency turns the crawler into a load generator.
	Katana also follows redirects off-site, so it will happily walk into a
	host that is not in the scope file — bound it with `-crawl-scope` or
	`-fs` off-host filtering where the tool supports it.
- **If not installed**: `sudo apt install -y katana`.

### ffuf

- **Package**: `ffuf`
- **Binary**: `ffuf`
- **Purpose**: Content discovery by fuzzing a URL position with a wordlist.
	It is precise, fast and easy to bound, which makes it the default for
	directory and file enumeration.
- **CyberPi tool**: `cyber_dir_enum` (technique `web-testing`).
- **Key flags**:
	- `-u <url>` — the URL with the `FUZZ` keyword marking the fuzz position.
	- `-w <wordlist>` — the wordlist. A second list after `:` is used as the
	value list, and a third after `:` as the match filter.
	- `-e <ext>` — append extensions to every word.
	- `-mc <codes>` — match only these status codes.
	- `-fc <codes>` — filter out these status codes.
	- `-fs <size>` — filter by response size (useful against a catch-all page
	that returns 200 for everything).
	- `-t <n>` — threads. `-rate <n>` — requests per second.
	- `-recursion` / `-recursion-depth <n>` — recurse into found directories.
	- `-s` — skip the automatic calibration request.
	- `-ac` — automatic calibration.
	- `-k` — do not verify the certificate.
	- `-b <cookies>` — cookies. `-H '<header>'` — extra header.
	- `-of <fmt>` — output format: `json`, `csv`, `html`, `md`. `-o <file>` —
	output file. `-json` is a shortcut for the JSON format.
	- `-noninteractive` — never prompt, for automation.
- **Output parsed**: the JSON output stream (one object per finding with
	`url`, `status`, `length`, `words`, `lines`, `input`, and the matched
	`FUZZ` value). ffuf writes results to stdout when no output file is given;
	when `-o` is used the wrapper reads that file.
- **Typical runtime**: seconds for a small list, 1 to 10 min for a large
	list at a low rate. A full `seclists` raft list at 50 req/s is about 10 min.
- **Safe default**: `ffuf -u <url>/FUZZ -w <list> -mc 200,204,301,302,307,
	401,403,405,500 -rate 50 -t 20 -s -of json -noninteractive`. Filtering
	404s is what keeps the result set meaningful.
- **Risky options**: `-recursion` multiplies the request count and can walk
	out of the target application into file shares or admin panels. Raising
	`-rate` above 100 turns enumeration into load. `-ac` (calibration) sends a
	random request that some applications log as an attack.
- **If not installed**: `sudo apt install -y ffuf`.

### gobuster

- **Package**: `gobuster`
- **Binary**: `gobuster`
- **Purpose**: Content discovery in `dir`, `dns`, `vhost` and `fuzz` modes.
	Still the most common alternative to ffuf, and better at DNS and vhost
	enumeration.
- **CyberPi tool**: none; the alternative to `cyber_dir_enum`.
- **Key flags**:
	- `gobuster dir -u <url> -w <list>` — directory and file enumeration.
	- `gobuster dns -d <domain> -w <list>` — subdomain brute force.
	- `gobuster vhost -u <url> -w <list>` — virtual host enumeration.
	- `-x <ext>` — extensions to append.
	- `-t <n>` — threads. `--timeout <s>` — per-request timeout.
	- `-b <codes>` — exclude these status codes (404 by default).
	- `--status-codes <codes>` — include only these.
	- `-k` — skip certificate verification.
	- `--no-error` — do not print errors.
	- `-q` — quiet.
- **Output parsed**: the plain-text result table. The wrapper parses the
	`Status` column and the found path. There is no JSON mode, so this is one
	of the tools where scraping is unavoidable.
- **Typical runtime**: seconds to minutes, proportional to list size and rate.
- **Safe default**: `gobuster dir -u <url> -w <list> -x <ext> -t 20 -b
	404,403 --no-error`.
- **Risky options**: `dns` mode is brute force against the client's
	authoritative servers, generating a DNS query per word — for a large list
	that is a real burden on the client's DNS. `vhost` mode sends a Host header
	the target has never seen, which can bypass routing rules and reach
	unintended internal virtual hosts.
- **If not installed**: `sudo apt install -y gobuster`.

### feroxbuster

- **Package**: `feroxbuster`
- **Binary**: `feroxbuster`
- **Purpose**: Recursive content discovery, written in Rust, with a
	built-in status, size and response-time filter set and a live progress
	display.
- **CyberPi tool**: none; the recursive alternative to `cyber_dir_enum`.
- **Key flags**:
	- `-u <url>` — the target. `-w <list>` — the wordlist.
	- `-x <ext>` — extensions.
	- `--depth <n>` / `-d <n>` — recursion depth. `--no-recursion` disables it.
	- `--filter-status <codes>` — drop these status codes.
	- `--filter-size <bytes>` — drop responses of this size.
	- `--filter-regex <pattern>` — drop responses matching a pattern.
	- `--collect-backups` — request backup extensions (`.bak`, `~`, `.old`).
	This is a probing behaviour some applications react badly to.
	- `--extract-links` — crawl the links found in responses.
	- `--parallel <n>` — concurrent connections. `--rate-limit <n>` — requests
	per second.
	- `--auto-bypass` — try common WAF bypasses.
	- `--json` — JSON Lines to stdout. `--no-color`.
	- `--screenshot` — capture a screenshot of each hit.
- **Output parsed**: JSON Lines with `url`, `status`, `content_length`,
	`time`, `word`, `wildcard`, `method`. The `wildcard` flag marks responses
	produced by a catch-all route, which is what the status and size filters
	exist to remove.
- **Typical runtime**: 1 to 15 min for a medium site with recursion.
- **Safe default**: `feroxbuster -u <url> -w <list> -x <ext> --depth 2
	--filter-status 404 --no-color --json --rate-limit 50`.
- **Risky options**: `--collect-backups` asks for files that are often not
	meant to be served, and some applications will log it as an intrusion.
	`--auto-bypass` deliberately sends malformed requests. Both are fine when
	the engagement is explicitly testing for exposed backups and WAF bypasses,
	and inappropriate otherwise.
- **If not installed**: `sudo apt install -y feroxbuster`.

## 8. Web vulnerability scanning

### nuclei

- **Package**: `nuclei`
- **Binary**: `nuclei`
- **Purpose**: Template-driven vulnerability scanning. Thousands of community
	templates cover CVEs, misconfigurations, exposed panels, default
	credentials and more, and the same template language can express custom
	checks.
- **CyberPi tool**: `cyber_vuln_scan` (technique `vulnerability-scan`).
- **Key flags**:
	- `-u <url>` — a single target. `-l <file>` — a list of targets.
	- `-t <dir>` — template directory. `-t <tag>` — a tag such as `cve`,
	`misconfig`, `exposure`, `tech`. `-e <id>` — specific templates.
	- `-severity <list>` — `info,low,medium,high,critical`.
	- `-jsonl` — JSON Lines output. `-silent` — suppress the banner.
	- `-rl <n>` — requests per second. `-c <n>` — concurrency.
	- `-proxy <url>` — proxy. `-H '<header>'` — custom header. `-cookie`.
	- `-d` — disable the template's own authentication and payload requests.
	- `-f` — enable fuzzing templates (they send many requests).
	- `-x` — enable exploit templates. **This is the option that actually
	exploits.**
	- `-headless` — allow templates that drive a browser.
	- `-nc` — no colour. `-stats` — periodic progress.
	- `-duc` — disable the update check (offline or air-gapped hosts).
	- `-timeout <s>` — per-request timeout. `-retries <n>`.
- **Output parsed**: JSON Lines. Each record carries `templateID`, `info`
	(`name`, `severity`, `tags`, `description`, `reference`), `type`, `host`,
	`matched-at`, `extracted-results` and `curl-command`. The wrapper reads the
	severity, the matched URL and the template identifier, and turns each
	record into a candidate finding.
- **Typical runtime**: 1 to 10 min for a small target list. A large list with
	the full template set and `-f` can run for an hour.
- **Safe default**: `nuclei -l targets.txt -jsonl -silent -severity
	low,medium,high,critical -rl 50 -c 10 -nc -duc -stats`.
- **Risky options**:
	- `-x` (exploit) runs the exploit payload — it can write files, create
	accounts, or spawn shells. Never enable it by default.
	- `-f` (fuzz) sends large volumes of parameterised requests.
	- `-headless` lets a template drive a real browser, which means the target
	sees a full session and the templates can submit forms.
	- Several templates in the default set are "active" (they try to log in,
	create resources, or trigger destructive workflows). Restrict with
	`-severity` and, where the engagement requires it, an explicit template
	allowlist.
- **If not installed**: `sudo apt install -y nuclei`. Also install the
	templates: `nuclei -update-templates`. A nuclei without templates is a
	silent no-op.

### sqlmap

- **Package**: `sqlmap`
- **Binary**: `sqlmap`
- **Purpose**: Automated SQL injection detection and exploitation: boolean,
	time, error, union, stacked and inline queries, across MySQL, PostgreSQL,
	SQLite, MSSQL and Oracle.
- **CyberPi tool**: `cyber_sqli` (technique `web-testing`).
- **Key flags**:
	- `-u <url>` — the target URL. `--data '<string>'` — a POST body.
	- `--batch` — never ask, always choose the default answer. Required for
	unattended runs.
	- `--level <1-5>` — how many payloads to test (1 is safe, 5 is heavy).
	- `--risk <1-3>` — how risky the payloads are. **2 and 3 include
	`OR`/`AND` conditions and query side effects.**
	- `--technique <BEUSTQ>` — restrict the injection classes.
	- `--dbs` — enumerate all supported databases.
	- `--forms` — crawl and test every form on the page.
	- `--crawl <n>` — crawl this many levels deep.
	- `--tamper <list>` — tamper scripts to bypass WAFs and filters.
	- `--dbms <name>` — restrict to one database engine.
	- `--random-agent` — rotate the User-Agent.
	- `--flush-session` — forget previous results for the target.
	- `--dump` — dump the contents of the affected tables.
	- `--os-shell` / `--sql-shell` — get a shell on the database or the server.
	- `--output-dir <dir>` — where to write the results directory.
- **Output parsed**: sqlmap's console output is text, not JSON, so the wrapper
	extracts the marked lines: the injectable parameter list, the payload
	section, and the final `[INFO]` summary. Everything sqlmap writes to
	`<target>/` in its output directory is kept as an artifact.
- **Typical runtime**: 1 to 10 min for a single URL at level 1. Level 5 with
	`--forms` and `--crawl` can run for hours.
- **Safe default**: `sqlmap -u <url> --batch --level 1 --risk 1 --technique
	BEUS --random-agent --flush-session --output-dir <artifacts>`. Detection
	only.
- **Risky options**: `--risk 2` and `--risk 3` send payloads that modify
	data (`UPDATE`, `DELETE`, `INSERT`); `--risk 3` can touch every row of
	every table. `--os-shell` executes commands on the database host.
	`--dump` exfiltrates data in volume, which the client's data handling
	policy may not permit. `--tamper` intentionally breaks application
	assumptions and can corrupt data. Default to detection; escalate only when
	the engagement asks for it and record the escalation in the journal.
- **If not installed**: `sudo apt install -y sqlmap`.

### dalfox

- **Package**: `dalfox`
- **Binary**: `dalfox`
- **Purpose**: XSS scanner. It finds reflected, stored and DOM-based XSS,
	and can verify a finding with a non-blind proof of concept.
- **CyberPi tool**: `cyber_xss` (technique `web-testing`).
- **Key flags**:
	- `url <url>` — a single URL. `file <file>` — a list of URLs.
	- `--format json` — JSON output. `--silence` — no banner. `--no-color`.
	- `--blind` — use only out-of-band (blind) detection.
	- `--mining-dict <file>` — mine a wordlist for blind XSS from the page.
	- `--skip-bav` — skip the basic-analysis phase and only fuzz.
	- `--only-poc` — report only findings with a working proof of concept.
	- `--follow-redirects` — follow redirects.
	- `--user-agent <ua>` / `--cookie <c>` — request identity.
	- `--waf-evasion` — attempt to bypass a WAF.
	- `--worker <n>` — concurrency. `--delay <ms>` — delay between requests.
	- `--deep` — deeper DOM analysis.
	- `--report <file>` — write the report.
- **Output parsed**: JSON. Each finding carries `type` (`V` vulnerable, `D`
	DOM, `R` reflected), `method`, `param`, `evidence`, `vuln_type`, `severity`
	and `message`.
- **Typical runtime**: 10 s to 3 min for a single URL. A file of URLs scales
	linearly.
- **Safe default**: `dalfox url <url> --format json --no-color --silence
	--only-poc --skip-bav`.
- **Risky options**: `--blind` sends out-of-band callbacks to a collaborator
	domain — that means an external service learns about the finding, so it is
	only appropriate when the client knows and accepts it. `--waf-evasion`
	deliberately crafts requests that trip WAF rules and application logs.
	Findings with a live proof of concept are executable: the stored payload can
	be used against a real user, so the artifact must be handled as a
	credential-equivalent.
- **If not installed**: `sudo apt install -y dalfox`.

### nikto

- **Package**: `nikto`
- **Binary**: `nikto`
- **Purpose**: Web server scanner. It checks for a long list of known
	misconfigurations, default files, outdated server versions and dangerous
	headers. Its findings are dated and noisy, but it is a fast sanity check
	on an unfamiliar server.
- **CyberPi tool**: none; a companion to `cyber_vuln_scan`, not a replacement.
- **Key flags**:
	- `-h <url>` — the target.
	- `-p <port>` — port.
	- `-C all` / `-C 2` — scan categories. `-Tuning <x>` — fine-tune.
	- `-timeout <s>` — request timeout.
	- `-maxtime <s>` — stop after this long.
	- `-nointeractive` — never prompt.
	- `-Format json` — JSON output on Nikto 2.5 and newer. Older builds
	support only `xml` and `text`; use `-Format xml` and parse the XML
	instead.
	- `-ask` — ask before a potentially dangerous test.
- **Output parsed**: the JSON document (or XML on older builds), whose `items`
	array holds the findings with `description`, `uri`, `namel`, `osvdb`,
	`method` and `severity` where available.
- **Typical runtime**: 1 to 5 min per host.
- **Safe default**: `nikto -h <url> -nointeractive -Format json -maxtime 300`.
- **Risky options**: some of nikto's tests are old and can hang on unusual
	applications, hence `-maxtime`. A handful of categories attempt to create
	files or provoke errors that pollute the logs. Treat nikto output as
	leads to verify with nuclei or manual inspection, never as findings in
	their own right.
- **If not installed**: `sudo apt install -y nikto`.

## 9. TLS, WAF and server fingerprinting

### testssl.sh

- **Package**: `testssl.sh`
- **Binary**: `testssl.sh` (also present as `/usr/bin/testssl.sh`)
- **Purpose**: Deep TLS/SSL inspection: protocol versions, cipher suites,
	certificate chain and expiry, renegotiation, compression, HSTS, OCSP
	stapling and client-certificate handling.
- **CyberPi tool**: none; the TLS half of a web assessment.
- **Key flags**:
	- `--jsonfile-pretty <file>` — JSON output. `--csvfile <file>`,
	`--htmlfile <file>` — other formats.
	- `--severity <level>` — `OK`, `LOW`, `MEDIUM`, `HIGH`, `FATAL`.
	- `--protocols` — which protocol versions to test.
	- `--waf` — WAF detection.
	- `--full` — the whole test suite. `--quick` — the fast subset.
	- `--sneaky` — deliberately use old protocol versions and weak ciphers to
	provoke the server's fallback behaviour. **This is the option that
	surprises application teams.**
	- `--ip <one>` — test only this IP (for SNI testing with a chosen address).
	- `--add-cipher`, `--show-certificate`, `--phone-out` — report a client
	fingerprint that some WAFs treat differently.
	- `--quiet` — less output.
	- `--openssl <path>` — use a specific OpenSSL build.
- **Output parsed**: the JSON document, whose `scanResult` array holds one
	entry per test with `id`, `finding`, `severity` and `ip`.
- **Typical runtime**: 2 to 15 min for `--full`; about a minute for `--quick`.
- **Safe default**: `testssl.sh --jsonfile-pretty out.json --severity MEDIUM
	--quiet <host:port>`.
- **Risky options**: `--sneaky` makes the server negotiate obsolete protocols
	and ciphers, which some TLS terminators treat as an attack and some clients
	will log. `--phone-out` presents a client fingerprint that differs from a
	browser. Both should be a deliberate, reported decision.
- **If not installed**: `sudo apt install -y testssl.sh`.

### sslscan

- **Package**: `sslscan`
- **Binary**: `sslscan`
- **Purpose**: Quick TLS enumeration: supported protocol versions, ciphers,
	certificate details and a set of common TLS vulnerability checks. Lighter
	and faster than testssl.sh, and easier to script.
- **CyberPi tool**: none.
- **Key flags**:
	- `--xml=<file>` — XML output.
	- `--sni=<host>` — the SNI hostname to send.
	- `--no-colour` — plain output.
	- `--show-certificate` — print the full certificate.
	`--show-times` — timing information.
	- `--enabled-cipher` / `--disabled-cipher` — restrict the cipher list.
	- `--severity=<level>` — `low`, `medium`, `high`.
	- `--checks=<list>` — select individual checks.
	- `--ipv4` / `--ipv6`.
	- `--fancy` — colours and a progress bar.
- **Output parsed**: the XML document, whose `ssltest` element carries the
	protocol versions, the cipher list and the `<error>`/`<warning>` elements.
- **Typical runtime**: 5 to 30 s per host.
- **Safe default**: `sslscan --xml=out.xml --no-colour --sni=<host>
	--severity=medium <host:port>`.
- **Risky options**: very few. `--checks` with an aggressive set adds
	handshake-flooding checks. `--fancy` is cosmetic only.
- **If not installed**: `sudo apt install -y sslscan`.

### wafw00f

- **Package**: `wafw00f`
- **Binary**: `wafw00f`
- **Purpose**: Identify the web application firewall or CDN sitting in front
	of a site, by sending a small set of crafted requests and matching the
	responses against known signatures.
- **CyberPi tool**: none; a quick input for the web-testing phase.
- **Key flags**:
	- `wafw00f <url>` — test one URL.
	- `-a` — find all possible WAFs, not just the first match.
	- `-f` — find the WAF using a known path.
	- `-t` — test a list of URLs.
	- `-r` — follow redirects.
	- `-b` — blacklisted checks: identify a WAF by comparing responses with
	and without a known attack string. This is the most accurate mode and the
	most conspicuous one.
	- `-o <file>` — write the output to a file.
	- `--detect-tech` — also fingerprint the technology stack.
	- `--no-follow` — do not follow redirects.
- **Output parsed**: the plain-text report, which names the detected
	firewall and the cloud/CDN provider.
- **Typical runtime**: 2 to 10 s per target.
- **Safe default**: `wafw00f <url> --detect-tech`.
- **Risky options**: `-b` sends a payload string to the target specifically to
	trip a WAF rule. It is visible in the client's WAF logs as an attack
	attempt, and it can move a source IP onto a block list.
- **If not installed**: `sudo apt install -y wafw00f`.

## 10. Packet capture and protocol analysis

### tcpdump

- **Package**: `tcpdump`
- **Binary**: `tcpdump`
- **Purpose**: Capture packets from an interface to a pcap file or to
	standard output. The entry point for any traffic analysis in an
	engagement.
- **CyberPi tool**: `cyber_capture` (technique `recon`).
- **Key flags**:
	- `-i <iface>` — the interface. `-i any` captures on all of them.
	- `-n` / `-nn` — do not resolve names or ports; much faster and it keeps
	the capture self-contained.
	- `-c <n>` — stop after this many packets. **Always set it**: a capture
	without a limit runs until the disk fills.
	- `-w <file>` — write a pcap file.
	- `-s <bytes>` — snap length; `0` captures full packets.
	- `-A` / `-X` — dump payload as ASCII / hex.
	- `-v` — more detail. `-e` — include the link-layer header.
	- `-Z <user>` — drop privileges after opening the interface. Use this.
	- `-B <kb>` — kernel buffer size.
	- `port 443` — a BPF filter, applied before capture.
- **Output parsed**: the packet summary lines on standard output, and the
	pcap file in the artifact directory. The pcap is the real result: it is
	what tshark later reads.
- **Typical runtime**: bounded by `-c`; 1000 packets on a busy link is a few
	seconds, on a quiet link it can be minutes.
- **Safe default**: `tcpdump -i <iface> -nn -c 1000 -s 0 -w <artifact>.pcap`.
- **Risky options**: capturing without a count and without a snap limit fills
	the disk. Capturing on a live client network captures other people's
	traffic — scope it with a BPF filter (`host <target> and port 443`) and
	treat the resulting pcap as if it contained the client's data. Promiscuous
	mode (`-p`) on an unmanaged network is a policy violation.
- **If not installed**: `sudo apt install -y tcpdump`.

### tshark

- **Package**: `tshark`
- **Binary**: `tshark`
- **Purpose**: The Wireshark command-line dissector. Reads a pcap and
	extracts structured fields, statistics and protocol trees.
- **CyberPi tool**: not wrapped, but it is the parser for the pcap that
	`cyber_capture` produces; the capture workflow expects it to be present.
- **Key flags**:
	- `-r <file.pcap>` — read a capture file.
	- `-Y <filter>` — display filter, e.g. `http.request and http.host`.
	- `-T fields -e <field> ...` — print specific fields, tab separated.
	- `-T json` / `-T jsonraw` — JSON output.
	- `-q` — quiet, no packet summary.
	- `-x` / `-V` — hex dump / full detail for a packet.
	- `-z <stat>` — statistics, e.g. `conv,tcp`, `io,phs`, `endpoints,ip`.
	- `-c <n>` — stop after n packets.
- **Output parsed**: JSON (`-T json`) or a field list (`-T fields`).
- **Typical runtime**: seconds for a small capture; minutes for a large one.
- **Safe default**: `tshark -r <file.pcap> -q -T fields -e ip.src -e
	ip.dst -e tcp.dstport -e http.request.uri`.
- **Risky options**: none. The risk is in the data, not the tool: a capture
	contains whatever traffic the network carried, including credentials in
	cleartext HTTP or in protocol handshakes. Treat the pcap as sensitive
	material and keep it in the artifact directory.
- **If not installed**: `sudo apt install -y tshark`. On a desktop install
	the package may prompt for the dumpcap privilege set; in a headless
	engagement set `dumpcap` capabilities with
	`sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap` so captures
	work without root.

### wireshark

- **Package**: `wireshark`
- **Binary**: `wireshark` (GUI), `tshark` and `capinfos` (CLI, in the `tshark`
	package)
- **Purpose**: The graphical protocol analyser. The same dissection engine as
	tshark, with a user interface.
- **CyberPi tool**: never. CyberPi only runs non-interactive commands, so
	the GUI is not launched by any tool; `cyber_capture` produces a pcap and
	tshark summarises it. The GUI is for the human analyst, reading the
	artifact afterwards.
- **Key flags**: the GUI takes a capture file on the command line
	(`wireshark capture.pcap`); `capinfos <file>` summarises a capture from the
	command line.
- **Output parsed**: not applicable.
- **Typical runtime**: interactive; the GUI loads a capture in seconds.
- **Safe default**: open the artifact pcap in the GUI, read-only.
- **Risky options**: live capture from the GUI needs the same privilege set
	as tshark. A GUI started by an automated agent would block the harness, so
	it is never used from a tool.
- **If not installed**: `sudo apt install -y wireshark` (this pulls in
	tshark). On a headless Kali box install `tshark` instead.

## 11. Exploitation frameworks

### searchsploit

- **Package**: `exploitdb` (Kali) — provides the `searchsploit` command and
	the Exploit Database archive.
- **Binary**: `searchsploit`
- **Purpose**: Search the Exploit Database offline for exploits, shellcode
	and papers by keyword, CVE, title, author, platform or file type. No
	network access, so it is safe to run anywhere.
- **CyberPi tool**: `cyber_exploit_search` (technique `exploit`).
- **Key flags**:
	- `searchsploit <keyword>` — free-text search over titles and paths.
	- `--id <id>` — look up one entry by EDB id.
	- `--title <text>` — search titles only.
	- `--author <name>` — filter by author.
	- `--platform <name>` — filter by platform (`windows`, `linux`, `php`).
	- `--type <name>` — filter by type (`exploit`, `shellcode`, `paper`).
	- `--exclude <text>` — exclude matching titles.
	- `--strict` — disable the loose word ordering, so the results are exact.
	- `-c` / `--command` — show the copy-paste command line for the match.
	- `-o <file>` / `--json` — machine-readable output. Older builds write JSON
	to a file with `-o`; newer builds accept `--json` on standard output.
- **Output parsed**: the JSON document when available (`id`, `title`, `path`,
	`date`, `author`, `type`, `platform`, `source_url`). When only the text
	table is available, the wrapper parses the numbered rows and their
	metadata columns.
- **Typical runtime**: under a second. The whole database is local.
- **Safe default**: `searchsploit --strict --json <keyword>`. `--strict`
	matters: without it, "apache" also matches every path containing the
	letters in any order, and the result set becomes noise.
- **Risky options**: none — searchsploit only reads a local database. The
	risk is in what it returns: the linked files are weaponised exploits for
	the exact versions you just found. Read them, do not run them blindly.
- **If not installed**: `sudo apt install -y exploitdb`.

### msfconsole

- **Package**: `metasploit-framework`
- **Binary**: `msfconsole`
- **Purpose**: The Metasploit Framework console: exploit modules, payloads,
	encoders, auxiliary scanners and post-exploitation modules, driven
	interactively or from a resource script.
- **CyberPi tool**: `cyber_exploit_run` (technique `exploit`).
- **Key flags**:
	- `-q` — quiet banner.
	- `-x "<command>"` — run one console command and exit. This is the
	unattended form the wrapper uses.
	- `-r <file.rc>` — run a resource script.
	- `-f` — use the last used framework settings.
	- `-n` / `--no-database` — do not use the local database. The database
	stores session data and credentials from past runs.
	- `--defer-exit` — leave the console open after a script.
	- `--payload-options` — show payload options.
	- `-y` — assume yes to all prompts.
- **Output parsed**: the console transcript on standard output, plus the
	`-x` result. The wrapper sends a scripted sequence (`use`, `set`, `run`)
	and extracts the module outcome lines — "exploit completed", "session
	opened", "meterpreter session".
- **Typical runtime**: 5 s to 5 min per module, plus framework start-up
	(10 to 30 s with the database). A check module on many hosts runs as a
	background job and much longer.
- **Safe default**: `msfconsole -q -n -x "<check command>"`. Using `-n`
	keeps past credentials out of the run, and the wrapper prefers
	`check`/`check` and `exploit ... check` over actually running an exploit.
- **Risky options**: `run` on an exploit module is the point of the tool and
	the point of the risk: it can crash the service, write files, create
	accounts or open a shell. `msfconsole` also drops into `msfvenom`-style
	payload generation and can produce a live session that the agent then
	drives. Because the framework is a full interpreter, treat every
	`use`/`set`/`run` sequence as a privileged action and journal it.
- **If not installed**: `sudo apt install -y metasploit-framework`. It is a
	large package and pulls in Ruby and PostgreSQL; the installer may also
	ask to initialise the database — `msfdb init` if `msfconsole` complains
	that the database is not present.

### msfvenom

- **Package**: `metasploit-framework`
- **Binary**: `msfvenom`
- **Purpose**: Generate a payload and its listener configuration outside the
	console, for use in a manual or scripted exploitation step.
- **CyberPi tool**: none. `cyber_exploit_run` uses msfconsole; payload
	generation is a manual step in the exploitation workflow.
- **Key flags**:
	- `-p <payload>` — the payload, e.g. `windows/x64/shell_reverse_tcp`.
	- `-l` — list the payloads.
	- `--payload-options` — list the options of a payload.
	- `LHOST=<ip>` / `LPORT=<port>` — the listener address.
	- `-f <format>` — output format: `raw`, `elf`, `exe`, `powershell`,
	`python`, `sh`.
	- `-o <file>` — write the payload to a file.
	- `--platform <name>` / `--arch <name>` — target platform.
	- `--encoder <name>` — apply an encoder.
	- `--small` — make the payload as small as possible. This changes the
	payload's shape and can break it.
	- `--loot` — generate loot of the requested type.
- **Output parsed**: the encoded payload on standard output, or the file
	written with `-o`.
- **Typical runtime**: under a second.
- **Safe default**: `msfvenom -p <payload> --payload-options` (discovery
	only) before generating anything.
- **Risky options**: everything that produces a usable payload. A generated
	reverse shell is a working attack tool; if it leaves the engagement host
	it becomes one of the artefacts. `--small` can silently corrupt a payload.
	Generate into the engagement directory and treat the file as a controlled
	artefact.
- **If not installed**: `sudo apt install -y metasploit-framework`.

## 12. Credential attacks

### hashcat

- **Package**: `hashcat`
- **Binary**: `hashcat`
- **Purpose**: GPU-accelerated password cracker. CyberPi uses it twice: once
	to identify a hash's type, once to attempt recovery.
- **CyberPi tool**: `cyber_hash_id` (identify) and `cyber_hash_crack`
	(technique `password-audit`).
- **Key flags**:
	- `-m <mode>` — the hash mode; the list is in `hashcat -h` and
	`hashcat --example-hashes`. `1000` is NTLM, `0` is MD5, `1400` is
	SHA2-256, `13100` is KerberosNetNTLMv2, `22000` is WPA-PBKDF2-PMKID+EAPOL.
	- `-a <mode>` — attack mode: `0` straight, `3` brute force, `6` hybrid
	wordlist + mask, `7` hybrid mask + wordlist.
	- `-r <rules>` — rule file, e.g. `best64.rule`.
	- `-w <n>` — workload profile: `1` low, `2` default, `3` high, `4`
	insane. **4 will not yield the GPU to anything else.**
	- `--runtime <s>` — stop after this long. Always set it in an engagement.
	- `--session <name>` — named session, with `--status` to check it and
	`--restore` to resume.
	- `-O <file>` / `--outfile` — cracked hashes.
	- `--outfile-autohex-disable` — write raw values, not hex.
	- `--show` / `--left` — show cracked and uncracked entries.
	- `--identify <file>` — identify the hash types in a file (hashcat 6.x).
	- `--potfile-disable` — do not read or write the potfile. Use it so that a
	previous engagement's results do not leak into this one.
	- `-b` — benchmark the device.
	- `--force` — ignore the installed driver warning.
- **Output parsed**: the status block (`STATUS`, `HASH:`, `Speed.#`,
	`Recovered:`, `Session:`) and the `hash:plaintext` lines. **The plaintext
	is credential material:** the wrapper reports how many were recovered and
	writes the values to the artifact file instead of into the transcript.
- **Typical runtime**: identification is instant. Recovery ranges from
	seconds (a hash in a common password list) to hours (a strong hash with a
	large mask at `-w 3`). `--runtime` bounds it.
- **Safe default**: `hashcat --identify <file>` for identification, and for
	cracking `hashcat -m <mode> -a 0 -w 2 --runtime 600 --potfile-disable
	-O <artifact> <hashfile>`.
- **Risky options**:
	- `-w 4` makes the machine unusable for the rest of the run and can
	destabilise a laptop; on a shared or remote host use `-w 2`.
	- `-a 3` with a large mask is a full GPU burn for the whole runtime
	window, which on a shared host looks like a denial of service.
	- Cracking recovered credentials must stay inside the engagement: the
	`cyber_password_audit` technique in the scope file is the gate, and the
	resulting credentials belong in the findings file, never in the
	transcript.
- **If not installed**: `sudo apt install -y hashcat`. Check that the GPU is
	visible (`hashcat -I`); on a VM without a passthrough GPU, hashcat falls
	back to the CPU and a run that should take minutes takes days — use `--runtime`
	accordingly and consider `john` instead.

### john

- **Package**: `john` (with `john-data` for the configuration and the
	bundled wordlists)
- **Binary**: `john`
- **Purpose**: The original UNIX password cracker, with a large format
	coverage, strong rules and an incremental cracking mode. On CPU it is
	often faster than hashcat for single hashes, and it handles formats that
	hashcat does not.
- **CyberPi tool**: none; the CPU alternative to `cyber_hash_crack`.
- **Key flags**:
	- `--wordlist=<file>` — the wordlist. `--format=<name>` — the hash format.
	- `--list=formats` — list the supported formats.
	- `--show` — show the cracked entries. `--show=left`.
	- `--stdin` — read the hash from standard input.
	- `--incremental` — use the incremental (character-based) mode, with
	`--max-length=<n>`.
	- `--rules` — apply the rules in the rule directory. `--rules=<name>`.
	- `--session=<name>` — named session, with `--status` and `--restore`.
	- `--single` — crack a single hash.
- **Output parsed**: the `hash:plaintext` lines on standard output. As with
	hashcat, the plaintext is credential material: summarise and point at the
	artifact.
- **Typical runtime**: seconds to hours depending on the format and the
	wordlist. A 100 MB wordlist against an NTLM hash is roughly an hour on a
	modern CPU.
- **Safe default**: `john --wordlist=<list> --format=<fmt> --session=eng
	<hashfile>`, then `john --show --format=<fmt> <hashfile>` to read the
	results.
- **Risky options**: `--incremental` without `--max-length` will run for a
	very long time. Do not run john and hashcat against the same session
	directory, and do not let john reuse a potfile from another engagement —
	set `--session` explicitly and keep the potfile inside the engagement
	directory.
- **If not installed**: `sudo apt install -y john john-data`.

### hydra

- **Package**: `hydra` (THC Hydra). `hydra-wizard` is the separate GUI
	package.
- **Binary**: `hydra`
- **Purpose**: Online password auditing against network services: SSH, FTP,
	HTTP form, SMB, RDP, LDAP and dozens more.
- **CyberPi tool**: `cyber_password_audit` (technique `password-audit`).
- **Key flags**:
	- `-l <user>` — a single user. `-L <file>` — a user list.
	- `-p <pass>` — a single password. `-P <file>` — a password list.
	- `-s <port>` — the port. `-s <url>` — a URL to log in to.
	- `-t <n>` — parallel tasks. `-T <n>` — parallel hosts.
	- `-f` — stop at the first success per host.
	- `-u` — use a different password for each user.
	- `-e ns` — try the empty password and the password equal to the user name.
	- `-V` — verbose, printing every attempt.
	- `-w <s>` — wait between attempts.
	- `-I` — do not verify the server's TLS certificate.
	- `-x <hex>` — **null-byte password mode.** Send a NUL after the password.
	Only for services known to be vulnerable to it.
	- `-m <module>` — the service module, e.g. `ssh`, `http-post-form`,
	`smb`.
	- `-S` / `-s` — small and large wordlists from the system.
- **Output parsed**: the text result lines. The `login: ... [SUCCESS]` or
	`login: ... [ERROR]` pairs are extracted. **The recovered password is
	credential material** and goes to the artifact, not the transcript.
- **Typical runtime**: minutes to hours. A four-account audit against a
	hundred-word list with `-t 4` takes seconds; a full password list against
	a hardened service takes hours and generates lockout events.
- **Safe default**: `hydra -l <user> -P <list> -s <port> -t 4 -f -m <module>
	<host>`. Keep `-t` low (4 to 8) to stay under the lockout threshold of most
	services, and always set `-f`.
- **Risky options**:
	- High `-t` or `-T` guarantees account lockout and possibly an incident
	response. A locked-out account is a visible client impact.
	- `-x` (null byte) can crash a service that is not patched for it.
	- `-I` disables certificate checks, which weakens the audit itself.
	- Successful logins are real accesses to the client's systems; the
	technique allowlist and the scope file are the only things keeping the
	audit inside its authorisation.
- **If not installed**: `sudo apt install -y hydra`.

## 13. Secret scanning in source control

### trufflehog

- **Package**: `trufflehog`
- **Binary**: `trufflehog`
- **Purpose**: Scans repositories, filesystems, buckets and GitHub
	organisations for credentials and other high-entropy secrets, and verifies
	them against the issuing service when it can.
- **CyberPi tool**: `cyber_secret_scan` (technique `password-audit`).
- **Key flags**:
	- `trufflehog filesystem <path>` — scan a directory tree.
	- `trufflehog git <repo>` — scan a git repository, including its history.
	- `trufflehog github --org=<org> --token=<token>` — scan an organisation.
	- `trufflehog s3 --bucket=<name>`, `trufflehog docker`, `trufflehog
	kafka`, `trufflehog github-workflow`.
	- `--json` — JSON Lines output.
	- `--only-verified` — keep only the secrets that were confirmed live.
	- `--results=verified,unknown,unverified` — control the result classes.
	- `--since-commit <sha>` / `--branch <name>` — limit the history scanned.
	- `--no-update` — skip the version check on an offline host.
	- `--fail` — exit non-zero when a secret is found.
	- `--allow-verified` / `--deny-verified` — policy filters.
- **Output parsed**: JSON Lines. Each record carries `DetectorName`,
	`Raw` (the secret itself), `SourceMetadata` (the file, repository, commit
	and line) and `Verified` (a boolean). **The wrapper never prints `Raw`.** It
	reports the detector, the location and the verification state, and writes
	the full record to the artifact file.
- **Typical runtime**: 10 s to 10 min, dominated by the size of the history
	being walked.
- **Safe default**: `trufflehog git <repo> --json --no-update --results=
	verified,unknown`.
- **Risky options**: `--only-verified` makes trufflehog **test each secret
	against the live service it belongs to** — that is an authentication
	attempt against a third-party or client system, and it may show up in that
	service's logs. It is also the only way to know whether a leaked key is
	still live, so it is a decision to make explicitly. `github --token=` puts
	a live API token on the command line, where it is visible in the process
	list; pass it through the environment instead.
- **If not installed**: `sudo apt install -y trufflehog`. If the version is
	old enough to lack the subcommand syntax, update it — the v2 and v3
	command lines are not compatible.

### gitleaks

- **Package**: `gitleaks`
- **Binary**: `gitleaks`
- **Purpose**: Git-focused secret scanner with a curated rule set. Faster and
	lighter than trufflehog on a repository, with fewer detectors, and it
	reports the exact commit and line.
- **CyberPi tool**: none; the lightweight alternative to `cyber_secret_scan`.
- **Key flags**:
	- `gitleaks detect --source <dir>` — scan a git repository.
	- `gitleaks dir <dir>` — scan a plain directory (gitleaks 8.19 and newer).
	- `--no-git` — scan the working tree without git history.
	- `--report-format json --report-path <file>` — JSON findings.
	- `--redact` — replace the secret with a fixed mask. **Use this** when the
	report will be shared.
	- `--redact-partial` — mask all but a few characters.
	- `--config <file>` — a custom rule set.
	- `--exit-code <n>` — the exit code to use when findings exist.
	- `--log-opts "<range>"` — limit the history scanned.
- **Output parsed**: the JSON report, an array of findings with `RuleID`,
	`Description`, `File`, `StartLine`, `EndLine`, `Secret`, `Match`,
	`Commit` and `Author`.
- **Typical runtime**: seconds on a working tree, a minute or two on a full
	history.
- **Safe default**: `gitleaks detect --source <dir> --report-format json
	--report-path <artifact> --redact --no-git`.
- **Risky options**: without `--redact` the report file contains the full
	secret. That file is as sensitive as the credential itself and must live
	with the other controlled artefacts. gitleaks does not verify secrets
	against live services, so it never authenticates anywhere — that is its
	safety advantage over trufflehog.
- **If not installed**: `sudo apt install -y gitleaks`.

## 14. Active Directory

### ldapdomaindump

- **Package**: `ldapdomaindump`
- **Binary**: `ldapdomaindump`
- **Purpose**: Dumps the structure and the content of an Active Directory:
	users, groups, computers, organisational units, trusts, ACLs on key
	objects and the objects that are not shown by the usual tools.
- **CyberPi tool**: `cyber_ad_enum` (technique `active-directory`).
- **Key flags**:
	- `-d <domain>` — the domain to dump.
	- `-u <user>` / `-p <pass>` — credentials. `-u` alone uses the current
	user's Kerberos ticket.
	- `-k` — no LDAPS, no StartTLS.
	- `-z` — use LDAPS (port 636) instead of LDAP.
	- `-h` — use plain LDAP (port 389) even when StartTLS is possible.
	- `-o <prefix>` — write the tree and the relation files to a prefix.
	- `--no-color` — plain output.
	- `-r` — resolve SIDs to names.
- **Output parsed**: the printed tree, plus the relation files written with
	`-o`: `users.txt`, `groups.txt`, `computers.txt`, `trusts.txt`,
	`objectsid.txt` and similar. The wrapper reads the relation files when
	they exist and falls back to parsing the tree.
- **Typical runtime**: 5 s to 2 min, depending on the size of the domain and
	how many pages the server returns.
- **Safe default**: `ldapdomaindump -d <domain> -u <user> -p <pass> -o
	<artifact-prefix> --no-color`.
- **Risky options**: a domain dump enumerates the entire directory. It is
	read-only, but it is a large, high-sensitivity disclosure, and it is
	visible to the domain controllers and to any directory monitoring. `-k`
	sends credentials in cleartext LDAP — use it only over a network the
	client controls, and prefer LDAPS or Kerberos.
- **If not installed**: `sudo apt install -y ldapdomaindump`.

### impacket-scripts

- **Package**: `impacket-scripts`
- **Binary**: the package installs each script with an `impacket-` prefix:
	`impacket-secretsdump`, `impacket-smbserver`, `impacket-ntlmrelayx`,
	`impacket-GetUserSPNs`, `impacket-GetNPUsers`, `impacket-tgt`,
	`impacket-mimikatz`, `impacket-wmiexec`, `impacket-atexec`,
	`impacket-dpapi`, and so on.
- **Purpose**: The Impacket protocol library, exposed as scripts. They speak
	the SMB, LDAP, Kerberos, MS-RPC, DCE/RPC and NBNS protocols directly,
	which is what makes relay attacks, Kerberoasting and credential dumping
	possible.
- **CyberPi tool**: `cyber_ad_attack` (technique `active-directory`), which
	requires `impacket-smbserver`.
- **Key flags** (vary per script, the common ones):
	- `-target <host>` — the target host.
	- `-dc-ip <ip>` — the domain controller to talk to when the target is not
	one.
	- `-u <user>` / `-p <pass>` — credentials. `-k` — use Kerberos.
	- `-no-sam` / `-no-lm` / `-no-ntlm` — restrict what is collected.
	- `-hash` / `-hashcat` — output the hashes in a cracking format.
	- `-request` — request the ticket rather than reading it from the cache.
	- `-target-domain <domain>`.
- **Output parsed**: text, script by script. `impacket-secretsdump` prints
	lines of the form `user:domain:SAM_HASH:LM_HASH:::`, and
	`impacket-GetUserSPNs` prints the service tickets to crack. **All of these
	are credential material:** the wrapper counts what it found, names the
	accounts, and writes the values to the artifact file.
- **Typical runtime**: seconds to a few minutes per host.
- **Safe default**: run the read-only scripts first
	(`impacket-GetUserSPNs` with `-request` against a known service account),
	and prefer `-hashcat` output over a table of hashes.
- **Risky options**:
	- `impacket-smbserver` impersonates a legitimate SMB server to capture
	authentication attempts. It is a rogue service on the network and it can
	cause other hosts to send credentials to it — that is the whole point,
	and it is also how an unauthorised attacker would behave. It should only
	run in a window the client has agreed to.
	- `impacket-ntlmrelayx` relays captured authentication to another service.
	- `impacket-mimikatz` and `impacket-dpapi` extract secrets from a remote
	host, which is a full compromise of that host.
	- `impacket-wmiexec` and `impacket-atexec` execute commands on a remote
	host.
- **If not installed**: `sudo apt install -y impacket-scripts`.

### netexec

- **Package**: `netexec` (the maintained successor to CrackMapExec)
- **Binary**: `netexec` (also installed as `nxc`)
- **Purpose**: Enumerates and attacks Windows networks over SMB, WinRM, WMI
	and LDAP: users, groups, shares, sessions, and the various ways Windows
	stores credentials.
- **CyberPi tool**: none; the broader AD tool behind the `cyber_ad_attack`
	workflow.
- **Key flags**:
	- `netexec <target> -u <user> -p <pass>` — the target and the credentials.
	- `--local-auth` — authenticate against the local machine, not the domain.
	- `--no-bloody` — do not enable the "bloodhound" privilege escalation
	attempts. **Use this by default.**
	- `--shares` / `--enum-shares` — list shares. `--enum-users` — list users.
	- `--enum-sessions` / `--enum-domains` / `--enum-smb-share-paths`.
	- `--sam` / `--ntlm` / `--dpapi` / `--registry` — collect credential
	material. Each is a full compromise of the host.
	- `--collection <name>` — BloodHound collection methods.
	- `--bloodhound` / `--collection-all` — build a graph.
	- `--zip <file>` — write the BloodHound output to a zip.
	- `--krb5-ccache <file>` — authenticate with a Kerberos ticket.
	- `--force` — continue when the SMB signing check fails.
	- `--smb-signing <yes|no>` — override the signing requirement.
	- `--pwn3r` — attempt the local privilege escalation chain.
	- `--winrm` / `--wmi` — change the transport.
	- `--exec <cmd>` — run a command on the remote host.
- **Output parsed**: the coloured text tables, which CyberPi should run with
	colour disabled so the output can be parsed. The tables are turned into
	structured records: users, shares, and machines.
- **Typical runtime**: seconds to a few minutes per target; a whole subnet
	takes considerably longer.
- **Safe default**: `netexec <target> -u <user> -p <pass> --local-auth
	--no-bloody --shares --enum-users`.
- **Risky options**: `--sam`, `--ntlm`, `--dpapi` and `--registry` dump
	credentials from a host — that is a full compromise. `--pwn3r` attempts
	privilege escalation. `--exec` runs a command. `--force` bypasses a
	signature check, which the domain administrator may have configured
	deliberately. Everything except enumeration should be an explicit,
	journalled decision.
- **If not installed**: `sudo apt install -y netexec`. Older Kali
	installations still have `crackmapexec`; note that netexec is not a drop-in
	replacement for every flag, and that `cme` is end-of-life.

### responder

- **Package**: `responder`
- **Binary**: `responder`
- **Purpose**: Listens for name resolution protocols (LLMNR, NBT-NS, MDNS)
	and, when a host asks for a name that does not exist, answers it with a
	malicious IP. The next authentication attempt goes to the attacker
	instead. It also captures the hashes it sees.
- **CyberPi tool**: none; a manual step, and the most conspicuous one in the
	whole toolkit.
- **Key flags**:
	- `-I <iface>` — the interface to listen on.
	- `-i <ip>` — the address to advertise.
	- `-A` — **analyse mode**: observe the network and report what is
	happening without poisoning anything.
	- `-v` — verbose.
	- `--disable-ntlm-responder` — do not answer NTLM challenges.
	- `--disable-mdns-responder`, `--disable-nbtns-responder` — turn off
	individual responders.
- **Output parsed**: the text log of captured hashes and the detected
	protocols. The captured NTLM hashes are credential material and go to the
	artifact file, not the transcript.
- **Typical runtime**: continuous, until it is stopped. Every captured hash
	appears as it is seen.
- **Safe default**: `responder -I <iface> -A` — analyse only. Nothing is
	poisoned and nothing is captured.
- **Risky options**: the full capture mode. It poisons name resolution for
	the whole segment, so every machine that looks up a name it cannot
	resolve will try to authenticate to the operator's host. On a client
	network this is indistinguishable from a credential theft in the SIEM, and
	it can lock out domain accounts. It also captures hashes from systems that
	were never meant to be part of the engagement. Only run it inside an
	agreed window, on an agreed segment, with the client's explicit consent
	in the scope file.
- **If not installed**: `sudo apt install -y responder`. It needs raw socket
	access, so it runs as root (or with the equivalent capabilities).

### bloodhound-python

- **Package**: `bloodhound-python` (the current collector; the older
	`bloodhound` package provides the legacy BloodHound.py and SharpHound
	binaries)
- **Binary**: `bloodhound-python`
- **Purpose**: Collects Active Directory data — users, groups, sessions,
	ACLs, trusts, Object ACLs, RDP, DCSync — and writes it as the JSON files
	that the BloodHound GUI imports. It is a data collector, not an attack
	tool.
- **CyberPi tool**: none; a manual collection step in the AD workflow.
- **Key flags**:
	- `-d <domain>` — the domain to collect from.
	- `-u <user>` / `-p <pass>` — credentials.
	- `-g <group>` — collect a specific group.
	- `--collection <name>` / `--collection-all` — choose the collection
	methods.
	- `--zip <file>` — write a zip of the JSON files.
	- `--server <url>` — the BloodHound server to upload to.
	- `--dc <host>` — the domain controller to use.
- **Output parsed**: a zip archive of JSON documents. CyberPi treats the zip
	as an artefact and reports the collection size; it does not parse the
	graph itself.
- **Typical runtime**: 1 to 10 min, proportional to the size of the domain.
- **Safe default**: `bloodhound-python -d <domain> -u <user> -p <pass>
	--collection-all --zip <artifact>`.
- **Risky options**: collection methods such as DCSync, SessionLoop and
	PSReading are read-only but generate a high volume of LDAP traffic, which
	can trip directory monitoring. The resulting JSON graph contains the
	complete permission structure of the domain — a highly sensitive artefact
	that must stay under engagement control.
- **If not installed**: `sudo apt install -y bloodhound-python`. Verify the
	package name on the target Kali release: `bloodhound-python` and the
	legacy `bloodhound` package have different flags.

## 15. Wireless

Wireless work needs a monitor-mode capable adapter. Check with
`iw list` before anything else; most internal laptop adapters do not support
monitor mode, and a promiscuous capture on a corporate network is a policy
violation.

### airodump-ng

- **Package**: `aircrack-ng`
- **Binary**: `airodump-ng`
- **Purpose**: Captures and lists nearby wireless networks and the clients
	associated with them: BSSID, ESSID, channel, encryption, signal strength
	and the client stations.
- **CyberPi tool**: `cyber_wireless_scan` (technique `wireless`).
- **Key flags**:
	- `-i <iface>` — the interface.
	- `-w <prefix>` — write the capture files with this prefix. This is what
	produces the file that aircrack-ng later reads.
	- `--bssid <mac>` — only this access point.
	- `--essid <name>` — only this network name.
	- `-c <n>` — lock to a channel. Without it, the capture hops channels and
	misses some traffic.
	- `--mode` — hop channels.
	- `--ignore-negative-one` — do not show the "no APs found" line.
- **Output parsed**: the terminal table of APs and stations, plus the files
	written with `-w`: `<prefix>-01.cap` (the capture), `<prefix>-01.csv`
	(the AP list) and `<prefix>-01.net.txt` (the client list).
- **Typical runtime**: a fixed observation window — 30 s to several minutes
	gives a usable picture; longer improves the handshake odds.
- **Safe default**: `airodump-ng -i <iface> --bssid <target-bssid> -c
	<channel> -w <artifact-prefix>`.
- **Risky options**: passive by default, and that is what makes it safe.
	Active attacks (`aireplay-ng` deauthentication, packet injection) are
	separate tools and are not part of this workflow. Running a monitor-mode
	capture on a network the client does not own is illegal in most
	jurisdictions, and it is conspicuous to the client even when it is legal.
- **If not installed**: `sudo apt install -y aircrack-ng`. If the adapter
	will not enter monitor mode, a USB adapter with a supported chipset
	(commonly an Atheros-based one) is required.

### aircrack-ng

- **Package**: `aircrack-ng`
- **Binary**: `aircrack-ng` (the package also provides the companions
	`aireplay-ng`, `airmon-ng`, `airbase-ng`, `airdecap-ng`,
	`packetforge-ng`).
- **Purpose**: Cracks the WEP or WPA/WPA2 key from a captured handshake, and
	can also verify a captured PMKID.
- **CyberPi tool**: `cyber_wireless_crack` (technique `wireless`).
- **Key flags**:
	- `-w <capture.cap>` — the capture file (or a PMKID file).
	- `-b <bssid>` — the access point to attack.
	- `-e <essid>` — the network name.
	- `-a <mode>` — attack mode: `1` for WPA/WPA2 PSK, `2` for WEP.
	- `-W` — WEP-specific dictionary attack.
	- `-N` — attack a PMKID (`PMKID hash` file) directly.
	- `-f <n>` — the fudge factor for the PTW attack.
	- `--interactive` — use the interactive session selection.
	- `-r <file>` — ignore IVs in this file.
	- `-q` — quiet.
- **Output parsed**: the text result, including the `KEY FOUND!` line and the
	recovered key. **The key is credential material:** the wrapper reports
	that the key was recovered, names the SSID, and writes the value to the
	artifact file.
- **Typical runtime**: seconds when the key is in the wordlist, minutes to
	hours otherwise. A WEP capture cracks in under a minute; WPA2 depends
	entirely on the password strength.
- **Safe default**: `aircrack-ng -w <capture.cap> -b <bssid> -a 1` with a
	bounded wordlist.
- **Risky options**: cracking a key that is not the engagement's own network
	is a criminal act in most jurisdictions. `--interactive` and a PMKID
	attack are only more effective, not more dangerous. The capture and the
	recovered key are both controlled artefacts.
- **If not installed**: `sudo apt install -y aircrack-ng`.

### wifite

- **Package**: `wifite`
- **Binary**: `wifite`
- **Purpose**: An orchestrator that automates the whole wireless attack
	chain: monitor mode, capture, handshake or PMKID acquisition, and cracking
	with a bundled wordlist.
- **CyberPi tool**: none; the "one command" alternative to the
	`cyber_wireless_scan` plus `cyber_wireless_crack` pair.
- **Key flags**:
	- `-i <iface>` — the interface.
	- `--bssid <mac>` / `--essid <name>` — restrict to one network.
	- `--channel <n>` — lock the channel.
	- `--pmkid` — attack the PMKID instead of the handshake.
	- `--wpa` / `--wep` / `--11n` — restrict the attack types.
	- `--skip-crack` — capture only, do not crack. **Use this by default in
	an engagement.**
	- `--no-updates` — skip the wordlist update on an offline host.
	- `--keep` — keep the capture files.
- **Output parsed**: the coloured status output, which is a narrative
	rather than a structured record.
- **Typical runtime**: 1 to 20 min per network, dominated by the capture
	window and the cracking.
- **Safe default**: `wifite -i <iface> --bssid <target> --skip-crack`.
- **Risky options**: everything past `--skip-crack`. wifite drives
	deauthentication and injection automatically, and a full run against an
	access point can knock legitimate users off the network repeatedly. The
	client must agree to that explicitly.
- **If not installed**: `sudo apt install -y wifite`. It needs
	`aircrack-ng` and a wordlist (`/usr/share/wordlists/aircrack-ng`).

### hcxtools

- **Package**: `hcxtools`
- **Binary**: `hcxpcapng` (the main tool; the package also provides
	`hcxhashtool`, `hcxcat`, `hcxpmktool`)
- **Purpose**: Extracts WPA/WPA2 PMKID and handshake material from a capture
	and converts it into the `hcx22000` format that hashcat consumes. It is
	the modern path from a capture to a cracking job.
- **CyberPi tool**: none; the preparation step for `cyber_hash_crack` on
	wireless material.
- **Key flags**:
	- `-i <capture.pcap>` — the input capture.
	- `-o <out.hc22000>` — the output hash file.
	- `-w <out.pcapng>` — write a pcapng copy.
	- `--all` — include every hash, not only the best ones.
	- `-J` — write a JSON summary.
	- `--capture <type>` — restrict the handshake types to collect.
- **Output parsed**: the `hcx22000` file. Each line is a hash record with a
	type field (`PMKID`, `WPA1`, `WPA2`, …).
- **Typical runtime**: seconds for a small capture.
- **Safe default**: `hcxpcapng -i <capture.pcap> -o <artifact>.hc22000`.
- **Risky options**: none beyond the capture itself. The output file is
	password-cracking material and must be treated as a controlled artefact.
- **If not installed**: `sudo apt install -y hcxtools`.

### bettercap

- **Package**: `bettercap`
- **Binary**: `bettercap`
- **Purpose**: A network manipulation and monitoring toolkit: ARP and DNS
	spoofing, WiFi deauthentication, BLE reconnaissance, an HTTP/SOCKS proxy
	and a BLE/Bluetooth attack suite. It is the general-purpose "network
	middlebox" for a lab or a controlled engagement.
- **CyberPi tool**: none; a manual tool, and the one with the widest blast
	radius in this list.
- **Key flags**:
	- `-iface <iface>` — the interface.
	- `-eval "<command>"` — run one command and exit, e.g.
	`bettercap -eval "net.recon on" -iface eth0`.
	- `net.recon on` / `net.probe on` — host discovery and probing.
	- `net.attack on` — enable the ARP, DNS, mDNS, NBT-NS and WiFi
	deauthentication attacks. **This is the dangerous one.**
	- `http.proxy on --proxy-port 8080` — the interception proxy.
	- `wifi.deauth <bssid>` / `wifi.browne` — WiFi attacks.
	- `ble.recon on` — Bluetooth device discovery.
- **Output parsed**: the event log on standard output. The `net.recon` and
	`net.probe` results are the useful, read-only part.
- **Typical runtime**: `net.recon` finishes in seconds; the proxy and the
	attack modules run until they are stopped.
- **Safe default**: `bettercap -eval "net.recon on" -iface eth0` — read-only
	discovery.
- **Risky options**: `net.attack on` and the HTTP proxy. ARP spoofing breaks
	connectivity for everything on the segment; DNS spoofing redirects the
	whole network; the proxy intercepts other people's traffic. On a client
	network this is a visible, disruptive, security-relevant event, and the
	HTTPS interception requires installing a CA certificate on the clients,
	which is an intrusive change to their estate. Use only with explicit
	client agreement and a stated window.
- **If not installed**: `sudo apt install -y bettercap`. It needs root for
	raw socket access.

## 16. Hardware and firmware

### binwalk

- **Package**: `binwalk`
- **Binary**: `binwalk`
- **Purpose**: Identifies the contents of a firmware image: file system
	boundaries, compressed and encrypted regions, bootloaders, and embedded
	files. Extraction pulls the individual files out of the image.
- **CyberPi tool**: `cyber_firmware_analysis` (technique `iot-hardware`).
- **Key flags**:
	- `binwalk <file>` — the basic scan.
	- `-e` / `--extract` — extract the embedded files into a directory.
	- `-D` / `--carve` — carve every identified file out of the image.
	- `--dd="<pattern>"` — extract only the files matching a pattern, e.g.
	`--dd=".*:ext:bin:uboot"`.
	- `--entropy` — entropy analysis, which highlights compressed and
	encrypted regions.
	- `-M` / `--signature` — signature analysis.
	- `-x` / `--hexdump` — hex dump the region of interest.
	- `-B` / `--map` — map the file offsets of the identified regions.
	- `--json` — JSON output (binwalk v3).
- **Output parsed**: the scan table of offsets, types and descriptions, and
	the extracted file list. The JSON form gives offsets and types directly.
- **Typical runtime**: seconds for a small image, minutes for a large one
	with extraction.
- **Safe default**: `binwalk <file> --entropy` first — the scan and the
	entropy view are read-only. Extract into the artefact directory with `-e`.
- **Risky options**: none against a network. The risk is forensic: extracted
	firmware routinely contains hard-coded credentials, keys and internal
	hostnames, and the extraction directory becomes a sensitive artefact.
	`--dd` patterns can pull megabytes of binary into the engagement
	directory.
- **If not installed**: `sudo apt install -y binwalk`.

### radare2

- **Package**: `radare2`
- **Binary**: `r2` (with `rabin2` for the header, symbol and string
	analysis, and `radare2` for the interactive shell)
- **Purpose**: Reverse engineering and disassembly. It loads a binary,
	recovers its structure, decodes its instructions and lets an analyst work
	through the logic.
- **CyberPi tool**: none. It is the manual second stage of the firmware
	workflow that `cyber_firmware_analysis` feeds: binwalk finds the
	interesting blob, radare2 explains what it does.
- **Key flags**:
	- `-q` — quit after running the commands, no interactive shell.
	- `-c "<commands>"` — the commands to run.
	- `-A` — run the full analysis (`aaa`).
	- `-n` — do not load the binary's symbols.
	- `-e <setting>` — set an analysis option.
	- `-b <bits>` — the target bit width.
	- `-w` — open the file for writing. Only when patching is intended.
	- `rabin2 -I <file>` — the binary information. `rabin2 -z <file>` — the
	strings in the data section. `rabin2 -l <file>` — the linked libraries.
	- `rabin2 -zz <file>` — the strings with their offsets.
- **Output parsed**: the plain text of the command output. `rabin2 -I`
	produces a short key/value block; `rabin2 -zz` produces one line per
	string.
- **Typical runtime**: seconds for `rabin2`; a minute or more for a full
	`aaa` analysis of a large binary.
- **Safe default**: `r2 -q -A -c "afl" <file>` for the function list, and
	`rabin2 -zz <file>` for the strings.
- **Risky options**: `-w` writes to the file. Never use it on the original
	evidence; work on a copy inside the artefact directory. The strings output
	of a firmware image is where hard-coded credentials live, so it is
	sensitive material.
- **If not installed**: `sudo apt install -y radare2`. The `cutter` package
	provides the graphical front end.

### hidrd

- **Package**: `hidrd`
- **Binary**: `hidrd`
- **Purpose**: Decodes USB HID reports. It parses the HID report descriptor
	of a USB device, shows the report structure and the meaning of each
	field, and can capture the reports a device sends.
- **CyberPi tool**: `cyber_hid_attack` (technique `iot-hardware`).
- **Key flags**: hidrd takes the device path as its argument. The options
	cover parsing the report tree, analysing it and writing the decoded output
	to a file. Confirm the exact spelling with `hidrd -h` on the target
	system before relying on a flag — the option set has varied between
	releases.
	- The device is a `hidraw` node, e.g. `/dev/hidraw0`, found with
	`ls /dev/hidraw*` or from `lsusb`.
	- The output file receives the decoded report tree.
- **Output parsed**: the decoded report tree, with the report ID, the bit
	offsets and the usage codes for each field.
- **Typical runtime**: instant for a descriptor; a capture runs until it is
	stopped.
- **Safe default**: parse the descriptor of the device in front of you and
	write the tree to the artefact directory. Work on a device you own or one
	the client has handed over.
- **Risky options**: the tool itself only decodes. The risk is in the
	physical engagement: plugging an unknown USB HID device into the operator's
	own machine is how keyloggers and HID implants work. Analyse the device
	on an isolated machine, and treat the device as hostile until it has been
	characterised.
- **If not installed**: `sudo apt install -y hidrd`.

## 17. Pivoting, proxies and transport

### chisel

- **Package**: `chisel` (the client binary; the server is installed as
	`chisel-server` by the same or a separate package)
- **Binary**: `chisel` and `chisel-server`
- **Purpose**: A TCP/UDP tunnel over HTTP, with SOCKS5 and reverse forwarding.
	The client runs on the target, the server on the operator's side, and the
	tunnel is multiplexed over a single HTTP connection.
- **CyberPi tool**: `cyber_pivot` (technique `pivot`).
- **Key flags** (client):
	- `chisel client <server>:8080 R:1080` — a remote forward: port 1080 on
	the server reaches the client's local port 1080.
	- `chisel client <server>:8080 R:socks` — expose a SOCKS5 proxy through
	the server.
	- `chisel client <server>:8080 L:8080:127.0.0.1:80` — a local forward.
	- `--tls` — TLS on the tunnel; use it.
	- `--tls-skip-verify` — accept any certificate. Avoid it.
	- `--auth <user:pass>` — authenticate to the server.
	- `--fingerprint <sha256>` — pin the server certificate.
	- `--keepalive <s>` — keepalive interval.
	- `--max-retry-count <n>` — reconnection attempts.
	- `-v` — verbose.
	Server side: `chisel server --port 8080 --reverse --tls --auth
	<user:pass>`.
- **Output parsed**: the client log, which reports the server URL, the
	remotes, and the SOCKS proxy address.
- **Typical runtime**: a tunnel stays up until it is closed. Setup is
	instantaneous.
- **Safe default**: `chisel client <server>:8080 R:socks --tls --auth
	<user:pass> --fingerprint <sha256>`.
- **Risky options**: `--tls-skip-verify` removes the protection against a
	machine-in-the-middle. `--reverse` turns the server into a relay that
	anyone with the server's address can use. A tunnel that outlives the
	engagement is an unmanaged backdoor into the client's network — tear it
	down and record that it was torn down.
- **If not installed**: `sudo apt install -y chisel`. If the server binary is
	missing, install it from the upstream release on the operator's machine
	and copy it to the target — the client is the part that must be on the
	target.

### ligolo-ng

- **Package**: `ligolo-ng`
- **Binary**: `proxy` (the operator side) and `agent` (the target side)
- **Purpose**: A tunnelling proxy that creates a transparent network
	interface on the target, so routed traffic appears to come from the
	target's own address. That is what makes it invisible to a firewall rule
	that trusts the subnet.
- **CyberPi tool**: none; the alternative to `cyber_pivot` for routed (rather
	than TCP) access.
- **Key flags**:
	- Proxy: `proxy -selfcert -laddr 0.0.0.0:443` — generate a self-signed
	certificate and listen on 443.
	- `-cert <file>` / `-key <file>` — use an existing certificate.
	- `-lport <n>` — the listen port.
	- Agent: `sudo ./agent -proxy <proxy>:443 -iface eth0` — the agent runs on
	the target and creates a tun interface.
	- `-L <local>:<remote>` — a local port forward.
	- `-R <remote>:<local>` — a reverse forward.
	- `-nodelay` — disable Nagle.
- **Output parsed**: the agent's log on the target, which reports the tun
	interface, the routes and the proxied connections.
- **Typical runtime**: persistent, until the agent is stopped.
- **Safe default**: `agent -proxy <proxy>:443 -iface eth0` with a pinned
	certificate, and `-L` forwards only to the specific internal host and port
	the engagement authorises.
- **Risky options**: the transparent nature of the tunnel is the point, and
	it is why the operator's address appears nowhere in the target's logs while
	the traffic still traverses the client network. Route only what the scope
	authorises; a default route over the tunnel (`0.0.0.0/0`) would take the
	target's entire traffic through the operator's host.
- **If not installed**: `sudo apt install -y ligolo-ng`. If the package is
	not available for the target's distribution, the release publishes static
	`proxy` and `agent` binaries; the agent must be copied to the target.

### proxychains4

- **Package**: `proxychains4`
- **Binary**: `proxychains4` (and `proxychains`)
- **Purpose**: Forces any dynamically linked application to send its traffic
	through a SOCKS4, SOCKS5 or HTTP proxy. It works by interposing on
	`connect()` calls, so it applies to tools that are not proxy-aware.
- **CyberPi tool**: none; it is how a non-proxy-aware tool is routed through
	a `cyber_pivot` SOCKS tunnel.
- **Key flags**:
	- `-f <file>` — the configuration file. Kali's is `/etc/proxychains4.conf`.
	- `<command>` — the command to run through the proxy.
	- `-q` — quiet.
- **Output parsed**: the proxied command's own output. proxychains4 adds a
	few lines about the chain to standard error.
- **Typical runtime**: whatever the wrapped command takes, plus a small
	overhead per connection.
- **Safe default**: `proxychains4 -f /etc/proxychains4.conf <command>` with
	the chain configured for the SOCKS5 endpoint of the pivot.
- **Risky options**: it makes an arbitrary tool reach an arbitrary network.
	The rule is the same as for the pivot itself: the destination must be
	inside the engagement scope, because proxychains bypasses the scope check
	that the CyberPi tools apply to their own targets. Do not use it to reach
	a target that the scope file would refuse.
- **If not installed**: `sudo apt install -y proxychains4`. The Kali
	configuration file lists a local `127.0.0.1:9050` SOCKS chain by default,
	which is the Tor configuration; point it at the pivot's endpoint.

### socat

- **Package**: `socat`
- **Binary**: `socat`
- **Purpose**: A general-purpose relay that moves bytes between two
	endpoints, with a large set of address types: TCP, UDP, UNIX sockets,
	TUN/TAP devices, OPENSSL, SOCKS and file descriptors.
- **CyberPi tool**: none; the ad-hoc transport for things no other tool
	covers.
- **Key flags**:
	- `-` — one side is standard input/output.
	- `TCP-LISTEN:8080,fork,reuseaddr` — listen on a port and fork per
	connection.
	- `TCP:host:port` / `UDP:host:port` — connect out.
	- `OPENSSL-CONNECT:host:443,verify=0` — connect with TLS.
	- `OPENSSL-LISTEN:443,cert=cert.pem,key=key.pem` — a TLS listener.
	- `EXEC:"<command>"` — run a command per connection.
	- `SYSTEM:"<command>"` — run a command through the shell.
	- `TUN:...,iff-up-cmd='...'` — create a TUN interface.
	- `SOCKS5-CONNECT:host:1080` — connect through a SOCKS5 proxy.
	- `-d -d` — debug output.
- **Output parsed**: the relayed bytes. A socat relay is a transport, not a
	scanner, so there is nothing to parse.
- **Typical runtime**: as long as the relay runs.
- **Safe default**: `socat -d -d TCP-LISTEN:8080,reuseaddr,fork
	TCP:<target>:80`.
- **Risky options**: `EXEC` and `SYSTEM` execute commands; a `SYSTEM` variant
	passes data through a shell, so anything that reaches the listener is
	executed. An `OPENSSL-LISTEN` with `verify=0` accepts any client
	certificate. A `TUN` relay can move the whole routing table. Bind relays
	to the specific interface and port the engagement authorises.
- **If not installed**: `sudo apt install -y socat`.

## 18. Cloud CLIs

### awscli

- **Package**: `awscli` (Debian/Kali) or the official AWS CLI v2 installer
- **Binary**: `aws`
- **Purpose**: The AWS command line interface. It queries IAM, S3, EC2,
	STS, Lambda, CloudTrail and every other service, and it can create and
	change resources.
- **CyberPi tool**: `cyber_cloud_enum` (technique `cloud-enumeration`).
- **Key flags**:
	- `--profile <name>` — a named profile from `~/.aws/credentials`.
	- `--region <region>` — the region to talk to.
	- `--output json` — machine-readable output. **Always use it.**
	- `--query <jmespath>` — select the fields you need. This keeps the
	output small.
	- `--no-cli-pager` — do not page; required in a non-interactive run.
	- `--endpoint-url <url>` — talk to a local stack, MinIO or a lab
	endpoint.
	- `--debug` — verbose SDK logging. It can print tokens; avoid it in an
	engagement.
- **Output parsed**: the JSON document from `--output json`. The wrapper
	queries the read-only surfaces — `sts get-caller-identity`,
	`iam list-users`, `iam list-roles`, `s3api list-buckets` — and parses the
	identity and the resource lists.
- **Typical runtime**: 0.5 to 3 s per API call, dominated by network
	round-trips and by the occasional throttling response.
- **Safe default**: `aws sts get-caller-identity --output json
	--no-cli-pager` followed by read-only list calls with `--query`.
- **Risky options**: every mutating call. `aws iam create-access-key`,
	`aws s3 sync`, `aws lambda invoke` and `aws sts assume-role` all act in
	the client's account. Some of them — a new access key, an assumed role —
	create persistent, invisible access. The wrapper only issues read calls;
	anything else must be a separate, explicitly authorised tool.
- **If not installed**: `sudo apt install -y awscli` (this is CLI v1; the v2
	installer from AWS is recommended for a current release, and provides
	`aws` v2 with SSO and `aws configure sso`). The identity check
	`aws sts get-caller-identity` is the fastest way to confirm the
	credentials work.

### gcloud

- **Package**: `google-cloud-cli` (Kali), or Google's own apt repository
	package
- **Binary**: `gcloud`
- **Purpose**: The Google Cloud command line interface — projects, IAM,
	service accounts, storage, compute and the rest of GCP.
- **CyberPi tool**: none; the GCP alternative to `cyber_cloud_enum`.
- **Key flags**:
	- `--project <id>` — the project to act on.
	- `--format json` — machine-readable output. `--format=value(...)` for
	a single field.
	- `--impersonate-service-account <sa>` — act as a service account.
	- `--account <email>` — the account to use.
	- `--quiet` — do not prompt.
	- `--auth-activate` / `--login` — interactive authentication, which never
	works in an unattended run.
- **Output parsed**: the JSON document from `--format json`.
- **Typical runtime**: 0.5 to 3 s per call.
- **Safe default**: `gcloud auth list --format json` and
	`gcloud projects list --format json`.
- **Risky options**: the mutating calls, and `--impersonate-service-account`,
	which uses the operator's own rights to act as another principal. That
	matters for the audit trail: the engagement's journal should record which
	identity was used, not just that gcloud ran.
- **If not installed**: `sudo apt install -y google-cloud-cli`, or add
	Google's apt repository and install `google-cloud-cli` from it. The
	Debian package in some Kali releases is called `google-cloud-sdk`.

### az

- **Package**: `azure-cli` (Kali), or Microsoft's apt repository package
- **Binary**: `az`
- **Purpose**: The Azure command line interface — subscriptions, RBAC,
	storage accounts, VMs, Key Vault and the rest of Azure.
- **CyberPi tool**: none; the Azure alternative to `cyber_cloud_enum`.
- **Key flags**:
	- `--subscription <id>` — the subscription to act on.
	- `--output json` — machine-readable output. `-o tsv` for a table.
	- `--only-show-errors` — suppress warnings on standard error.
	- `--tenant <id>` — the tenant.
	- `--debug` — verbose SDK logging; it can print tokens. Avoid it.
- **Output parsed**: the JSON document from `--output json`.
- **Typical runtime**: 0.5 to 4 s per call.
- **Safe default**: `az account list --output json` and
	`az role assignment list --output json`.
- **Risky options**: the mutating calls. `az keyvault secret list` and
	`az role assignment create` are the sensitive ones: the first exposes
	secret material and the second creates a new access path in the client's
	Azure tenant. The wrapper only issues read calls.
- **If not installed**: `sudo apt install -y azure-cli`. If the Microsoft
	repository is configured, `apt install azure-cli` pulls a newer version
	than the Kali package.

## 19. Wordlists

Kali stores its wordlists in system directories, not in the engagement
directory. The CyberPi wrappers reference them by absolute path so that a
wordlist is never resolved relative to whatever the current directory happens
to be.

### Where they live

| Path | Provided by | Contents |
|---|---|---|
| `/usr/share/seclists` | `seclists` | The largest collection: discovery, web content, DNS, hostnames, passwords, exploits. |
| `/usr/share/wordlists` | `wordlists` | A metapackage that pulls in the individual providers below. |
| `/usr/share/dirb/wordlists` | `dirb` | The classic `dirb` lists: `common.txt`, `big.txt`, `small.txt`, `vulns.txt`. |
| `/usr/share/dirbuster/wordlists` | `dirbuster` | `directory-list-2.3-medium.txt` and the other DirBuster lists. |
| `/usr/share/wfuzz` | `wfuzz` | The wfuzz wordlists, organised by content type. |
| `/usr/share/wordlists/aircrack-ng` | `aircrack-ng` | The wireless cracking lists. |
| `/usr/share/metasploit-framework/data/wordlists` | `metasploit-framework` | Small, per-module lists. |
| `/usr/share/seclists/Passwords` | `seclists` | Password lists for credential audits. |

### Installing them

```bash
sudo apt update
sudo apt install -y seclists wordlists dirb dirbuster wfuzz
```

`seclists` is the one that most often installs incompletely: the package
lands but `/usr/share/seclists` is empty or nearly empty. Repair it with:

```bash
sudo apt install --reinstall seclists
```

The directory should then contain `Discovery/`, `Passwords/`, `Exploits/` and
`Web-Content/`. If a specific list is still missing, the Seclists project
publishes it at <https://github.com/danielmiessler/seclists>.

### Choosing a list

| Purpose | List | Size |
|---|---|---|
| Fast first pass on a web application | `/usr/share/dirb/wordlists/common.txt` | 4 600 |
| Standard web enumeration | `/usr/share/dirb/wordlists/big.txt` | 20 000 |
| Thorough web enumeration | `/usr/share/seclists/Discovery/Web-Content/raft-medium-*.txt` | 25 000 |
| Very thorough web enumeration | `/usr/share/seclists/Discovery/Web-Content/raft-large-*.txt` | 3.7 M |
| DNS bruteforce | `/usr/share/seclists/Discovery/DNS/subdomains-top1million-*.txt` | 1 M |
| Hostname enumeration | `/usr/share/seclists/Discovery/Hostnames/...` | varies |
| Password audit | `/usr/share/seclists/Passwords/...` | varies |

A note on the large lists: `raft-large-*.txt` is 3.7 million entries. At
50 requests per second that is about 20 hours, and the target sees a
sustained enumeration for the whole engagement. Start with `common.txt`,
and only escalate to a large list when the client has agreed to the load
and the timeline allows it.

### Engagement hygiene

- **Keep the wordlist path absolute.** A relative path resolves against the
	engagement directory and silently finds nothing.
- **Wordlists are not evidence.** They are inputs. The findings that matter
	are the responses, and those live in the artefact directory.
- **Do not copy wordlists into the engagement directory.** They are large,
	they are not engagement output, and they would bloat the deliverable.
- **Record which list was used** in the finding. A result found with
	`common.txt` and one found with `raft-large-*.txt` are worth different
	amounts.

## 20. When a tool is missing

Every CyberPi tool declares the binaries it needs in `requires`. The shared
toolkit checks them with `which` before the command runs, and a missing
binary stops the tool with an actionable message:

```
Missing required tool(s): ffuf. Install the missing tools on Kali with:
sudo apt install -y ffuf
```

The behaviour is deliberate: the tool fails rather than degrading to a
partial or misleading result. A scanner that is not installed cannot
produce a scan, and an empty scan report that looks like a clean result is
worse than no result at all.

Practical steps:

1. **Install the package.** `sudo apt update && sudo apt install -y
	<package>`. The package name is in the entry above; it is not always the
	binary name (`dnsutils` provides `dig`, `exploitdb` provides
	`searchsploit`, `mtr-tiny` provides `mtr`).
2. **Check the whole toolchain.** `bin/cyberpi-doctor` reports every missing
	binary at once, which is faster than discovering them one tool call at a
	time.
3. **Check the PATH.** A binary installed in `/usr/local/bin` or a
	`$HOME/.local/bin` is not found if the shell that started CyberPi has a
	different `PATH`. `command -v <binary>` in the same shell that launched
	CyberPi is the check that matters.
4. **Check the version.** Kali rolling ships current versions, but a
	container image or a locked-down build may be several releases behind.
	The flag sets that matter changed in a few tools: `amass` v3 against v4,
	`nikto` before 2.5, `searchsploit` before it gained `--json`,
	`trufflehog` v2 against v3, `gitleaks` before 8.19. When a tool behaves
	unexpectedly, compare `binary --version` and `binary -h` against the
	flags in this document.
5. **Privileges.** Several tools need root and say so only at runtime:
	`tcpdump`, `tshark` (through `dumpcap`), `responder`, `bettercap`,
	`airmon-ng` and `wfite`. Give them the minimum: `setcap` for the capture
	tools, and root only where the tool genuinely needs raw sockets.
6. **Never work around a missing tool with a mock.** A fabricated result
	would enter the findings file and end up in the client's report. If a
	tool is unavailable, the engagement records the gap.

## 21. Quick install sets

For a full engagement, the Kali package groups are:

```bash
# Core: scanning, probing, crawling, DNS
sudo apt install -y nmap naabu httpx katana ffuf nuclei dnsutils whois iproute2 net-tools

# Web: injection, XSS, enumeration, TLS, WAF
sudo apt install -y sqlmap dalfox nikto gobuster wafw00f sslscan testssl.sh feroxbuster

# Credentials
sudo apt install -y hashcat john hydra trufflehog gitleaks

# Exploitation (large package)
sudo apt install -y metasploit-framework exploitdb

# Active Directory
sudo apt install -y impacket-scripts responder bloodhound-python ldapdomaindump netexec

# Wireless
sudo apt install -y aircrack-ng wifite hcxtools bettercap

# Hardware and firmware
sudo apt install -y binwalk radare2 hidrd python3-serial

# Networking and pivoting
sudo apt install -y tcpdump tshark wireshark chisel proxychains4 socat

# Cloud
sudo apt install -y awscli azure-cli google-cloud-cli

# Wordlists
sudo apt install -y seclists wordlists dirb dirbuster wfuzz
```

The heavyweight groups (`metasploit-framework`, `bloodhound`, `wireshark`,
`tshark`) are the slow part of an install; the installer script offers them
as opt-in flags for that reason.
