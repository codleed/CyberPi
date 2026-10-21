# CyberPi troubleshooting

A symptom-first guide. Find the message you are seeing, read the cause, apply
the fix, then run the verification command to confirm it worked.

Everything here is written for **Kali Linux**. CyberPi refuses to run on
Windows and macOS because the toolchain it drives (nmap, impacket,
aircrack-ng, metasploit) is Linux-only.

| Symptom | Section |
|---|---|
| `pi: command not found`, or Pi fails on a syntax error | [1. Pi is not installed or too old](#1-pi-is-not-installed-or-too-old) |
| `CyberPi targets Kali Linux and is not supported on win32` | [2. CyberPi refuses to start on the wrong OS](#2-cyberpi-refuses-to-start-on-the-wrong-os) |
| `Blocked by engagement scope: target ... is not in the authorized scope` | [3. The scope blocks everything](#3-the-scope-blocks-everything) |
| `Missing required tool(s): nmap` | [4. A tool says a binary is missing](#4-a-tool-says-a-required-binary-is-missing) |
| `cyber_cve_lookup` finds nothing, `stats` reports 0 CVEs | [5. The CVE database is empty or stale](#5-the-cve-database-is-empty-or-stale) |
| A scan completes but returns zero hosts or zero ports | [6. A scan returns nothing](#6-a-scan-returns-nothing) |
| `nmap` or `naabu` takes far longer than expected | [7. nmap or naabu is very slow](#7-nmap-or-naabu-is-very-slow) |
| `airmon-ng` says "monitor mode failed" | [8. Wireless tools fail](#8-wireless-tools-fail) |
| `msfconsole` hangs at the banner | [9. Metasploit does not start or hangs](#9-metasploit-does-not-start-or-hangs) |
| sqlmap or nuclei returns hundreds of irrelevant results | [10. sqlmap or nuclei produces noise](#10-sqlmap-or-nuclei-produces-noise) |
| The generated report has no findings | [11. The report is empty](#11-the-report-is-empty) |
| Pi takes a long time to start | [12. Pi starts slowly](#12-pi-starts-slowly) |
| `EACCES: permission denied` on `.cyberpi/journal.jsonl` | [13. Permission problems in the engagement directory](#13-permission-problems-in-the-engagement-directory) |
| You need to hand a problem to someone else | [14. Collecting a support bundle](#14-collecting-a-support-bundle) |

---

## 0. The first thirty seconds

Run these before reading further. They cover most reports.

```bash
# 1. Is the platform supported?
cat /etc/os-release | head -3

# 2. Is Node new enough, and is Pi installed?
node --version      # must be >= v22.19.0
pi --version

# 3. Does the harness see the Kali toolchain?
cyberpi-doctor

# 4. Where is the engagement state?
ls -la .cyberpi/
cat .cyberpi/scope.json
```

`cyberpi-doctor` prints one line per check and, at the end, a summary of what
is missing and how to install it (the wording below is illustrative):

```
[ok]      node v22.19.0
[ok]      pi 0.4.2
[ok]      kali-linux 2025.1
[ok]      nmap 7.95
[missing] nuclei
          -> sudo apt install -y nuclei
[ok]      scope: acme-web-2025-03 (2 targets, 6 techniques)
[ok]      cve db: /root/.cyberpi/cve.db (241883 CVEs, synced 2 days ago)
```

If the command is not on your `PATH`, run it from the package directory:

```bash
bash bin/cyberpi-doctor
```

`cyberpi-doctor --json` prints the same information as a JSON object, which is
the form to attach to a support bundle.

---

## 1. Pi is not installed or too old

**Symptom**

- `pi: command not found` after `cyberpi` starts.
- Pi starts but every tool is missing, or Pi exits with an error mentioning
  `node:` built-ins it cannot find.
- `npm WARN EBADENGINE` during installation.

**Cause**

CyberPi is a **Pi package**, not a standalone application. It extends an
existing Pi installation; it cannot replace one. Pi requires **Node 22.19 or
newer**, which is also the `engines.node` constraint in CyberPi's
`package.json`.

**Fix**

```bash
# Check the runtime
node --version          # v22.19.0 or newer
npm --version

# Install Pi (from the upstream project)
npm install -g @earendil-works/pi-coding-agent

# Verify
pi --version
```

If `node --version` is older, upgrade Node first (nvm, nodesource, or the
Kali-provided `apt install nodejs`). Pi will not start on Node 18/20 and
CyberPi inherits that limitation.

Then install CyberPi as a package:

```bash
pi install ./CyberPi        # or: pi install <git-url>
pi update                   # refresh an installed package
```

`pi install -l ./CyberPi` installs into the current project only, which keeps
the package out of every other working directory.

**Verify**

```bash
node --version && pi --version
pi --help | head -20
```

---

## 2. CyberPi refuses to start on the wrong OS

**Symptom**

```
CyberPi targets Kali Linux and is not supported on win32.
Run it inside Kali Linux (bare metal, a VM, or a container).
```

or, on a non-Kali Linux distribution:

```
CyberPi requires Kali Linux; Debian GNU/Linux 12 was detected and
CYBERPI_STRICT_KALI=1 is set.
```

**Cause**

`extensions/lib/platform.ts` implements the support gate:

- **Not Linux** (Windows, macOS): always refused. The tools drive Linux-only
  binaries and the packet-capture assumptions do not hold elsewhere.
- **Linux but not Kali**: allowed with a warning, *unless*
  `CYBERPI_STRICT_KALI=1` is set, which turns the warning into a refusal.

`bin/cyberpi` performs the same check before starting Pi, so the message
appears before the agent comes up.

**Fix**

Use a Kali VM, a Kali container, or a live USB. If you must work on another
Linux distribution:

```bash
# 1. See what the gate sees
cat /etc/os-release | grep -E '^(NAME|VERSION_ID|ID)='

# 2. Allow the degraded mode explicitly (one command, one session)
unset CYBERPI_STRICT_KALI

# 3. Or export it for the session
export CYBERPI_STRICT_KALI=0
```

Distributions with `ID_LIKE` containing `kali` are treated as Kali. A
container image based on Kali (`kalilinux/kali-rolling`) works; a plain
Debian image with a Kali apt mirror does not, because the check reads
`/etc/os-release`.

**Verify**

```bash
grep -E '^(NAME|VERSION_ID|ID|ID_LIKE)=' /etc/os-release
echo "strict=${CYBERPI_STRICT_KALI:-unset}"
cyberpi --check
```

---

## 3. The scope blocks everything

**Symptom**

The tool returns a refusal instead of running. The first line is the reason
from the authorization engine; the harness appends the same "add it to the
scope file" hint every time:

```
Blocked by engagement scope: target 10.0.0.5 is not in the authorized scope
of engagement "acme-web-2025-03". Add it to .cyberpi/scope.json if the client
authorized it.

Add the target to .cyberpi/scope.json if the client authorized it, then retry.
```

Other variants you will meet:

```
Blocked by engagement scope: no scope.json found. Create
<engagement>/.cyberpi/scope.json and add the authorized targets before
running this action.
```

```
Blocked: technique "exploit" is not in the engagement technique allowlist
(recon, port-scan, service-enumeration, web-testing, vulnerability-scan)
```

```
Blocked by engagement scope: port 8443 is not in the allowed ports 80, 443
```

```
Blocked by engagement scope: protocol unknown is not in the allowed protocols tcp
```

```
Blocked by engagement scope: technique exploit is not allowed by rule 10.0.0.0/24
```

**Cause**

This is the authorization engine working, not a bug. CyberPi **fails closed**:
with no scope file, nothing except the local machine is reachable. Three
independent filters exist, and they are checked in this order:

1. **Global technique allowlist** (`techniques` at the top level of
   `scope.json`) — checked *before* the target, so a narrow allowlist blocks
   even `localhost`.
2. **Target rules** (`rules[].target`) — the host, CIDR or wildcard that
   matches.
3. **Per-rule filters** — `ports`, `protocols` and `techniques` on the rule
   itself.

The last three messages come from the per-rule filters. `protocol unknown`
means the tool did not declare a protocol, so a rule that restricts protocols
cannot match it.

**Fix**

The scope file lives at `<engagement>/.cyberpi/scope.json`. It is JSON with
comments allowed (the loader strips `//` and `/* */`).

```jsonc
{
  // Engagement name, shown in every refusal and in the report.
  "engagement": "acme-web-2025-03",
  "client": "Acme Corp",
  "authorization": {
    "statement": "Written authorization, signed 2025-03-01 by the client CISO.",
    "authorizedBy": "ciso@acme.example",
    "start": "2025-03-01T00:00:00Z",
    "end": "2025-03-31T23:59:59Z"
  },

  // Global technique allowlist. Empty or absent = every technique allowed.
  // Valid identifiers:
  //   recon, port-scan, service-enumeration, web-testing, vulnerability-scan,
  //   exploit, password-audit, privilege-escalation, active-directory, pivot,
  //   wireless, iot-hardware, cloud-enumeration, forensics, social-engineering
  "techniques": [
    "recon",
    "port-scan",
    "service-enumeration",
    "web-testing",
    "vulnerability-scan"
  ],

  // Local machine and loopback stay reachable for self-testing (default true).
  "allowSelfTest": true,

  "rules": [
    // 1. A single host.
    { "target": "10.0.0.5", "notes": "jump host" },

    // 2. A CIDR block. IPv4 and IPv6 both work.
    { "target": "192.168.10.0/24" },
    { "target": "2001:db8::/32" },

    // 3. A domain: the domain AND its subdomains.
    { "target": "acme.example" },

    // 4. Subdomains only, never the apex.
    { "target": "*.acme.example" },

    // 5. Exactly this host, no subdomains.
    { "target": "exact:shop.acme.example" },

    // 6. Restrict the rule to ports and protocols.
    { "target": "10.0.0.0/28", "ports": [80, 443, 8443], "protocols": ["tcp"] },

    // 7. Restrict a rule to specific techniques.
    {
      "target": "10.0.0.0/28",
      "techniques": ["recon", "port-scan", "vulnerability-scan"]
    }
  ]
}
```

Target syntax at a glance:

| Written as | Matches |
|---|---|
| `10.0.0.5` | that one IPv4 address |
| `10.0.0.0/24` | every address in the IPv4 CIDR |
| `2001:db8::/32` | every address in the IPv6 CIDR |
| `acme.example` | `acme.example` and every subdomain of it |
| `*.acme.example` | subdomains only, **not** `acme.example` |
| `exact:acme.example` | that host name only, no subdomains |

Two gotchas that cause confusing refusals:

- **Ports are matched from the tool's own parameters or from the target
  string.** If a rule says `"ports": [443]` and you scan `https://shop.acme.example`
  without the port in the URL, the tool cannot know the port and the rule
  refuses. Write the port explicitly: `https://shop.acme.example:443`.
- **A protocol-restricted rule only matches tools that declare a protocol.**
  If you get `protocol unknown is not in the allowed protocols tcp`, either add
  `"protocols": ["tcp", "udp"]` to the rule, or drop the protocol filter.

Blocked attempts are journalled, so the refusal history is recoverable:

```bash
grep '"action":"blocked"' .cyberpi/journal.jsonl
```

**Verify**

```bash
cat .cyberpi/scope.json
# The harness prints a one-line summary of the active scope:
/cyber
```

Then re-run the blocked tool. A target that matches a rule now runs; a target
that does not is refused with the same message and the rule that was
considered.

---

## 4. A tool says a binary is missing

**Symptom**

```
Missing required tool(s): nmap, nuclei. Install the missing tools on Kali with:
sudo apt install -y nmap nuclei
```

**Cause**

Every tool declares the binaries it needs in `requires`. The shared toolkit
checks them with `which` before the command is spawned, so a missing binary
produces a clear message instead of a shell error.

**Fix**

Install the Kali package that provides the binary. The mapping is not always
one to one:

| Binary the tool needs | Kali package | Install command |
|---|---|---|
| `nmap` | `nmap` | `sudo apt install -y nmap` |
| `naabu` | `naabu` | `sudo apt install -y naabu` |
| `httpx` (projectdiscovery) | `httpx-toolkit` | `sudo apt install -y httpx-toolkit` |
| `katana` | `katana` | `sudo apt install -y katana` |
| `ffuf` | `ffuf` | `sudo apt install -y ffuf` |
| `nuclei` | `nuclei` | `sudo apt install -y nuclei` |
| `sqlmap` | `sqlmap` | `sudo apt install -y sqlmap` |
| `dalfox` | `dalfox` | `sudo apt install -y dalfox` |
| `dig` | `dnsutils` | `sudo apt install -y dnsutils` |
| `whois` | `whois` | `sudo apt install -y whois` |
| `tcpdump` | `tcpdump` | `sudo apt install -y tcpdump` |
| `curl` | `curl` | `sudo apt install -y curl` |
| `hashcat` | `hashcat` | `sudo apt install -y hashcat` |
| `hydra` | `hydra` | `sudo apt install -y hydra` |
| `trufflehog` | `trufflehog` | `sudo apt install -y trufflehog` |
| `searchsploit` | `exploitdb` | `sudo apt install -y exploitdb` |
| `msfconsole` | `metasploit-framework` | `sudo apt install -y metasploit-framework` |
| `ldapdomaindump` | `ldapdomaindump` | `sudo apt install -y ldapdomaindump` |
| `impacket-smbserver` | `impacket-scripts` | `sudo apt install -y impacket-scripts` |
| `airodump-ng`, `aireplay-ng`, `aircrack-ng` | `aircrack-ng` | `sudo apt install -y aircrack-ng` |
| `binwalk` | `binwalk` | `sudo apt install -y binwalk` |
| `hidrd` | `hidrd` | `sudo apt install -y hidrd` |
| `chisel` | `chisel` | `sudo apt install -y chisel` |
| `aws` | `awscli` | `sudo apt install -y awscli` |
| `python3` | `python3` | `sudo apt install -y python3` |

Refresh the package index first if the install fails with "Unable to locate
package":

```bash
sudo apt update
sudo apt install -y <package>
```

**Alternatives and renames**

- **crackmapexec -> netexec.** CrackMapExec is no longer shipped by Kali. The
  replacement is **netexec**, packaged as `netexec` and providing both the
  `netexec` and `nxc` commands:

  ```bash
  sudo apt install -y netexec
  nxc --version
  netexec --help
  ```

  Use `nxc` in place of `crackmapexec` in any command you run by hand. The
  option names are close but not identical: `cme smb 10.0.0.0/24 -u user -p pass`
  becomes `nxc smb 10.0.0.0/24 -u user -p pass`.

- **`httpx` name collision.** Kali also ships a Python package called `httpx`
  whose CLI is unrelated to projectdiscovery's tool. CyberPi needs the
  projectdiscovery one (`httpx -version` prints a banner with `projectdiscovery.io`).
  If the wrong binary is on `PATH`, install `httpx-toolkit` and check which
  one resolves:

  ```bash
  which -a httpx
  httpx -version
  ```

- **`msfconsole` vs `msfvenom`.** Both come from `metasploit-framework`.

**Verify**

```bash
cyberpi-doctor                 # lists every missing tool and the fix
which -a nmap nuclei httpx     # which resolves first
nmap --version | head -2
```

Re-run the tool that failed. The `Missing required tool(s)` error is raised
before the command runs, so it disappears as soon as the binary is on `PATH`.

---

## 5. The CVE database is empty or stale

**Symptom**

- `cyber_cve_lookup` reports "no data" for a known CVE.
- `cyber_cve_search` returns nothing.
- `cyberpi-doctor` reports `cve db: missing` or `0 CVEs`.
- The database file is far smaller than expected.

**Cause**

The CVE database is a local SQLite mirror of the NVD 2.0 feed, the CISA Known
Exploited Vulnerabilities catalog and FIRST EPSS. It is **not** bundled and it
is **not** populated at install time. Until a sync runs, the tools have
nothing to query.

The sync is rate limited by the NVD: the public NVD 2.0 API allows only
**5 requests per 30 seconds** without an API key (50 with one). A complete
NVD pull is therefore a multi-hour operation that is deliberately throttled,
and the incremental sync — which fetches only CVEs modified since the last
run — is the everyday path.

**Fix**

```bash
# 1. Where the database should be
echo "${CYBERPI_CVE_DB:-$HOME/.cyberpi/cve.db}"

# 2. Populate it (incremental — use this normally)
#    Run from the CyberPi package directory, or use the absolute path to
#    tools/cvedb/cvedb.py inside it.
python3 tools/cvedb/cvedb.py sync

# 3. Full rebuild from scratch (hours)
python3 tools/cvedb/cvedb.py sync --full

# 4. Skip the optional sources if they are slow or unreachable
python3 tools/cvedb/cvedb.py sync --no-epss
python3 tools/cvedb/cvedb.py sync --no-kev
```

The same operation is available inside the harness as the
**`cyber_cve_sync`** tool, which is journalled like every other action, and
as an npm script in the package directory:

```bash
npm run cve-sync
```

**Expected size and location**

| Property | Value |
|---|---|
| Default location | `~/.cyberpi/cve.db` (override with `CYBERPI_CVE_DB`) |
| Home directory | `~/.cyberpi`, override with `CYBERPI_HOME` |
| Expected records | roughly 250,000–300,000 CVEs after a full sync |
| Expected size | a few hundred MB up to ~2 GB, depending on the NVD release |
| KEV entries | around 1,500–2,000 |
| Freshness | NVD publishes roughly 150–250 new/modified CVEs per day |

**Disk space**

A full sync needs several gigabytes of free space (the SQLite file plus
write-ahead and temporary files during the import):

```bash
df -h ~ /tmp
du -sh ~/.cyberpi 2>/dev/null
```

**Verify**

```bash
# Record counts and freshness
python3 tools/cvedb/cvedb.py stats --json

# A known CVE must return data
python3 tools/cvedb/cvedb.py get CVE-2021-44228 --json

# The KEV catalog must be populated
python3 tools/cvedb/cvedb.py kev --limit 5 --json

# The harness sees the same database
cyberpi-doctor
```

Inside Pi, ask for the same thing with the `cyber_cve_lookup` and
`cyber_cve_sync` tools; `cyber_cve_sync` reports the number of records it
added.

---

## 6. A scan returns nothing

**Symptom**

- `cyber_portscan` completes in seconds and lists no ports.
- `cyber_service_scan` reports `0 hosts up`.
- `cyber_http_probe` finds no web server on a host that clearly has one.
- The result looks suspiciously fast for the target size.

**Cause**

In order of likelihood:

1. **The scan is blocked by the edge.** A firewall that drops packets makes
   ports read as `filtered` rather than `closed`, so a scan of a filtered
   host legitimately returns nothing.
2. **The wrong egress path.** A VPN, a container network or a second
   interface sends the traffic somewhere the client never sees, or the
   traffic never leaves the machine.
3. **The scan was rate limited.** Rate-limited scanners silently drop
   packets and report fewer results.
4. **A stale cached result.** The toolkit caches identical calls; a cached
   empty result from an earlier failed attempt is replayed.
5. **The target is wrong** — a typo, a stale DNS record, or a hostname that
   now resolves elsewhere.

**Fix**

Check the routing and the interface first:

```bash
# Which interface and source address will the traffic use?
ip route get 10.0.0.5
ip -br addr

# Is the name resolving where you think?
dig +short shop.acme.example
getent hosts shop.acme.example

# Is anything actually listening locally? (self-test)
ss -tlnp
```

Clear the cache so the next call really re-scans:

```bash
rm -f .cyberpi/cache/results.json
```

If the target is behind a firewall, scan a wider port range and read the
`filtered`/`closed` distinction rather than assuming "no services":

```bash
nmap -sS -Pn -p- --open 10.0.0.5
```

**Verify**

```bash
# A guaranteed-visible target
ping -c1 127.0.0.1

# One port, one host, maximum visibility of what happens
nmap -Pn -p 443 -T4 10.0.0.5

# Confirm the harness is not replaying a cached result
ls -la .cyberpi/cache/
```

---

## 7. nmap or naabu is very slow

**Symptom**

- `cyber_service_scan` on a /24 takes tens of minutes.
- `cyber_portscan` seems to stall on the first host.
- The tool times out (the journal entry says `command timed out`).

**Cause**

Default timing is deliberately conservative, and three things make it slower:

1. **Host discovery.** nmap sends ICMP/TCP probes to every address before
   scanning, which doubles the traffic on a large range.
2. **Retries.** A filtered host is retried, and retries dominate the runtime
   when most hosts are filtered.
3. **UDP scanning** is a different beast: nmap probes every port of every
   host with empty packets and waits for each to time out.

**Fix**

Use timing templates and cut the work down:

```bash
# nmap timing templates
nmap -T4 ...            # fast (default for wide scans)
nmap -T3 ...            # default
nmap -T2 ...            # polite, slow
nmap -T0 ...            # paranoid, very slow — avoid

# Skip host discovery (hosts are known to be up)
nmap -Pn ...

# Force IPv4 only; IPv6 discovery can dominate the runtime
nmap -4 ...

# Limit retries and the per-host budget
nmap --max-retries 1 --host-timeout 30s ...

# SYN scan: needs root, half the packets, reaches far more hosts
sudo nmap -sS -T4 -Pn ...
# Connect scan: works unprivileged, completes the TCP handshake
nmap -sT -T4 -Pn ...
```

```bash
# naabu: rate and concurrency
naabu -host 10.0.0.0/24 -rate 1000 -c 100 -p top-100
naabu -host 10.0.0.0/24 -rate 5000 -c 500 -top-ports 1000
```

nmap's UDP scanning deserves its own budget:

```bash
sudo nmap -sU --top-ports 50 -T4 10.0.0.5     # a realistic UDP sweep
```

The CyberPi tools expose the tuning that matters; use the tool's own
parameters where they exist (for example the `rate` parameter on
`cyber_portscan`) rather than hand-rolling commands.

**Verify**

```bash
# Time a single host before and after tuning
time nmap -Pn -p 1-1000 -T4 10.0.0.5
time nmap -Pn -p 1-1000 -T2 10.0.0.5

# Confirm you are not waiting on retries
nmap --stats-every 5s ...     # prints progress and timing stats
```

---

## 8. Wireless tools fail

**Symptom**

- `airmon-ng` reports `monitor mode failed on wlan0`.
- `cyber_wireless_scan` finds no access points.
- `cyber_wireless_crack` cannot find a handshake or a PMKID.
- `airodump-ng` shows a capture that never sees EAPOL frames.

**Cause**

Monitor mode is a hardware-driver capability, not a software setting. Four
things must all be true:

1. **Root.** Changing the mode of a wireless interface requires
   `CAP_NET_ADMIN`.
2. **A monitor-capable adapter.** Not every chipset supports monitor mode or
   packet injection. A built-in laptop adapter usually cannot inject.
3. **A working driver.** Some chipsets need a firmware package
   (`firmware-iwlwifi`, `firmware-atheros`) and some need a driver that
   `airmon-ng` cannot switch automatically.
4. **A regulatory domain.** A locked-down regulatory domain (a US laptop
   shipped with a locked domain) refuses most channels.

**Fix**

```bash
# 1. Root and a clean start
sudo airmon-ng check

# 2. Unblock the adapter
rfkill unblock wifi
rfkill list

# 3. Confirm the driver
iw dev
sudo iw reg set US        # or your country code
sudo iw reg get

# 4. Put the interface into monitor mode
sudo airmon-ng start wlan0
iw dev                      # look for the monitor-mode interface (often wlan0mon)
sudo ip link set wlan0mon up

# 5. Test injection
sudo aireplay-ng --test wlan0mon
```

If `airmon-ng` still refuses, switch the mode by hand with `iw`:

```bash
sudo iw dev wlan0 set monitor otherbss
sudo ip link set wlan0 up
```

If the adapter is not capable, use one that is. A USB adapter with an
Atheros AR9271 or a MediaTek MT7612U is a common choice for monitoring and
injection.

**Handshake capture requirements**

A WPA handshake is four EAPOL messages exchanged between the access point and
a *client*. Consequences:

- The AP must have at least one associated client. An idle AP produces no
  handshake, ever.
- You must capture on the AP's channel. `airodump-ng` hops channels by
  default; pin it with `--channel` while capturing.
- The capture must run long enough to catch the association. Keep it running
  and use deauthentication to force a re-association:

```bash
# Terminal 1: capture, pinned to the AP channel
sudo airodump-ng -c 6 -w /tmp/handshake --bssid AA:BB:CC:DD:EE:FF wlan0mon

# Terminal 2: deauth the client to force a re-association
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c <client-mac> wlan0mon
```

```bash
# Verify the capture contains a handshake
sudo aircrack-ng /tmp/handshake-01.cap
```

For PMKID attacks (no client required), use `hcxdumptool` and
`hcxtools`, and convert the capture:

```bash
sudo apt install -y hcxtools
sudo hcxpcapngtool -o /tmp/pmkid.pcapng /tmp/handshake-01.cap
```

**Verify**

```bash
sudo airmon-ng
sudo airodump-ng wlan0mon        # lists APs and their clients
sudo aireplay-ng --test wlan0mon # must print "Injection is working"
```

---

## 9. Metasploit does not start or hangs

**Symptom**

- `msfconsole` prints the banner and then sits there.
- `cyber_exploit_run` times out.
- `db_status` reports that the database is not connected.
- `searchsploit` works but `msfconsole` does not.

**Cause**

Metasploit's console needs its PostgreSQL database. On Kali the database is
managed by `msfdb`, which is a wrapper around a local PostgreSQL instance.
If PostgreSQL is not running, the console blocks while it tries to connect,
and `db_status` reports `not connected`.

**Fix**

```bash
# 1. Check the database service
sudo msfdb status
sudo systemctl status postgresql

# 2. Start it
sudo msfdb start
sudo msfdb status          # expect: "postgresql is running"

# 3. If the database is in a broken state, rebuild it
sudo msfdb stop
sudo msfdb init
sudo msfdb start

# 4. Test the console non-interactively
msfconsole -q -x "db_status; exit"

# 5. Verify a workspace exists
msfconsole -q -x "workspace list; exit"
```

A first `msfconsole` start is slow because Metasploit builds its module
cache. Let it finish once; later starts are fast. A module cache you can
rebuild when it is corrupted:

```bash
sudo rm -rf ~/.msf4/modules
msfconsole -q -x "exit"
```

If PostgreSQL is broken after an upgrade:

```bash
sudo systemctl restart postgresql
sudo msfdb stop && sudo msfdb init && sudo msfdb start
```

**Verify**

```bash
sudo msfdb status
msfconsole -q -x "db_status; exit"      # expect: "connected to postgresql"
msfconsole -q -x "search type:exploit name:log4j; exit"
```

---

## 10. sqlmap or nuclei produces noise

**Symptom**

- `cyber_sqli` returns dozens of "parameter is injectable" results, most of
  them false positives.
- `cyber_vuln_scan` reports hundreds of findings that do not reproduce.
- Nuclei findings include hosts that were never in the engagement.
- The report fills up with low-severity noise that buries the real issues.

**Cause**

Four different mechanisms produce this:

1. **Scope.** Nuclei follows redirects and template requests to hosts that
   were never authorized. CyberPi checks the *starting* target; a template
   that walks off-site is not re-checked.
2. **Rate limiting.** sqlmap's default is one request per second, nuclei can
   run hundreds in parallel. Both look like "the server is slow" and then like
   "no results" or "everything is injectable".
3. **False positives.** The default sqlmap risk/level is 1/1, which already
   produces noise; nuclei's default templates include many informational
   checks.
4. **Scan depth.** Directory bruteforce and template scanning against a
   large wordlist multiply the request count.

**Fix**

**sqlmap** — raise the bar before you believe a result:

```bash
# Minimum: less noise, slower, more accurate
sqlmap -u "https://shop.acme.example/product?id=1" \
  --batch --level=3 --risk=2 --threads=4 --timeout=10

# Confirm by hand before recording a finding
sqlmap -u "https://shop.acme.example/product?id=1" --batch --technique=BT \
  --string="Acme" --not-string="Not found"

# Slow down when the target is fragile
sqlmap -u "..." --delay=2 --timeout=15
```

**nuclei** — filter by severity, rate and tag:

```bash
nuclei -u https://shop.acme.example -severity medium,high,critical
nuclei -u https://shop.acme.example -rl 50        # 50 requests per second
nuclei -u https://shop.acme.example -c 25         # 25 templates in parallel
nuclei -u https://shop.acme.example -etags dos,fuzz
nuclei -u https://shop.acme.example -fp -fpt "self-contained"   # fingerprint filter
nuclei -u https://shop.acme.example -stats
```

Always confirm a nuclei finding before recording it: re-run the single
template with `-debug` and reproduce it with `curl` before it becomes a
finding. Severity tiers above `info` are a reasonable default for a client
report.

**Keep the scope tight.** If a template is walking to another host, restrict
it with `-scope` or run it per-host inside the authorized range rather than
across a list of URLs.

**Verify**

```bash
# Count requests and check the rate the target actually saw
nuclei -u https://shop.acme.example -stats -silent | tail -5

# Re-run one template in isolation
nuclei -u https://shop.acme.example -t http/exposures/.../CVE-....yaml -debug
```

---

## 11. The report is empty

**Symptom**

- `cyber_report` produces a document with no findings.
- `/report` renders an empty list.
- The report has a scope section but no findings section.

**Cause**

The report is rendered from the **findings** recorded in the engagement, not
from the journal and not from the scan output. A scanner finding is only a
finding once it has been recorded with `cyber_record_finding`. If nothing was
recorded, the report is empty — this is correct behaviour, not a bug.

Everything lives under the engagement root:

```
<engagement>/
└── .cyberpi/
    ├── scope.json          # the authorization
    ├── journal.jsonl       # every action taken, one JSON object per line
    ├── surface.json        # the merged attack-surface index
    ├── findings/           # one Markdown file per recorded finding
    ├── artifacts/          # raw scanner output
    ├── cache/              # cached results
    ├── notes/
    └── reports/            # generated deliverables
```

**Fix**

Record the findings from inside the session, one `cyber_record_finding` call
per finding, or check whether anything was recorded at all:

```bash
ls -la .cyberpi/findings/
cat .cyberpi/findings/*.md 2>/dev/null | head -40
```

If the directory is empty, nothing was recorded. Use the journal to see what
was actually done, and to reconstruct the finding set:

```bash
wc -l .cyberpi/journal.jsonl
tail -20 .cyberpi/journal.jsonl
```

**Check the engagement root.** The harness resolves the engagement from the
current working directory, unless `CYBERPI_ENGAGEMENT` overrides it. A stale
override points the harness at a different engagement directory, so findings
land somewhere you are not looking:

```bash
echo "${CYBERPI_ENGAGEMENT:-<unset, using cwd>}"
pwd
ls -la .cyberpi/
```

**Verify**

```bash
ls .cyberpi/findings/ | wc -l        # number of recorded findings
ls -la .cyberpi/reports/              # generated reports
cyberpi-report                        # renders the report outside the agent
```

---

## 12. Pi starts slowly

**Symptom**

- Pi takes many seconds before the first prompt.
- Startup time grows every time you install something else.
- The delay happens before any engagement work begins.

**Cause**

Pi loads, at start-up:

- every **extension** in every installed package (CyberPi registers 35 tools
  plus the dashboard, the context injector and the prompt templates);
- the **name and description of every skill** — the body of a skill is read
  lazily, but the listing is not.

If the package directory has accumulated several packages, or a personal
skills directory has grown large, start-up time grows with it. The tools
themselves are not the problem: no scanner runs at start-up.

**Fix**

Load only what you are working on:

```bash
# Load CyberPi from the working tree, without installing it as a package
pi --extension ./CyberPi
# -e is the short form
pi -e ./CyberPi
```

Prune what is not in use:

```bash
# Which packages are installed? (user scope and project scope are listed
# separately, each with the path it was installed to)
pi list

# Remove a package you no longer need
pi uninstall <package>

# Install CyberPi for one project only, instead of for every project
pi install -l ./CyberPi
```

Keep the skills directory small: one skill per workflow, and delete the
copies you have written for a single engagement. CyberPi ships 17 skills; a
few hundred personal skills is what makes start-up crawl.

**Verify**

```bash
time pi --extension ./CyberPi        # compare against a plain start
time pi -e ./CyberPi
```

Measure on a warm start (the second run) — the first run pays for module
resolution and cache building.

---

## 13. Permission problems in the engagement directory

**Symptom**

```
Error: EACCES: permission denied, open '.cyberpi/journal.jsonl'
```

or:

```
Error: EACCES: permission denied, mkdir '.cyberpi/artifacts'
```

The tool fails with an I/O error instead of running, and the journal has a
gap where the action should be.

**Cause**

Almost always the same: the engagement directory was created (or written) as
root — typically by running `sudo cyberpi` or `sudo mkdir -p` once — and the
session now runs as an unprivileged user. The harness writes the journal,
artifacts, findings and cache as the current user, and it cannot write into a
root-owned directory.

Secondary causes: a read-only mount, a full filesystem, or SELinux/AppArmor
denying the write.

**Fix**

```bash
# 1. Who owns what?
ls -ld . .cyberpi .cyberpi/*
stat -c '%U:%G %a %n' .cyberpi .cyberpi/journal.jsonl

# 2. Give the directory back to the user that runs the agent
sudo chown -R "$(id -un):$(id -gn)" .cyberpi
chmod -R u+rwX .cyberpi

# 3. Never run the harness as root
#    Root is only needed for: monitor mode, SYN scans, packet capture.
```

If the engagement lives under `/root` (a common side effect of an earlier
`sudo` run), move it instead of loosening permissions on `/root`:

```bash
sudo mkdir -p ~/engagements
sudo mv /root/<engagement> ~/engagements/
cd ~/engagements/<engagement>
```

If the filesystem is full:

```bash
df -h .
du -sh .cyberpi/*
```

If SELinux is denying access (RHEL-family hosts, occasionally in Kali
containers):

```bash
getenforce
sudo restorecon -Rv .
```

**Verify**

```bash
# Write as the current user, without sudo
touch .cyberpi/.perm-check && rm .cyberpi/.perm-check && echo "writable"
cyberpi-doctor
```

The journal must grow after a tool runs:

```bash
wc -l .cyberpi/journal.jsonl
```

---

## 14. Collecting a support bundle

**Symptom**

You need to hand a problem to someone else: the maintainer, a colleague, or
your own notes from three weeks ago.

**Fix**

Collect four things: the environment report, the journal, the scope and the
tool versions. **Never include raw credentials, session cookies, tokens,
private keys or the artifact directory** — those files contain harvested
material by design.

```bash
# 1. The environment report, machine readable
cyberpi-doctor --json > /tmp/cyberpi-doctor.json

# 2. The journal and the scope (the engagement record)
cp .cyberpi/journal.jsonl /tmp/journal.jsonl
cp .cyberpi/scope.json /tmp/scope.json

# 3. Versions of everything that matters
{
  echo "date:        $(date -Is)"
  echo "pi:          $(pi --version 2>&1)"
  echo "node:        $(node --version)"
  echo "kernel:      $(uname -a)"
  echo "os:          $(grep PRETTY_NAME /etc/os-release)"
  echo "python:      $(python3 --version 2>&1)"
  for b in nmap naabu httpx katana ffuf nuclei sqlmap dalfox searchsploit msfconsole; do
    printf '%-14s %s\n' "$b" "$(command -v "$b" || echo MISSING)"
  done
} > /tmp/versions.txt

# 4. Package it
tar czf "$HOME/cyberpi-support-$(date +%F).tar.gz" \
  -C /tmp cyberpi-doctor.json versions.txt journal.jsonl scope.json
```

Before sending, check the bundle:

```bash
tar tzf "$HOME/cyberpi-support-"*.tar.gz
tar xzf "$HOME/cyberpi-support-"*.tar.gz -O scope.json | head -40
```

Redact the `scope.json` if it contains client names you do not want to share,
and drop `journal.jsonl` if it contains hostnames you cannot disclose. The
journal records the target, the command line and the exit code of every
action the harness took, so it is the most informative file in the bundle and
the one most likely to contain confidential detail.

**Verify**

```bash
tar tzf "$HOME/cyberpi-support-"*.tar.gz
ls -la "$HOME/cyberpi-support-"*.tar.gz
```

---

## 15. Where to report a problem

1. **Check the obvious first.** `cyberpi-doctor` names the missing package;
   `cyberpi-doctor --json` shows the environment; the journal shows what
   CyberPi actually ran and what it refused.
2. **Search the existing issues** in the repository that CyberPi was
   installed from. `pi list` prints the path each package was installed to,
   and the repository it came from is the `repository` field of that
   package's `package.json`.
3. **Open a new issue** with:
   - the symptom, quoted exactly (the whole refusal message, not a
     paraphrase);
   - `cyberpi-doctor --json`;
   - the engagement root layout (`ls -R .cyberpi | head -40`) with the scope
     redacted;
   - the relevant `.cyberpi/journal.jsonl` lines;
   - the command you ran by hand and its output, if the problem is in a
     single tool;
   - the CyberPi version and the Pi version.
4. **Never attach** artifacts that contain credentials, cookies, tokens,
   private keys, wordlists or the whole engagement directory. If a finding
   depends on a credential, describe it ("a valid service account was found")
   rather than pasting it.
5. **Pi itself** (missing tools, model access, UI problems) belongs in the Pi
   repository. CyberPi issues are about the extension, the scope engine, the
   tool wrappers, the CVE database and the documentation.
