# Evidence handling reference

Everything in this file is the detail behind `skills/forensics-and-ir/SKILL.md`:
the custody form, the acquisition procedures, the log and packet recipes, and
the report skeleton. Use it as a checklist, not as a script — run the commands
that apply, in the order the phase requires, and record what you ran.

All commands run on the Kali analysis box or on the live host. Sections 2 and
3 read live state: they change nothing, but the output is a point-in-time
snapshot, so run them in one pass and hash the result immediately. Commands
that write — acquisition, carving, extraction — must be pointed at your
evidence volume, never at the original device.

---

## 1. Chain of custody

Chain of custody answers one question: *can this artifact be tied to the
event and to the person who collected it?* A report that cannot answer it
fails in review, no matter how good the analysis is.

### Rules

- **One item, one id.** Number acquisitions `E-001`, `E-002`, … in the order
  they were taken. A copy of an item gets a new id that references the
  original (`E-004 (copy of E-002)`).
- **Hash at the boundary.** Every time an item is created, copied,
  transferred or handed over, hash it and record the hash. The recorded hash
  is what makes the item verifiable later.
- **Append only.** Never edit an earlier manifest or custody row. A correction
  is a new row that says what is being corrected and why. A row that changed
  after the fact is the single most damaging thing in a forensic file.
- **Name the human.** "Acquired by" is a person, not a role. A custody chain
  signed by `alex` is defensible; one signed by `the IR team` is not.
- **UTC.** Every timestamp is ISO 8601 in UTC (`2025-03-01T09:14:22Z`). Record
  the source host's local timezone in the case header, once.

### Manifest template

Keep it at `.cyberpi/notes/evidence-manifest.md`.

```markdown
# Evidence manifest — <incident id>

- Engagement: <engagement name>
- Operator: <name>
- Analysis host: <hostname>, <OS version>
- Source host timezone: <e.g. Europe/Berlin, UTC+01:00>
- Started (UTC): <iso timestamp>

| Item | Description | Source | Method | Acquired by | Acquired (UTC) | Size | SHA-256 | Stored at |
|---|---|---|---|---|---|---|---|---|
| E-001 | Memory image | 10.0.0.5 | LiME 6.1 `insmod` | alice | 2025-03-01T09:14:22Z | 8.0 GiB | `9f2c…` | /mnt/evidence/mem.lime |
| E-002 | Disk image | 10.0.0.5 `/dev/sda` | dc3dd 7.2, `bs=4M conv=noerror,sync` | alice | 2025-03-01T09:41:05Z | 500 GiB | `4ab1…` | /mnt/evidence/disk_sda.img |
| E-003 | Packet capture | 10.0.0.5 ↔ 198.51.100.7 | `cyber_capture` (tcpdump) | alice | 2025-03-01T10:03:40Z | 41 MiB | `c771…` | .cyberpi/artifacts/capture-10.0.0.5-2025-03-01T10-40-12-000Z.pcap |

## Transfer log

| Date/time (UTC) | Item | From | To | Purpose | Signature |
|---|---|---|---|---|---|
| 2025-03-01T09:44:10Z | E-002 | alice | bob | second analyst review | bob |
```

### Hashing

```bash
# Hash an item (SHA-256 is the default; SHA-512 for the final archive)
sha256sum /mnt/evidence/disk_sda.img
sha512sum /mnt/evidence/disk_sda.img > /mnt/evidence/disk_sda.img.sha512

# Hash a whole directory tree deterministically
find /mnt/evidence -type f -print0 | sort -z | xargs -0 sha256sum > /mnt/evidence/SHA256SUMS

# Verify before and after analysis
cd /mnt/evidence && sha256sum -c SHA256SUMS
```

Record the verification result in the manifest (`verified 2025-03-02T08:10Z`,
`mismatch — see note`). A mismatch is a finding about the custody chain, and
it must be reported as one.

---

## 2. Volatile acquisition — Linux

Run the whole set in one pass while the host is still up. Write each output to
a separate file under the evidence directory, then hash the set.

```bash
# 0. Identification and clock
date -u; timedatectl; hostnamectl; uname -a; cat /etc/os-release
cat /proc/uptime                       # uptime at collection time

# 1. Users and sessions
w; who -a; last -Faiw | head -100; lastlog

# 2. Processes, with start time and full command line
ps -eo pid,ppid,lstart,etime,user,stat,args --sort=start_time
ls -l /proc/*/exe 2>/dev/null          # deleted binaries show as " (deleted)"
ls -l /proc/*/cwd 2>/dev/null
ls -l /proc/*/fd 2>/dev/null | head -200

# 3. Network state
ss -tunap
ss -plant
ip -br addr; ip -s link; ip route; ip neigh
cat /etc/resolv.conf
resolvectl statistics 2>/dev/null
sudo nft list ruleset 2>/dev/null; sudo iptables-save 2>/dev/null

# 4. Kernel and modules
lsmod; cat /proc/modules
dmesg | tail -200
cat /proc/version

# 5. Mounts and storage
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,SERIAL,MODEL
cat /proc/mounts; df -hT

# 6. Persistence locations
crontab -l; ls -la /etc/cron.* ; cat /etc/crontab
systemctl list-timers --all
ls -la /etc/systemd/system/ /usr/lib/systemd/system/
ls -la ~/.ssh/ /root/.ssh/ ; cat /etc/sudoers.d/* 2>/dev/null

# 7. Accounts
cat /etc/passwd
getent passwd | awk -F: '$3 >= 1000 && $3 < 65534'
cat /etc/group

# 8. Recent log state (copy, do not read in place)
sudo cp -a /var/log /mnt/evidence/varlog-copy
sudo journalctl --output=export --since "-24h" > /mnt/evidence/journal-24h.xml
```

Sensitive by construction: `/etc/shadow`, process environments, SSH agent
sockets, `/proc/*/environ`, browser credential stores. Collect them to a file
if you need them, never to the transcript, and never into a report body.

```bash
# Environment variables of every process (sensitive: may contain tokens)
sudo sh -c 'for p in /proc/[0-9]*; do echo "== $p"; tr "\0" "\n" < "$p/environ" 2>/dev/null; done' \
	> /mnt/evidence/proc-environ.txt
```

---

## 3. Memory acquisition

Memory is the most volatile evidence and the only place some artifacts exist:
injected code, decrypted content, network state of a process, and the true
arguments of a masquerading process. Capture it first.

```bash
# AVML (Kali package: avml) — writes a LiME-compatible image
sudo avml --save=/mnt/evidence/mem.lime --compress --out=/mnt/evidence/

# LiME (kernel module, build for the running kernel) — load, then check dmesg
sudo insmod lime.ko "path=/mnt/evidence/mem.lime format=lime"
dmesg | tail -5

# Verify the image is plausible: size close to RAM, and a known string present
ls -lh /mnt/evidence/mem.lime
strings -n 8 /mnt/evidence/mem.lime | head -20
```

Notes:

- `sudo dd if=/proc/kcore` is **not** a substitute. On a modern kernel it is
  restricted to the 128 TiB virtual range and produces a useless file.
- If the suspect host is not Linux, or the kernel module will not load, boot
  a memory-acquisition environment (LiME ISO, Ubuntu "Acquire Memory", or
  AVML from a USB stick) and take the dump from there.
- Compressing changes the file, so hash the final file that is stored. Record
  the method and version.
- If the host must keep running, note that the memory image is a snapshot and
  a second image taken later may be needed to see short-lived processes.

---

## 4. Disk acquisition

```bash
# Identify the volume and record its identity
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,SERIAL,MODEL,ROTA
sudo blkid
sudo fdisk -l /dev/sda

# Clean image of a powered-off disk
sudo dc3dd if=/dev/sda of=/mnt/evidence/disk_sda.img bs=4M status=progress

# Live image (system stays up): noerror/sync tolerates I/O errors
sudo dc3dd if=/dev/sda of=/mnt/evidence/disk_sda.img bs=4M conv=noerror,sync hash=sha256

# Damaged or dying media: ddrescue, log the map for the second pass
sudo ddrescue -f -n /dev/sda /mnt/evidence/disk_sda.img /mnt/evidence/disk_sda.map
sudo ddrescue -d /dev/sda /mnt/evidence/disk_sda.img /mnt/evidence/disk_sda.map

# Hash and record
sha256sum /mnt/evidence/disk_sda.img
```

Guidelines:

- Image the whole device, not just the partition, unless size forbids it — the
  partition table and the gaps between partitions carry deleted data.
- Write to a different physical disk than the one you read. Filling the
  source device with the image destroys the evidence.
- Use `conv=noerror,sync` on a live acquisition so a read error does not abort
  the copy.
- Record the tool name and version, the block size, the flags, the device,
  the operator and the start and end times.

Read-only analysis of the image:

```bash
# Partition layout
sudo mmls /mnt/evidence/disk_sda.img

# Mount read-only, noatime so the image is not written by the mount itself
sudo mkdir -p /mnt/analysis
sudo mount -o ro,noload,noatime,loop /mnt/evidence/disk_sda.img /mnt/analysis
# or mount the partition directly with the byte offset from mmls
sudo mount -o ro,noatime,loop,offset=32256 /mnt/evidence/disk_sda.img /mnt/analysis

# Sleuthkit works on the image without mounting it
sudo fls -r -o 32256 /mnt/evidence/disk_sda.img > /mnt/analysis/fls.txt
sudo istat -o 32256 /mnt/evidence/disk_sda.img 12345
sudo icat -o 32256 /mnt/evidence/disk_sda.img 12345 > recovered.txt
```

Always work on a copy of the image, or at minimum re-verify the hash after
analysis. Any write to the image invalidates the hash you published.

---

## 5. Log and timeline analysis

### Where the Linux evidence lives

| Source | Path | What it shows |
|---|---|---|
| Authentication | `/var/log/auth.log`, `/var/log/secure` | SSH and sudo events, key and password logins. |
| System | `/var/log/syslog`, `/var/log/messages` | Service lifecycle, cron runs, kernel messages. |
| journald | `/var/log/journal/*/system.journal` | Structured, timestamped system log. |
| Login history | `/var/log/wtmp`, `/var/log/btmp`, `/var/log/lastlog` | Successful and failed logins, current sessions. |
| Cron | `/var/log/cron`, `/etc/crontab`, `/etc/cron.*` | Scheduled execution. |
| Audit | `/var/log/audit/audit.log` | `ausearch` events: user, exec, file and permission changes. |
| Web server | `/var/log/nginx`, `/var/log/apache2` | Requests, status codes, user agents. |
| Shell history | `~/.bash_history`, `~/.zsh_history` | Interactive commands. Note: not written until the shell exits. |
| Timestamps | file mtime / ctime / atime | On the image, with `stat`. |

```bash
# Authentication sweep
sudo grep -hE "Accepted|Failed password|Invalid user|session opened|useradd|usermod" /var/log/auth.log* \
	> /mnt/analysis/auth-events.txt
sudo journalctl -u sshd --since "2025-03-01 00:00" --until "2025-03-02 00:00" --no-pager
sudo journalctl _UID=0 --since "-7d" --no-pager | less   # root activity
sudo ausearch -m USER_LOGIN,USER_AUTH,USER_CMD,EXECVE -ts recent -i

# Logins
last -Faiw | head -50
sudo lastb -Faiw | head -50        # failed logins

# Service and privilege changes
sudo journalctl -u sudo --since "-7d" --no-pager
sudo grep -hE "systemd\[1\]: Started|systemd\[1\]: Starting" /var/log/syslog | tail -100

# File timeline (mtime) and ctime sweep on the mounted image
sudo find /mnt/analysis -xdev -newermt "2025-03-01 00:00" -printf '%T@ %TY-%Tm-%Td %TH:%TM:%TS %p\n' \
	2>/dev/null | sort -n > /mnt/analysis/mtime-timeline.txt
sudo find /mnt/analysis -xdev -cnewermt "2025-03-01 00:00" -printf '%C@ %CY-%Cm-%Cd %CH:%CM:%CS %p\n' \
	2>/dev/null | sort -n > /mnt/analysis/ctime-timeline.txt

# Files modified after they were created (tamper signal)
sudo find /mnt/analysis -xdev -type f -printf '%C@ %T@ %p\n' | awk '$1 < $2' | head -50
```

Cross-reference the timeline with `cyber_journal`: every entry there is
CyberPi's own footprint. Exclude it from the adversary timeline and disclose
it separately — see the "Our activity" section of the report.

### Windows artifacts (when a Windows host is in scope)

| Artifact | Path | Notes |
|---|---|---|
| Security log | `%SystemRoot%\System32\winevt\Logs\Security.evtx` | Logon, privilege, account and audit events. |
| Sysmon | `Microsoft\Windows\Sysmon\Operational.evtx` | Process, network, registry and image-load telemetry. |
| PowerShell | `Microsoft\Windows\PowerShell\Operational.evtx` | Script blocks (4104), module logging (4103). |
| NTFS | `$MFT`, `$UsnJrnl:$J`, `$LogFile` | File creation and rename history, even after deletion. |
| Prefetch, Amcache, Shimcache | `C:\Windows\Prefetch`, `Amcache.hve`, `SYSTEM` | Program execution history. |
| SAM / SYSTEM / SECURITY | registry hives | Accounts, services, cached secrets. |
| Prefetch + UserAssist | `NTUSER.DAT` | Programs run in the user context. |

Event IDs worth a filter:

| ID | Meaning |
|---|---|
| 4624 / 4625 | Successful / failed logon. |
| 4672 | Special privileges assigned (admin logon). |
| 4688 | Process created (with command line if auditing is on). |
| 4697 / 7045 | Service installed. |
| 4720 | User account created. |
| 4732 / 4728 | Added to a privileged group. |
| 1102 / 104 | Security log or event log cleared. |
| Sysmon 1 / 3 / 7 / 11 / 13 | Process create, network connect, image load, file create, registry set. |
| Sysmon 22 | DNS query. |

Tools: `chainsaw` (Sigma-style hunts over EVTX), `log2timeline.py` /
Plaso for super-timelines, `pstecat` for the PST, `reged`/`Ripgrep` for
hives, `Sleuthkit` for NTFS.

---

## 6. Packet capture analysis

`cyber_capture` produces the capture file and a summary of it. The summary
belongs in the report; the frames belong in the timeline. Hash the capture
file as soon as the tool returns — the path it prints is the artifact to
record in the manifest.

```bash
# Conversation summary (who talked to whom, how much)
tshark -r capture.pcap -q -z conv,tcp -z conv,udp

# DNS: resolutions and C2-looking names
tshark -r capture.pcap -Y "dns.flags.response == 0" \
	-T fields -e frame.time_epoch -e ip.src -e dns.qry.name

# HTTP requests: host, URI, method
tshark -r capture.pcap -Y "http.request" \
	-T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri

# TLS SNI: the plaintext host names in an encrypted session
tshark -r capture.pcap -Y "tls.handshake.extensions_server_name" \
	-T fields -e frame.time_epoch -e ip.dst -e tls.handshake.extensions_server_name

# New connections (SYN without ACK): the session starts
tshark -r capture.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
	-T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport

# Scans and sweeps
tshark -r capture.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
	-T fields -e ip.src | sort | uniq -c | sort -rn | head

# Suspected exfiltration: a long conversation with a lot of payload
tshark -r capture.pcap -q -z conv,tcp | awk '$0 ~ /10\.0\.0\.5/'

# Extract transferred objects
tshark -r capture.pcap --export-objects http,./extracted_http
tcpflow -r capture.pcap -o ./extracted_tcp
```

For a timeline, convert epoch to UTC (`date -u -d @1730000000`) and keep the
frame number in the reference so a reviewer can find the same frame.

Careful with what a capture can hold: a pcap of a cleartext protocol contains
credentials and session cookies. It stays an artifact. Quote the packet
reference in the report, never the payload contents.

---

## 7. Memory analysis

Volatility 3, against the memory image:

```bash
# Windows
python3 vol.py -f mem.lime windows.info
python3 vol.py -f mem.lime windows.pstree                 # process tree with start times
python3 vol.py -f mem.lime windows.cmdline                # full command lines
python3 vol.py -f mem.lime windows.netscan                # sockets and owning PID
python3 vol.py -f mem.lime windows.getsids                # token privileges
python3 vol.py -f mem.lime windows.malfind                # injected regions
python3 vol.py -f mem.lime windows.filescan | grep -i suspect
python3 vol.py -f mem.lime windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
python3 vol.py -f mem.lime windows.registry.printkey --key "System\CurrentControlSet\Services"
python3 vol.py -f mem.lime windows.dumpfiles --pid 1234

# Linux
python3 vol.py -f mem.lime linux.pslist
python3 vol.py -f mem.lime linux.pstree
python3 vol.py -f mem.lime linux.bash                     # command history from memory
python3 vol.py -f mem.lime linux.check_modules             # hidden kernel modules
python3 vol.py -f mem.lime linux.lsof
python3 vol.py -f mem.lime linux.ifconfig
python3 vol.py -f mem.lime linux.proc.Maps
python3 vol.py -f mem.lime linux.keyring
```

Map each plugin to the IR question it answers: `netscan` → "what was it
talking to", `malfind` → "was something injected", `check_modules` → "is the
kernel subverted", `cmdline` → "what was it really running".

---

## 8. Artifact triage checklist

For each row, record what you looked for, where, and what you found. A
documented negative is a result.

| IR question | Where to look | Tools |
|---|---|---|
| Initial access | Web and auth logs, mail gateways, exposed services, VPN logs | `grep`, `journalctl`, `chainsaw` |
| Execution | Process creation events, Prefetch, `bash_history`, memory `pstree` | Volatility, `ps` snapshots, Sysmon 1 |
| Persistence | `~/.ssh/authorized_keys`, cron, systemd units, `.bashrc`, registry Run keys, `authorized_keys` in every home | `find`, `ls`, `reged` |
| Credential access | `/etc/shadow` copies, `~/.ssh/id_*`, `~/.aws/credentials`, browser stores, SAM/SYSTEM hives, `~/.bash_history` | `find`, `ls`, `chainsaw` |
| Discovery | `enum*` tools in history, `arp -a`, `ip route`, DNS logs | `history`, capture analysis |
| Lateral movement | `smb.log`, SSH accepted events, Kerberos 4768/4769/4624 | `journalctl`, EVTX |
| Collection | Staging directories, archives, `tar`/`zip` in history, large outbound transfers | `find -size`, capture byte counts |
| Exfiltration | Long outbound sessions, DNS tunnelling, unusual SNI, uploads to new hosts | `tshark -z conv,tcp` |
| Impact | Encrypted files, ransom notes, deleted shadow copies, `vssadmin list shadows` | `find -newermt`, `strings` |

Tamper signals worth checking explicitly:

```bash
# Files whose change time predates their modification time
sudo find /mnt/analysis -xdev -type f -printf '%C@ %T@ %p\n' | awk '$1 < $2'

# Timestamps rounded to the hour — common in copied files
sudo find /mnt/analysis -xdev -type f -printf '%T@ %p\n' | awk 'int($1) % 3600 == 0' | head -50

# Recently changed configuration and startup locations
sudo find /mnt/analysis/etc /mnt/analysis/usr/lib/systemd /mnt/analysis/var/spool/cron \
	-type f -newermt "2025-03-01 00:00" -ls 2>/dev/null

# SUID/SGID binaries, a classic privilege escalation and persistence route
sudo find /mnt/analysis -xdev -perm /6000 -type f -ls 2>/dev/null

# Deleted-but-open files (held by a running process)
sudo lsof +L1 2>/dev/null | head -50

# Shadow copies and backups, relevant to ransomware impact
sudo vssadmin list shadows 2>/dev/null
```

Carving and scanning:

```bash
sudo foremost -t all -i disk_sda.img -o carved/          # file carving
sudo binwalk disk_sda.img                                # embedded files
yara -r -w /mnt/analysis suspicious.yar                  # rule-based scan
sudo bulk_extractor -o bulk/ disk_sda.img                # strings and carved data
strings -a -n 8 disk_sda.img | grep -iE "BEGIN .*PRIVATE KEY" | head
```

---

## 9. Incident report structure

`cyber_report` renders the findings and the journal. The narrative parts —
summary, timeline, evidence inventory, custody, containment — come from your
case notes, and they are what a reader actually uses. Assemble them in this
order:

1. **Incident summary** — what happened, when, to what, and the current
   status. One paragraph and a short bullet list. Written for a manager who
   was not there.
2. **Scope and authorization** — the engagement, the client, the
   authorization reference, the systems covered, and the systems explicitly
   excluded. State that the assessment was performed under written
   authorization.
3. **Timeline** — a UTC table: time, source artifact and line or frame
   reference, event, host. Split into "adversary activity" and "our activity".
4. **Evidence inventory and chain of custody** — the manifest table, the
   transfer log, and the hash verification result.
5. **Findings** — root cause, impact, evidence references, and the specific
   remediation. Order by severity, then by certainty.
6. **Containment** — what was done, when, by whom, with the effect. If nothing
   was done, say so plainly and say why.
7. **Eradication and remediation** — priorities, owners, and the evidence
   needed to verify each fix.
8. **Limitations** — what could not be collected, what was not covered, and
   which conclusions are consequently uncertain. This section is what makes
   the rest of the report credible.
9. **Appendices** — commands run, tool versions, hashes, log extracts, and
   references to the artifact files.

### Pre-delivery checklist

- [ ] Every claim points at an artifact, a log line, a frame number or a
      hash.
- [ ] Every artifact in the report exists in the manifest, and every hash in
      the manifest verifies.
- [ ] No raw credentials, cookies, tokens or personal data in the report body.
- [ ] Timestamps are UTC, with the source timezone stated once.
- [ ] The timeline excludes the assessor's own activity, which is disclosed
      separately.
- [ ] The scope and authorization section matches `.cyberpi/scope.json`.
- [ ] Findings that were not confirmed are labelled as assessments, not
      conclusions.
- [ ] The limitations section is honest about gaps.
- [ ] The report renders from `cyber_report` and the file is in
      `.cyberpi/reports/`.

---

## 10. Toolchain

Kali packages for this workflow:

```bash
sudo apt install -y sleuthkit volatility3 tshark tcpdump foremost yara \
	dc3dd gddrescue bulk-extractor
sudo apt install -y avml          # memory acquisition
sudo apt install -y zeek          # optional, better protocol analysis than tshark
```

`chainsaw` (Sigma hunts over EVTX) and `plaso` / `log2timeline` are available
as separate installs if Windows or super-timeline work is in scope.

Missing binaries are reported by CyberPi before a tool runs. For local
collection commands there is no such check: verify the tool exists
(`command -v vol.py`) before you rely on its output, and note the version in
the manifest.

---

## 11. Common mistakes

| Mistake | Consequence |
|---|---|
| Rebooting a suspected-compromised host to "clear it" | Memory, process arguments and network state are gone for good. |
| Copying logs to a USB stick without hashing them | The copy cannot be shown to be what the host produced. |
| Working on the live filesystem instead of the image | Every read alters atime; the evidence is contaminated. |
| Hashing after the analysis | Proves nothing about the state at acquisition. |
| Editing a manifest row | Destroys the credibility of the whole chain. |
| Reporting the scanner's own traffic as attacker activity | The report contradicts itself. |
| Pasting a credential into the chat to prove a finding | The secret is now in the transcript, the session log and possibly the model's context. |
| Concluding "no compromise" from a partial collection | Say what you searched and what you did not have. |
