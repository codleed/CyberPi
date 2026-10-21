---
name: iot-and-hardware
description: Assess embedded devices, IoT and OT hardware, and physical attack surfaces in an authorized engagement. Use when identifying a device from its network behaviour, checking published default credentials, extracting and analysing firmware images, accessing a serial or debug console, preparing a USB HID / BadUSB payload, or assessing RFID and NFC cards and readers. Also use when a target device cannot be rebooted and the work must stay read-only.
---

# IoT and hardware assessment

A device on the network is a computer with a smaller attack surface, a longer
support life and a much worse failure mode. The value of this skill is
narrowing an unknown box down to a specific model, a specific firmware
version and a specific weakness — and then stopping before the point where
the assessment breaks the device.

Two rules govern everything below:

1. **Read-only by default.** Identify, authenticate, dump, analyse. Writing to
   a device is a separate, explicitly approved action.
2. **Never print credential material.** Summarise the outcome and point at the
   artifact file. A default password is evidence, not something to paste into
   the transcript.

Read `references/hardware-triage.md` before the first device: it holds the
identification signals, the vendor port and default-credential tables, the
firmware extraction walkthrough, the UART and JTAG procedures, the HID and
RFID notes, and the full list of actions that are forbidden on a device that
cannot be rebooted.

## Tools

| Tool | Use it for | Returns |
|---|---|---|
| `cyber_iot_scan` | Identify a device and its management surface on the network: vendor ports, service banners, CPE and version strings. | Per-host service records with port, protocol, service, version and product info. |
| `cyber_firmware_analysis` | Extract and analyse a firmware image the operator supplied: embedded file systems, bootloaders, configuration, secrets and version strings. | Extraction results: file systems found at which offsets, embedded files, and the interesting strings. |
| `cyber_hid_attack` | Inspect a USB HID report descriptor and prepare a HID / BadUSB keystroke payload. | Rendered HID report descriptor (usage pages, report ids, lengths) and the encoded payload. |
| `cyber_service_scan` | Deeper service enumeration when `cyber_iot_scan` identifies the device but not the version. | Full nmap service data with scripts. |
| `cyber_http_probe` | Fingerprint a device's web admin interface (title, technology, status). | URL, status, title, technology list. |
| `cyber_cve_lookup` / `cyber_cve_search` | Match the exact firmware version to known vulnerabilities. | CVSS, CWE, EPSS, KEV flag, affected version range. |
| `cyber_record_finding` | Store a confirmed issue against the device. | Finding id and file path. |
| `cyber_journal` | Check what has already been run against this device. | Action history. |
| `cyber_surface` | Read what is already known about the host, port and version. | The surface index. |

Tool parameter names are shown in the tool list; check the tool's schema before
calling it. Every network-touching tool is scope-checked against
`.cyberpi/scope.json` and journalled automatically. A refusal means the device
is not in the authorized scope — it does not mean the scan is broken, and it
is not something to work around.

## Device triage flow

### 1. Establish the target and its status

Get three facts before touching anything:

- **What the device is** — an IP, a hostname, or a physical unit on the bench.
- **Whether it is in scope** — the harness enforces this, but confirm the
  operator named this device, and note the rule in `.cyberpi/scope.json` that
  authorized it.
- **Whether it can be rebooted** — ask explicitly. "Is this device in
  production?" decides everything that follows. If the answer is unknown, treat
  the device as non-rebootable and stay read-only.

Record the physical identifiers (model, serial, label, MAC) in your notes
before you start, so the report can name the device rather than an address.

### 2. Identify the device from the network

Run `cyber_iot_scan` against the address. It is tuned for embedded targets:
the vendor port set, the service banners and the product/CPE fields are what
make the difference between "an old Linux box" and "a Hikvision camera".

Then build the identification from at least two independent signals — MAC OUI,
listening ports, banner, UPnP metadata, TLS certificate, DHCP hostname, CPE.
The signal table is in `references/hardware-triage.md`. A single banner is a
hypothesis, not an identification.

If the version stays unknown, deepen with `cyber_service_scan` (version
detection scripts) or `cyber_http_probe` (admin panel fingerprinting). Do not
guess a version from the model name.

### 3. Check the management surface

With the model confirmed, look at what the device exposes beyond the
management port:

- Telnet / SSH with a published default credential for that model
- A web admin interface with no authentication, or with a default account
- Vendor cloud or vendor management endpoints reachable
- An exposed firmware download, an exposed backup, or an exposed config file
- UPnP/TR-069 with a weak SOAP action, or a vendor RPC port

Try the published defaults for the identified model only — the table in
`references/hardware-triage.md`. Do not brute force. Report the outcome as
"default credential accepted for `<service>` on `<model>`" and let the artifact
hold the detail.

### 4. Analyse the firmware offline

When the operator supplies a firmware image (or a device that allows a
read-only dump), run `cyber_firmware_analysis`. It extracts the embedded file
systems and surfaces the interesting strings.

The analysis answers four questions:

- **What is it?** Model, board string, kernel version, build date.
- **What version is it?** The exact firmware string — this is what makes a CVE
  match provable rather than plausible.
- **What is in it?** Configuration, default accounts, keys, service start-up
  order, an unauthenticated update endpoint.
- **What can be matched?** Feed the product and version to
  `cyber_cve_search` and `cyber_cve_lookup` for CVSS, EPSS and KEV.

Never upload a client firmware image to an online analysis service. Hash the
image, keep the original untouched, work on a copy.

### 5. Assess the physical interfaces

Only the interfaces the operator asked for.

**Serial console (UART).** Identify the header, measure the voltage before
connecting, cross TX/RX, share ground, and use a 3.3 V TTL adapter. Watch the
boot log at 115200 8N1 first; the bootloader prompt is often reachable with a
single interrupt key. *Observing* the console is read-only. *Typing* into a
bootloader is not — see the checkpoint below.

**JTAG / SWD.** Read-only core dumps are possible but attaching a debugger to
a locked device can trigger a mass erase. Ask before attaching anything. Never
attach to a device that cannot be rebooted without written approval.

**USB HID.** Use `cyber_hid_attack` to read the report descriptor and establish
the usage page, the report id, the report length and the boot-keyboard
support, then encode a minimal, benign payload. Prove the payload locally on
a sacrificial test machine before it goes near anything in scope. Never test a
payload on the machine holding the engagement evidence.

**RFID / NFC.** Identify the card, dump it read-only, and assess what the
data means. Cloning a real access card needs explicit written authorization
for the access-control system and a sacrificial duplicate; prefer a test card
the operator provides.

**OT / ICS devices.** When the target is an operational-technology asset,
change the method rather than the tool: read the traffic with `cyber_capture`
and identify the protocol from the packets, do not scan the process segment,
never write to a process register, and treat an availability issue on a
controller as the primary finding. The specific protocols and the boundaries
are in `references/hardware-triage.md`.

### 6. Correlate and report

Turn what you proved into findings:

- One device, one identity. Anchor the finding to the model, the serial and
  the firmware version, not to an IP address.
- A CVE needs the exact affected version range matched, not a plausible
  product. `cyber_cve_search` gives you the range; use it.
- A default credential is **high** on an internet-reachable management
  interface, **medium** on a LAN-only device.
- Store the evidence as an artifact and reference the path. Redact anything
  that would leak a credential, a cookie or a token.
- Record each confirmed issue with `cyber_record_finding`.

## Destructive-action checkpoint

Some hardware actions cannot be undone and can end the device's life. Before
any of them, **stop and get an explicit yes from the operator, naming the
device**. "The client wants the result" is not a yes; the operator confirming
the specific device and the specific action is.

| Action | Why it needs approval | Safer alternative |
|---|---|---|
| Writing, flashing or upgrading firmware | A bad image bricks the device; on a locked bootloader it is unrecoverable | Read the image out and analyse it offline |
| Mass erase via JTAG/SWD, `mtd erase`, "reset to factory" | Erases flash and the device may have no recovery path | Offline analysis of an image the operator supplies |
| Writing to flash, NVRAM or the config partition | Corrupts stored credentials and network config; may disconnect it permanently | Read the partition, report its contents |
| `reboot`, `restart`, `shutdown`, power-cycle through any channel | Loses the device's live role; a camera or gateway may not come back | Observe the current state; report the exposure |
| `AT+CFUN=1`, `AT&F`, or any command that resets a modem | Drops the link; on a cellular device that is the alarm path | Read the configuration, do not reset it |
| A HID payload that reboots, uploads firmware or writes to flash | Executes on whatever is focused, on a machine you do not control | A benign keystroke sequence that proves injection |
| RF interference: jammer, deauth flood, EAPOL flood | Takes down the site | Passive capture; a scoped association test |
| Writing to a live RFID card | Destroys a credential the building uses | Read-only dump of a test card |
| Writing a coil, register or setpoint (Modbus, DNP3, OPC UA, S7, EtherNet/IP) | Actuates equipment in a live process | Passive capture; identify the role from the traffic |
| Unplugging power or removing a jumper | Same as a power cycle | Never, without the explicit instruction |
| Sending commands to a production OT/ICS device | A bad write can actuate equipment | Passive observation; client-controlled test window |

Rules that follow from the table:

- **A device that cannot be rebooted is read-only.** No flash writes, no
  resets, no power commands, no interfering with its radio, no payload that
  changes device state. Passive observation, protocol analysis, documentation
  review, and offline work on images the operator supplies are the whole
  permitted scope.
- **A successful authentication is not authorization to change anything.**
  Logging in proves the weakness; it does not authorize an upgrade.
- **One approved action at a time.** Do the approved step, report the result,
  and wait for the next approval. Bundling "and then I reflashed it" into one
  approval is how devices get bricked.
- **State the risk before asking.** Say what the action does, what breaks if
  it goes wrong, and what the alternative is. "I can reflash the camera to
  test the update path — it will not come back if the image is wrong, and
  there is no OTA recovery. Do you want me to proceed?" is a checkpoint.
  "Can I proceed?" is not.

## Working rules

- **Stay inside the scope.** The harness refuses out-of-scope targets. A
  refusal is a routing message to the operator, not an obstacle to route
  around.
- **Never print credentials, cookies, tokens or card data.** Summarise and
  point at the artifact.
- **Identify before you exploit.** A model number and a firmware version are
  the prerequisite for every downstream claim; get them from the device, not
  from memory.
- **One claim, one proof.** A finding is a statement about a named device
  with a reproducible step and an artifact behind it.
- **No invented identifiers.** No CVE, CVSS vector, firmware version or model
  from recollection. If the database has no record, say the record is absent.
- **Keep the transcript small.** Summaries in the tool output, detail in the
  artifacts, findings in `.cyberpi/findings/`, and the device notes in
  `.cyberpi/notes/`.
