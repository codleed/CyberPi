# Hardware triage reference

Deep reference for the `iot-and-hardware` skill. Read it when a device needs
to be identified, its firmware dissected, its console accessed, or a USB HID /
RFID assessment has to be prepared.

Everything in this document assumes a written authorization (`.cyberpi/scope.json`)
and a named operator who can approve destructive actions. When in doubt, stop at
the checkpoint in `SKILL.md` and ask.

---

## 1. Identifying a device

A device rarely announces itself. Build the identification from independent
signals and only trust a vendor name when at least two signals agree.

| Signal | Where it comes from | Notes |
|---|---|---|
| MAC OUI | `cyber_iot_scan` service output, `ip link` | First three octets map to the vendor. `nmap --script=upnp-info` often names the model. |
| Listening ports | scan result | See the vendor port table below. |
| Service banners | scan result | `Server: nginx/1.12.1`, `GoAhead-Webs`, `lighttpd`, `uhttpd`, `mini_httpd` are vendor tells. |
| mDNS / SSDP / NetBIOS | passive capture or directed probe | SSDP `SERVER` and `ST` headers carry the model more often than the banner does. |
| UPnP metadata | `cyber_iot_scan` | `Location: http://host:5000/rootDesc.xml` — the XML names the manufacturer and model. |
| HTTP title and login page | `cyber_http_probe` | Router and camera admin pages are trivially fingerprinted. |
| TLS certificate | handshake | Self-signed certificates carry the internal hostname of the device. |
| CPE in the scan output | nmap service detection | `cpe:/h:vendor:model:firmware` — the most precise identifier you will get. |
| DHCP hostname / DNS label | network traffic | `huawei-ct-*`, `TP-LINK_*`, `Zyxel_*` are strong hints. |
| Hardware string in the device | firmware analysis | `/etc/board.json`, `deviceinfo`, `ubus` board string. |

Vendor port table (the ports that most often mean "consumer IoT"):

- 21, 22, 23, 80, 443, 8080, 8443 — generic
- 37215, 52869 — Huawei HG router RCE
- 5555, 7547 — TR-069 / TR-064 (ISP CPE)
- 81, 8081, 8443 — Dahua / Hikvision camera admin
- 8000, 8899, 34567 — various DVRs and IP cameras
- 37777, 5555 — Dahua / DVR backends
- 49152 — Netis backdoor
- 5431 — Sun Oracle JSSE, not IoT, but a common false positive
- 20000, 53413 — D-Link NAS / UPnP
- 9034, 2222 — Tp-Link / weak SSH services

A device is worth deeper work when it exposes a management service, an
unencrypted protocol, a vendor cloud, or a physical interface (UART, JTAG,
USB, RFID) that the client asked to be assessed.

---

## 2. Default credentials

Default credentials are the highest-yield check on a device and the easiest
thing to get wrong in the report. Two rules:

1. **Never print a credential into the transcript.** The tool summary must
   state that a default was accepted and point at the artifact file that holds
   the detail. The artifact is the evidence; the transcript is the summary.
2. **Only try credentials the operator has named, or the well-known published
   defaults for the identified vendor/model.** Brute forcing beyond that needs
   an explicit instruction and a rate limit.

Published defaults worth trying once the model is known:

| Vendor / class | Typical pairs |
|---|---|
| Generic routers and cameras | `admin` / `admin`, `admin` / `password`, `root` / `root`, `user` / `user` |
| Ubiquiti | `ubnt` / `ubnt` |
| TP-Link | `admin` / `admin` (older), `admin` / (blank) |
| Zyxel | `admin` / `1234` |
| Hikvision | `root` / (blank or `hikvision`), `admin` / `admin` |
| Dahua | `root` / (blank) |
| MikroTik | `admin` / (blank) |
| Realtek-based CPE | `admin` / `admin` (often on `8080`) |
| ZTE / Huawei ONT | `admin` / `admin`, `telecomadmin` / `nE7jA%5m` (ISP, usually not in scope) |

Record the outcome as: model, service, method (password / SSH key / web
console), whether the default worked, and the artifact path. Never the value
itself.

A default credential is a **high** severity finding on a management interface
of an Internet-reachable device, and **medium** on a LAN-only device that is
otherwise patched.

---

## 3. Firmware extraction and analysis

`cyber_firmware_analysis` runs `binwalk` against a firmware image the operator
has provided (or that was pulled from a device, which is itself a checkpoint
item). Do the analysis offline — never upload a client firmware image to a
public service.

### 3.1 Extraction walkthrough

1. **Identify the container.** `binwalk` prints the offset and the type. Typical
   layouts:
   - `0x0000` SquashFS or UBI image, then an appended rootfs
   - `0x0000` uImage header (`Linux kernel Image`) followed by a SquashFS
   - `0x0000` JFFS2 (NAND) or UBIFS (NAND) — no container, mount it instead
   - `0x0000` ZIP/CPIO for `.deb`-style or `cpio` archives
   - Encrypted blob (`Encrypted, unknown, 0x...`) — the device uses a signed
     or encrypted update, and the real image is not extractable
2. **Extract** with `binwalk -e` into a working directory. Use a copy; keep
   the original image hash (`sha256sum`) for the report.
3. **Unpack the rootfs** depending on the type:
   - SquashFS: `unsquashfs -d rootfs image.squashfs`
   - UBIFS: `ubireader_extract_images -o out image.ubifs`
   - JFFS2: `jefferson -d out image.jffs2` or `jffs2dump`
   - CRAMFS: `cramfsswap` / `binwalk -e` handles it
   - Yaffs2: `yaffs2extract`
   - ext4: `debugfs` or loop mount
4. **Read the board identity.** Look for `/etc/board.json`, `/etc/os-release`,
   `/proc/cpuinfo` (model string), `uname -a` output baked into
   `/etc/version`, `/usr/bin/strings` on the web binary, and the `deviceinfo`
   or `nvram` tooling.
5. **Version and CVEs.** With the exact firmware version, query the local CVE
   database with `cyber_cve_lookup` and `cyber_cve_search` for the vendor
   product. Record the version string verbatim as evidence.

### 3.2 What to look for inside the rootfs

| Category | Where | Why it matters |
|---|---|---|
| Credentials | `/etc/passwd`, `/etc/shadow`, `/etc/shadow-`, `/etc/inittab`, `/etc/profile.d/`, `*.conf` | Default root accounts, hashed or plaintext |
| SSH keys | `/etc/dropbear/`, `/etc/ssh/`, `authorized_keys` | Pre-seeded device keys allow access without a password |
| Web admin | `/etc/nginx/`, `/usr/www/`, `/www/`, `*.cgi` | Default admin account, hardcoded API keys, debug endpoints |
| API/keys | `/etc/*.conf`, `/var/`, `/usr/lib/*.so` | Cloud keys, signing secrets, JWT secrets |
| Update logic | `/usr/bin/*update*`, `*/ota/*`, `rc.local` | Unauthenticated update endpoints, missing signature checks |
| Listening services | `/etc/init.d/`, `/etc/rc*.d/` | Telnet, `busybox` shells, adb enabled |
| SUID/SGID | `find . -perm -4000` | Local privilege escalation on the device |
| Debug flags | `strings` on the main binary | `--debug`, `DEBUG=1`, hardcoded IPs of the vendor lab |
| Vendor tooling | `deviceinfo`, `nvram`, `mtd` | Factory defaults, the secret to unlock a bootloader |

### 3.3 Firmware signing and safe update

If the device verifies update signatures, an unsigned update is usually
rejected. Read the verification code before attempting anything: a bypass is a
finding, and the write itself is a **destructive checkpoint** action.

---

## 4. Serial and debug console access

### 4.1 Serial (UART)

1. **Identify the header.** 4-pin (GND, TX, RX, VCC), 3-pin, or a dedicated
   console header. The silkscreen or the board file names the pins.
2. **Measure the voltage before connecting.** A 3.3 V TTL console on a 5 V
   UART line, or feeding 5 V into a 3.3 V pin, destroys the SoC. Use a
   multimeter on the TX idle line: ~3.3 V or ~5 V means TTL, a negative swing
   or a large amplitude around 0 V means RS-232.
3. **Wire TX to RX and RX to TX**, share ground. On TTL, cross over; on
   RS-232, cross over too but also respect the voltage levels.
4. **Use a TTL-USB adapter with a 3.3 V setting**, never a bare RS-232 port.
5. **Common baud rates**: 115200 8N1 (most), 9600 8N1 (older Realtek), 57600,
   38400, 230400. `stty -F /dev/ttyUSB0 115200 raw -echo` then watch with
   `cat /dev/ttyUSB0` or `picocom -b 115200 /dev/ttyUSB0`.
6. **Boot-time messages** reveal the bootloader, kernel, and often a root
   shell. Interrupt the boot with `Ctrl-A` (U-Boot), `Ctrl-C` (Linux), or
   `Esc`/`Ctrl-B` (Cisco-style) to reach a monitor prompt.

Read-only console observation is safe. Anything that writes to flash is not.

### 4.2 JTAG / SWD

JTAG and SWD give the strongest access and the highest risk:

- Attaching a debugger to a locked device can trigger a **mass erase** on
  connect. That is irreversible on devices with no recovery path.
- Read-only work (halt the core, dump flash to a file, analyze offline) is
  acceptable only when the operator has confirmed the device can survive it
  and has a backup.
- Never connect a debugger to a device that must not be rebooted without an
  explicit written approval.

### 4.3 Console expectations

| Symptom | Meaning |
|---|---|
| Nothing at all | Wrong baud, swapped TX/RX, wrong voltage, or the console is disabled in the bootloader |
| Garbage | Wrong baud rate or RS-232 vs TTL mismatch |
| U-Boot prompt | Bootloader shell — often offers `boot`, `run`, `printenv` |
| `BusyBox` shell as root | Full userspace on the device; expect `/etc/passwd` to be readable |
| Kernel panic on connect | The debugger halted the CPU and the watchdog reset the board — treat as a reboot event |

---

## 5. USB HID and BadUSB

### 5.1 The HID report descriptor

A USB HID device is described by a report descriptor: a bitfield structure
that the host parses to build the device's input reports. `cyber_hid_attack`
uses `hidrd` to render that descriptor in a readable form so the keyboard
layout, report length, and usage pages are known before anything is sent.

What to establish from the descriptor:

- **Usage page / usage** — keyboard (0x01/0x06), mouse (0x01/0x02), consumer
  control, vendor-defined, or a gamepad.
- **Report count and length** — the number of input reports and their byte
  size, e.g. 8 bytes for the boot keyboard.
- **Boot protocol support** — the `Boot Keyboard` usage (0x06/0x01) means the
  host will accept the compact 8-byte boot report, which is what most
  payloads assume.
- **Report ID** — some descriptors prefix every report with an ID byte;
  a payload without it produces garbage.
- **Modifiers bitmap** — which of the eight modifier bits (Ctrl, Shift, Alt,
  GUI) the device actually reports.

### 5.2 Preparing a payload

A BadUSB payload is a sequence of keystrokes (or HID reports) that a host
executes as if a human typed them. Preparation steps:

1. **Know the target layout.** The payload's keystrokes are interpreted with
   the *host's* active keyboard layout. A US-layout payload on a DE-layout
   host produces different characters. Confirm the layout, or use layout
   agnostic sequences (`Ctrl`, `Alt`, `F-keys`) wherever possible.
2. **Choose the delivery.** Rubber Ducky / Bash Bunny style devices replay a
   script; a `hidrd`/libusb program can send raw HID reports directly.
3. **Keep the payload minimal.** Delay, then the shortest sequence that proves
   the vector. A payload that opens a shell and types a command is enough to
   demonstrate; it does not need to download and run a second stage.
4. **Prove it locally first.** Encode the script, run it against a local
   virtual keyboard or a sacrificial test machine on the bench, and confirm
   the byte sequence produces the intended characters. Do not test the payload
   on the operator's own workstation or on anything that is not in scope.
5. **Do not include destructive commands in the demonstration payload.** The
   point is to show that arbitrary input is injectable.

### 5.3 Physical safety

- A USB device that emulates a keyboard can type into whatever is focused,
  including a BIOS password prompt. Keep the payload benign.
- Some devices re-enumerate (disconnect and reconnect) when the payload
  changes the report size. That is a USB-level reset, harmless to a host but
  it will interrupt the session.
- Do not connect a HID payload to a machine that holds the engagement evidence
  or the engagement's own scope file. Use a separate test machine.

---

## 6. RFID and NFC

### 6.1 Frequency classes

| Class | Frequency | Typical use | Tooling |
|---|---|---|---|
| LF RFID | 125 kHz | Access cards, door fobs, vehicle keys, animal tags | `proxmark3`, `libpm3`, `rfid` readers |
| HF NFC | 13.56 MHz | MIFARE Classic, Ultralight, DESFire, ISO 14443 | `proxmark3`, `nfc-tools` (`nfc-list`, `nfc-mfclassic`) |
| UHF RFID | 860–960 MHz | Vehicle tags, pallets, access systems | `rfid` readers, `proxmark3` in UHF mode is rare |

### 6.2 Assessment sequence

1. **Identify** the card with `hf search` / `nfc-list` — record the UID type
   (4/7/10 byte), the technology and the memory size.
2. **Authenticate and dump** read-only: `hf mf dump`, `hf ul dump`. Default
   keys for MIFARE Classic are public knowledge and are the first thing to
   try: `FFFFFFFF`, `A0A1A2A3A4A5A6A7`, `5041524548414B45`, `0000000000000000`.
3. **Assess** what the dump contains: card IDs that are door credentials,
   manufacturer data, and whether the data is signed or MAC-protected.
   DESFire with 3DES/AES does not yield a usable key from a simple dump.
4. **Do not write** to a card that belongs to the client's building unless the
   operator has explicitly authorized it and a sacrificial duplicate exists.
   Cloning a card that opens a door is a physical-access bypass; a written
   authorization for the access-control system is required.

### 6.3 Access control findings

- Cloned card = a duplicate that was never deactivated: **high**.
- Card UID that is static and predictable: **medium** (snapshot cloning).
- Vendor backend exposed on the network: escalate to the network findings.
- Reader firmware and default keys: usually a **medium** misconfiguration.

---

## 7. Devices that cannot be rebooted

Some devices in the scope are in production: a camera covering a loading bay,
a PLC in a live process, a gateway that cannot be restarted without a truck
roll. For those, the following are forbidden without written approval from
the operator naming the device:

- Flashing, reflowing, or upgrading firmware
- Mass erase via JTAG/SWD, `mtd erase`, or a vendor "reset to factory"
- Writing to the device's own flash, NVRAM, or config partition
- `reboot`, `restart`, `shutdown`, or a power-cycle of the target through any
  channel (admin page, UPnP, telnet, smart-plug relay)
- Sending commands that trigger a watchdog, a watchdog *kick* that is wrong,
  or an AT command that resets the modem (`AT+CFUN=1`, `AT&F`, `reboot`)
- Unplugging power or removing a jumper
- A USB HID payload that types a reboot, a firmware upload, or a `dd` onto
  the device's flash
- RF interference: a jammer, a flood of EAPOL frames, a deauth storm, or a
  proxmark write in an active RF zone

For those devices, restrict the work to:

- Passive and read-only network observation
- Non-invasive banners, protocol handshakes, and documentation review
- Offline analysis of firmware images the operator supplies
- Console *observation* without sending commands that change state

---

## 8. OT and ICS cautions

Operational technology shares the hardware profile of consumer IoT — embedded
Linux, vendor web consoles, default credentials, unpatched firmware — but the
consequence of a mistake is physical.

- **Never write to a process.** Modbus/TCP (port 502), DNP3 (20000), OPC UA
  (4840), Siemens S7 (102), EtherNet/IP (44818/2222), PROFINET and FINS all
  carry write operations. Reading coils and registers is passive; writing a
  coil is not.
- **Passive first.** Capture traffic with `cyber_capture` and identify the
  protocol, the device role and the process values from the traffic alone.
- **No scanning of the process segment.** Port scans, service enumeration and
  vulnerability scans can stall a controller or a legacy device with a
  single request. Work from the traffic and from the vendor documentation
  instead.
- **Patching a controller is an outage.** A firmware update on a PLC or a
  safety instrumented system needs a maintenance window and a rollback plan.
  That is an operator decision, never a tool decision.
- **Safety systems are out of bounds.** SIS, ESD and safety PLCs are not
  assessment targets. If one appears in scope, flag it to the operator and
  exclude it.
- **Availability is the finding.** In OT, an unauthenticated DoS against a
  controller is frequently more serious than a credential leak, because the
  device cannot be patched on demand.

## 9. Evidence and reporting

- Hash every acquired artefact (`sha256sum firmware.bin`) and record the
  acquisition method (download, sniff, dump, physical copy).
- Raw scanner output belongs in `.cyberpi/artifacts/`, not in the transcript.
- The transcript carries: the device identity, the model and firmware version,
  the ports and services, the class of the issue, and the artifact path.
- Credential results are reported as "default credential accepted for
  `<service>` on `<device>`" with the artifact path — never the credential.
- Record each confirmed issue with `cyber_record_finding` and set the target
  to the device (serial number or IP), not to the client machine.
