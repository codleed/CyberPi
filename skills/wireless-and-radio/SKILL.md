---
name: wireless-and-radio
description: Assess wireless and other radio networks during an authorized engagement. Use for WiFi/802.11 work - adapter and monitor-mode preparation, network survey, WPA/WPA2 handshake and PMKID capture, key recovery with cyber_wireless_scan and cyber_wireless_crack, deauthentication and evil-twin testing, rogue access point and KARGER-style client assessment, and for Bluetooth/BLE, NFC, RFID, Zigbee and other radio surfaces. Triggers on wifi, 802.11, WPA, WPA2, WPA3, monitor mode, airodump-ng, aircrack-ng, hcxtools, PMKID, handshake, deauth, evil twin, rogue AP, karver, karma, Bluetooth, BLE, NFC, RFID, Zigbee, Z-Wave, LoRa.
---

# Wireless and radio assessment

Radio assessment is where a written authorization matters most, because the
radio spectrum is shared. Every frame an adapter transmits is seen by
everyone in range, and a mistake reaches devices that are not the client's.

This skill is a workflow, not a licence. Work in this order:

1. **Authorize** - the engagement scope file names the networks and the
   "wireless" technique.
2. **Prepare** - one adapter in monitor mode, injection verified, channel
   locked.
3. **Survey** - passively enumerate the authorized networks.
4. **Capture** - collect the evidence the report needs.
5. **Recover** - try the captured material against the client's wordlists.
6. **Assess** - rogue APs, client-side risk, and the other radio protocols.

Step 5 and step 6 are where the findings come from. Everything before them
is preparation.

Read `references/wireless-recipes.md` before the first capture: it holds
the adapter and chipset tables, the command-level procedures for each
recipe, the rogue-AP detection method, the Bluetooth and NFC procedures,
the evidence-handling rules and the troubleshooting matrix.

## Tools

| Tool | Use it for | Returns |
|---|---|---|
| `cyber_wireless_scan` | Survey the authorized networks and record the capture: airodump-ng against the interface, filtered by BSSID, ESSID or channel. | The networks found (BSSID, ESSID, channel, cipher, power, stations) and the artifact path of the capture file. |
| `cyber_wireless_crack` | Recover a key from a capture or PMKID file: aircrack-ng against a wordlist. | Whether a key was recovered and where the result is stored - not the key itself. |
| `cyber_record_finding` | Store a confirmed wireless finding: recovered key, rogue AP, exposed BLE service, unprotected management frame. | Finding id and file path. |
| `cyber_journal` | Check what has already been run against this site, including the steps that were run by hand. | Action history. |
| `cyber_surface` | Read what is already known about the site's networks. | The surface index. |
| `cyber_report` | Render the deliverable once the findings are recorded. | The report path. |

Tool parameter names are shown in the tool list; check the tool's schema
before calling it. Every tool is scope-checked against
`.cyberpi/scope.json` and journalled automatically. A refusal means the
network or the technique is not in the authorized scope - it does not mean
the scan is broken, and it is not something to work around.

Frame transmission (`aireplay-ng`, `airbase-ng`, `hostapd`, `hcxpcapng`
probes, `hcitool scan`) is not wrapped by a CyberPi tool in this release.
Run those by hand, under the written authorization described below, and
record them in the engagement notes yourself.

## Scope comes first

CyberPi fails closed. Without `.cyberpi/scope.json`, every tool call is
refused. A wireless engagement needs three things in that file:

- The authorized networks. Scope rules match a target string, so each
  authorized ESSID is a rule target, for example
  `{ "target": "Acme-Corp", "notes": "HQ WLAN, contract 2025-03" }`. Add
  BSSIDs where the client named specific access points.
- The technique. If the file lists `techniques`, add `"wireless"` or the
  tools are refused with
  `technique "wireless" is not in the engagement technique allowlist`.
- A note on the physical scope. Write down the building, the floor, the
  time window and the radio channels the client approved. The scope file
  cannot express "only between 22:00 and 06:00", so it goes in `notes` and
  in the authorization statement.

If a scan is refused, do not work around the refusal. Tell the operator
which target or technique is missing and let them extend the scope file.

## Adapter preparation

Wireless work needs a second, dedicated adapter. The laptop's built-in
adapter is the client you will test, not the instrument.

```bash
# 1. What do we have?
iw dev
ls /sys/class/net
airmon-ng

# 2. Free the interface from the network stack
sudo systemctl stop NetworkManager
sudo nmcli radio wifi off
rfkill unblock wlan

# 3. Monitor mode
sudo airmon-ng start wlan0        # typically creates wlan0mon
iw dev wlan0mon info               # must report "type monitor"

# 4. Check what is fighting for the interface
sudo airmon-ng check

# 5. Verify injection works (this transmits one broadcast probe)
sudo aireplay-ng --test wlan0mon
```

Notes that matter:

- `airmon-ng check` names the processes that break monitor mode:
  NetworkManager, `wpa_supplicant`, `avahi-daemon`, and Bluetooth daemons.
  Stop them before the capture, not after it fails.
- A chipset that does not support injection (most Realtek RTL88xx dongles
  without a driver) cannot run deauthentication or an evil twin. The
  workhorse adapters are the Atheros AR9271 and AR9287 and Ralink RT3070
  class chipsets. `iw list` shows what the driver believes the card can do.
- The regulatory domain caps channel availability and transmit power. Set it
  to the client's country (`sudo iw reg set US`) or the 5 GHz and high-power
  channels silently disappear from `iw list`.
- Lock the channel explicitly with `sudo iw dev wlan0mon set channel 6`.
  A card that hops channels loses handshakes and half the survey.
- Keep one adapter for the client and one for the monitor. Two cards in
  monitor mode on the same channel still works, but the client-side
  assessment in `references/wireless-recipes.md` needs the split.

If `airmon-ng start` fails, the interface is usually held by NetworkManager
or a driver that lacks monitor support. `sudo airmon-ng check` and
`dmesg | tail -20` answer most cases.

## Survey the authorized networks

`cyber_wireless_scan` wraps `airodump-ng` and is the sanctioned way to
enumerate. It writes the capture and the parsed networks into the
engagement artifacts directory, and every run is journalled.

Use it for:

- **The survey**: which access points are visible, on which channels, with
  which cipher, at which signal strength.
- **The capture**: run it with the target BSSID and channel selected so it
  records a `.cap` for that network instead of a promiscuous sweep.

The tool's parameter names are in its own schema - read the schema rather
than guessing. What matters is the intent:

- Target the client's access point by BSSID, and by ESSID when the
  operator only knows the network name.
- Pin the channel. A handshake captured on the wrong channel is useless.
- Give the tool a short observation window (30-90 seconds) for a survey;
  longer for a capture.

Read the summary rather than the raw dump. For every network you get the
BSSID, ESSID, channel, cipher, power and station count. That is enough to
decide what to capture. The full output stays in the artifact file.

What to look for in the survey:

| Signal | What it means |
|---|---|
| `WPA2` with `WEP` fallback or `TKIP` cipher | Downgrade path worth documenting |
| Open (`OPN`) management frame | Management frame authentication is off |
| `WPS` enabled | Separate attack surface, check the lock flag |
| Hidden ESSID | Probe the BSSID directly; the SSID is not the security control |
| Same ESSID on several BSSIDs | Band steering, roaming, or a rogue |
| Very high power for the environment | Unusual transmitter, worth a look |
| No stations, weak signal | Likely not the client's network - do not touch it |

## Capture workflow

The order matters. Capturing first and asking questions later wastes the
engagement window.

1. **Confirm the target** - the BSSID and channel of the authorized
   network, from the survey.
2. **Lock the adapter** - `sudo iw dev wlan0mon set channel <ch>`.
3. **Start the capture** - either through `cyber_wireless_scan` with the
   target selected, or by hand:
   ```bash
   sudo mkdir -p /tmp/cyberpi-captures
   sudo airodump-ng -c 6 -b AA:BB:CC:DD:EE:FF \
       --output-format netxml \
       -w /tmp/cyberpi-captures/acme-hq wlan0mon
   ```
   `airodump-ng` writes `acme-hq-01.cap`, plus `.netxml`, `.csv` and a
   `.log`.
4. **Get the handshake** - a client must reassociate. Either wait for it
   (a client reassociating on its own, for example after a DHCP renewal),
   or ask the client to rejoin the network, or force it:
   ```bash
   sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon
   ```
   `-0 5` sends five deauthentication frames to the client. That is a
   transmission - see the safety rules below.
5. **Confirm the capture** - `airodump-ng` prints `WPA handshake captured`
   in its header when it has the four EAPOL messages. If it does not, the
   client did not reassociate, the channel is wrong, or the adapter is not
   in monitor mode.
6. **Copy the capture into the engagement** - captures contain everything
   on the air, including other people's traffic. Keep them in the
   engagement directory, or in a controlled `/tmp` that you clean up at the
   end. See the evidence handling section in the reference file.

PMKID is the quieter alternative: it needs no client, only the access
point, and it does not disturb anyone.

```bash
sudo hcxpcapng -i wlan0mon -o /tmp/cyberpi-captures/acme.pmkid.hcxpng
```

`hcxpcapng` sends authentication requests to every access point it hears,
so it is a transmission - but it disconnects nobody, and it is far quieter
than a deauthentication. If the client has not accepted probes to unknown
networks, extract the PMKID from a capture you already have instead, which
transmits nothing:

```bash
hcxpcapng -i /tmp/cyberpi-captures/acme-hq-01.cap -o /tmp/acme.pmkid.hcxpng
```

`hcxtools` is in the Kali repository.

## Key recovery

`cyber_wireless_crack` wraps `aircrack-ng` and takes the capture plus a
wordlist. The tool reports whether a key was found and where the result
lives; it does not need to print the key into the transcript, and neither
should you.

The wordlists that matter are the client's own:

```bash
# Typical Kali location
ls /usr/share/wordlists/rockyou.txt
zcat /usr/share/wordlists/rockyou.txt.gz > /tmp/rockyou.txt   # if still gzipped
```

Order of attack:

1. The client's own passwords - a reused corporate password is the most
   likely finding of the whole engagement.
2. `rockyou.txt` for consumer and SOHO gear.
3. A targeted list built from the organization's name, the AP model and
   the ESSID (`Acme-WAP`, `Acme123`, `acme2025`).
4. Rules-based mutations of the above.

Aircrack-ng reads the `.cap` and detects the format itself:

```bash
sudo aircrack-ng -w /tmp/rockyou.txt /tmp/cyberpi-captures/acme-hq-01.cap
```

Hashcat is faster on a GPU and understands the same material:

```bash
hcxpcapng -i /tmp/cyberpi-captures/acme-hq-01.cap -o /tmp/acme.hcxpng
hashcat -m 22000 /tmp/acme.hcxpng -w /tmp/rockyou.txt   # hashcat >= 6.2
hashcat -m 2500 /tmp/cyberpi-captures/acme-hq-01.cap -w /tmp/rockyou.txt
```

Mode 22000 is the current WPA-PBKDF2-PMKID+EAPOL mode in hashcat 6.2 and
later, and it reads the `.hcxpng` / `.pcapng` formats; mode 2500 is the
older `.cap` mode. Check `hashcat --help` for the modes the installed
build advertises rather than assuming.

Recovering a key is a finding, and it is a serious one:

- A recovered PSK means the network is open to anyone who knows or guesses
  one password. Severity depends on the data behind it, not on the crack.
- A recovered key on a network that uses WPA2-PSK with a shared key is
  normally **medium**, and **high** when the key also opens a management
  interface, a guest network, or another network on the same estate.
- Never paste the key into the transcript, the chat, or a ticket. It goes
  into the artifact file and the finding evidence as the artifact path.

## Active 802.11 testing

Deauthentication, evil twins and probe floods are the tools of a real
attacker, and they are the tools of an assessor. They are also the step
most likely to affect a third party, a neighbouring business, or a device
that the client did not know was in scope.

**CyberPi does not wrap frame transmission.** `cyber_wireless_scan` and
`cyber_wireless_crack` are the sanctioned tools. `aireplay-ng`,
`airbase-ng` and `hostapd` transmit, so run them by hand, and only when
the authorization names the BSSID and the window. Record them in the
journal by hand afterwards.

Safety rules, in order of importance:

1. **Written authorization must name the network.** Not "wireless was in
   scope" - name the ESSID, the BSSID and the physical location. If the
   client cannot name it, the client has not authorized an active attack
   on it.
2. **Never aim at a network you cannot identify.** An SSID you do not
   recognize is a neighbour. Skip it and note it in the report as
   observed-but-not-tested.
3. **Do not flood.** `-0 0` (continuous deauth) or a beacon flood takes a
   network down for as long as it runs and will be noticed by staff and by
   the ISP. Use the smallest number of frames that achieves the goal:
   `-0 5` instead of `-0 0`, one client at a time.
4. **Expect disruption and say so.** One deauthentication to one client
   is a WiFi dropout. The client should have been told. If they were not,
   stop and tell them now.
5. **Stay on the authorized channel and BSSID.** `-a` the target BSSID
   always. A deauth broadcast without `-a` hits every network in range.
6. **Do not attack devices.** A rogue client device (KARMA-style) is a
   client-side credential prompt, not a compromise. Assess whether clients
   *would* associate, and stop there.
7. **Keep the capture short.** A few minutes is enough to collect a
   handshake. An open capture on a busy channel records other people's
   traffic.

Deauthentication (authorized, targeted):

```bash
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon
```

Evil twin (authorized, hostapd). A soft access point with the client's
SSID, so clients reassociate to it and reveal their credentials over the
air. Only ever on the authorized network, and only with a written
instruction to do it.

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
EOF
sudo hostapd /tmp/hostapd.conf
```

`airbase-ng` (shipped with aircrack-ng) does the same thing in software;
check `airbase-ng --help` for the flag set of the installed version.

The finding for an evil twin test is about the *response*: whether clients
reassociate, whether the network sent a deauthentication to the twin, and
whether the client noticed. An enterprise network with 802.11w (protected
management frames) or 802.11r (fast roaming) resists the test - that
resistance is the finding.

`wifite` automates the survey-plus-deauth-plus-capture loop. It is a
convenience, not a control: it is exactly as dangerous as the flags it is
given. Use it only with the same authorization, and keep the same limits.

## Rogue AP and KARGER-style client assessment

A rogue access point is any AP that the organization does not know about,
or an AP that has been tampered with. The classic detection problem is not
finding the extra SSID - it is finding the AP that claims to be a legitimate
one but is not.

The KARGER approach turns the problem around: put a client on the network
and watch which radio actually serves the traffic. A legitimate AP beacons
one BSSID and serves frames from the same BSSID. A tampered or spoofing AP
beacons one BSSID and serves frames from another. That mismatch is the
finding.

Step by step:

1. **Survey** the site and record every BSSID, ESSID, channel, cipher and
   signal strength. Ask the client which of them are theirs.
2. **Select the monitoring adapter** and start a capture on the channel of
   the network under test.
3. **Associate the test client** to that network.
4. **Compare the beacon with the data frames:**
   ```bash
   # The BSSID the network advertises, and who sends the beacons
   sudo tshark -i wlan0mon -f "type mgt subtype beacon" \
       -Y 'wlan.bssid == "AA:BB:CC:DD:EE:FF"' \
       -T fields -e wlan.bssid -e wlan.sa -e wlan.ssid

   # Data frames that claim the BSSID but come from a different radio
   sudo tshark -i wlan0mon \
       -Y 'wlan.fc.type_subtype == 0x08 && wlan.bssid == "AA:BB:CC:DD:EE:FF" && wlan.sa != "AA:BB:CC:DD:EE:FF"' \
       -T fields -e wlan.sa -e wlan.bssid -e wlan.da
   ```
   `wlan.sa` is the transmitter address of the frame and `wlan.bssid` is
   the BSSID the frame is addressed to. The second command is the
   detector: it prints only the frames where a different radio is serving
   the network that the beacons advertise. An empty result is the clean
   result.
5. **Check the other mismatches**: an SSID that differs from the
   organization's naming convention by one character (a homoglyph or an
   added suffix), a channel that drifts, an AP that stops beaconing while
   still serving clients (the "carved" AP), a legitimate BSSID that
   disappears, and a duplicate BSSID with a different OUI.
6. **Re-check the client side.** Whether the client *would* associate with
   a spoofed SSID is a separate question from whether a rogue AP exists.
   Test that only in a lab, and only against the organization's own
   devices.

A KARGER-style client probe is not a compromise and must not be reported
as one. Report the assessment: which networks were checked, whether a
mismatch was found, and what the client-side association behaviour is.

## Bluetooth and other radio protocols

The same model applies to every radio: identify the protocol, get a
compatible receiver, capture passively, decode offline.

Bluetooth and BLE:

```bash
sudo systemctl start bluetooth
bluetoothctl power on
bluetoothctl --timeout 30 scan on
bluetoothctl devices
bluetoothctl info AA:BB:CC:DD:EE:FF     # services, name, pairing state
sudo hcitool scan                          # classic inquiry (transmits)
sudo btmon -w /tmp/cyberpi-captures/bt.btsnoop   # HCI capture
```

A short BLE scan with the Python stack that Kali ships:

```bash
python3 - <<'EOF'
import asyncio
from bleak import BleakScanner

async def main():
    for device, data in await BleakScanner.discover(timeout=10.0, return_adv=True):
        print(f"{device.address}  {device.name!r}  rssi={data.rssi}  {data.service_data} {data.manufacturer_data}")

asyncio.run(main())
EOF
```

What to assess:

- **Name and service exposure** - a device advertising RFCOMM SPP, OBEX,
  HID or a vendor service is a candidate for a connection attempt.
- **Pairing posture** - `btmgmt config` and `bluetoothctl info` show
  whether the device is bondable, whether secure simple pairing is
  required, and whether the transport enforces encryption. A discoverable,
  bondable device with no user confirmation is a real finding.
- **Version and firmware disclosure** - an information leak that helps
  version-pin the vulnerable Bluetooth stacks (BlueBorne and its
  descendants). Assess the *organization's own* devices and patch level;
  do not test a stranger's phone.
- **BLE advertising data** - manufacturer data, service UUIDs and
  beacon UUIDs can leak internal asset identifiers. That is a
  confidentiality finding, and the data belongs in the artifact, not in
  the transcript.

Other protocols, in the same shape - the recipes for each are in
`references/wireless-recipes.md`:

| Protocol | Instrument | What you learn |
|---|---|---|
| NFC | PN532 / `nfc-utils` | Cards, tags and access records in range |
| RFID (MIFARE, HID) | Proxmark3 | Card dumps, badge formats, cloneability |
| Zigbee / Z-Wave | CC2531 sniffer, Zigbee2MQTT | Device inventory, mesh topology |
| 433 MHz / LoRa | RFCat, LoRa SDR | OOK/FSK payloads, alarm and sensor traffic |
| Car key fobs | Proxmark3, nRF52 | Rolling-code exposure |

Card dumps, pairing keys, badge numbers and fob captures are credential
material. Store them in the engagement artifact directory, describe them
in the finding, and never print them into the transcript.

## Recording the work

- **Findings** - use `cyber_record_finding` for every result. The evidence
  is the artifact path, not the key. A recovered PSK, an exposed BLE
  service, a rogue AP mismatch and an unencrypted management frame are all
  findings, each with its own severity and its own reproduction steps.
- **Journal** - `cyber_journal` shows the record. Tool runs are journalled
  automatically. The manual steps (monitor mode, `aireplay-ng`,
  `hostapd`, `btmon`) are not, so note them in the engagement notes
  yourself. A wireless engagement is the one most likely to be questioned
  later, so the record has to stand on its own.
- **Surface** - the survey result belongs in the surface index so a later
  question about the site's networks is answered from the index rather
  than from a second capture.

## Reference

`references/wireless-recipes.md` holds the command-level detail:

- R0 adapter inventory and monitor-mode bring-up
- R1 survey and network inventory
- R2 handshake capture, and how to tell a failed capture from a failed card
- R3 PMKID capture with `hcxpcapng`
- R4 key recovery with aircrack-ng and hashcat, and how to build a
  targeted wordlist
- R5 deauthentication and evil twin, with the authorization checklist
- R6 rogue AP detection, including the BSSID-mismatch method
- R7 Bluetooth and BLE survey
- R8 NFC, RFID, Zigbee, 433 MHz and LoRa
- R9 evidence handling, capture hygiene and cleanup
- R10 troubleshooting: monitor mode, injection, missing handshakes,
  5 GHz, power saving, and interface disappearance
