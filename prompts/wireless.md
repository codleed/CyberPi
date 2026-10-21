---
description: Survey the wireless networks around the operator and attempt key recovery on the authorized ones
argument-hint: "[interface]"
---
Survey the wireless networks around this operator on interface ${1:-wlan0} and attempt key recovery on the authorized ones.

## Arguments

- Interface: $1
- Extra instructions: $@

## Steps

1. Confirm the interface is up and in monitor mode. If it is not, say exactly what is needed to put it into monitor mode and continue with the survey once the operator has done it.
2. `cyber_wireless_scan` - survey the airwaves on that interface: SSIDs, BSSIDs, channels, signal strength, the encryption type (WEP, WPA, WPA2 or WPA3), the cipher suite, and the access points that do not use a modern cipher. Pass the interface and a sensible dwell time.
3. Cross-check the results against the engagement scope. Only the networks the scope names are candidates for the next step.
4. `cyber_wireless_crack` - attempt key recovery on the authorized networks only, against the handshake you captured. Use the bundled wordlists first, and escalate to a larger wordlist only when the operator asks for it.
5. `cyber_record_finding` - for every network whose key you recovered, record a finding: the SSID, the BSSID, the cipher, the security impact and the evidence.

## Rules

- Monitor mode needs a wireless adapter that supports it. If the interface is not usable, report the adapter situation and stop, rather than guessing.
- Never attempt key recovery against a network that is not in the engagement scope, and never deauthenticate, inject or otherwise interfere with a third-party network.
- Do not print a recovered WPA passphrase in the transcript. Name the SSID and point at the artifact file.
- Do not use a network you have cracked. The engagement is the assessment, not the connection.

## Report back

- The networks seen: SSID, BSSID, channel, signal and encryption.
- The authorized networks, and whether the key was recovered for each.
- The networks that were out of scope, and the fact that they were left alone.
- The weaknesses visible without cracking anything: WEP, WPA with TKIP, WPS enabled, hidden SSIDs and open networks.
