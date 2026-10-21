---
description: Discover IoT devices, check them for default credentials and analyse their firmware
argument-hint: "[range]"
---
Discover the IoT devices in ${1:-the range in the engagement scope}, check them for default credentials, and analyse their firmware.

## Arguments

- Range: $1
- Extra instructions: $@

## Steps

1. `cyber_iot_scan` - discover and fingerprint the devices in the range: the open ports, the product and firmware version, and anything that looks like a management interface.
2. `cyber_password_audit` - test the discovered management services for default and weak credentials. Pass the device address in `target`, the service in `service`, and the credential list the operator supplied in `password_file`. Set `stop_on_success` so a single hit ends the run.
3. `cyber_firmware_analysis` - pull and analyse the firmware of the devices you identified, when the tool is able to obtain it. Look for embedded secrets, hardcoded keys, debug interfaces, backdoors, insecure update paths, and the exact build details that identify the applicable CVE.
4. `cyber_cve_lookup` - look up the firmware and software versions you found in the local CVE database and report the exploitability verdict for each.
5. `cyber_hid_attack` - only when the operator explicitly asks about USB or HID devices, and only against devices that are in scope. It is an intrusive step, so ask first and name the device.
6. `cyber_record_finding` - record each confirmed issue: the device address, the product and firmware, the weakness, the impact and the evidence.

## Rules

- Use only the CyberPi tools named above. Do not run nmap, binwalk or hydra yourself.
- Do not brick, reflash, modify or reset a device. Firmware analysis is read-only, and nothing may be written to a device.
- Never print a recovered password in the transcript. Name the device, the account and the artifact path instead.
- Use the wordlists that ship with the engagement or that the operator supplied. Do not invent new credential lists.

## Report back

- The devices found: address, product, firmware version and open services.
- The devices that accepted default credentials, and what that access gives.
- The firmware findings, including the embedded secrets and how the update mechanism works.
- The CVE verdicts for the versions you found.
- The devices that could not be fingerprinted, and why.
