---
description: Port scan a target, enumerate its services and summarise what is exposed
argument-hint: "[target]"
---
Port scan ${1:-the target in the engagement scope} and enumerate the services behind it, then summarise what is exposed.

## Arguments

- Target: $1
- Extra instructions: $@

## Steps

1. `cyber_portscan` - run a fast SYN scan of the target. Use the full port range unless the operator narrowed the scope; when they did, pass the permitted range in `ports`. Use `top_ports` for a quick first pass over a large range, and keep `rate` conservative on shared infrastructure.
2. `cyber_service_scan` - run service detection with version detection against the ports that step 1 found open. Restrict the scan with the same `ports` list so the run stays inside the authorization window. Leave `timing` at normal, and set `version_only` when NSE scripts are not wanted.
3. `cyber_surface` - confirm that the discovered hosts, ports, protocols and service versions were written to the engagement surface index.

## Rules

- Use only the CyberPi tools named above. Do not run nmap or naabu yourself.
- A scope refusal is part of the result. Report which target or port was refused and by which rule, and never attempt a workaround.
- Keep the raw nmap output out of the transcript. Summarise it and point at the artifact files in `.cyberpi/artifacts/`.
- When a banner reveals a product version, use `cyber_cve_lookup` to check it against the local CVE database rather than guessing whether it is vulnerable.

## Report back

- The open ports per host, with the service and version behind each one.
- The notable exposures: management interfaces, databases, directory services, remote shells such as ssh, rdp or telnet, file shares, anonymous access, software that is out of support, and default or vendor banners.
- The ports that are open on more hosts than expected, since that usually means a shared service.
- The issues that deserve to become findings.
