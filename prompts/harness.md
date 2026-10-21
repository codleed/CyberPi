---
description: Describe the CyberPi harness to the operator - what it can do, which tools exist, what is in scope and how to use it
argument-hint: "[topic]"
---
Describe the CyberPi harness to the operator, focused on ${1:-an overview of the harness}.

## Arguments

- Topic: $1
- Extra instructions: $@

Answer the operator's question about the harness directly, and use the state of the current engagement for the concrete details.

## What to cover

1. What CyberPi is: a Kali Linux security engagement harness built as a Pi package. Every network action goes through a CyberPi tool, every tool is checked against the engagement scope before it runs, and every action is written to the engagement journal.
2. The available tools, by group, using the exact tool names from `docs/TOOL-REGISTRY.md`:
   - Reconnaissance: `cyber_subdomain`, `cyber_dns`, `cyber_whois`
   - Network: `cyber_portscan`, `cyber_service_scan`, `cyber_capture`
   - Web: `cyber_http_probe`, `cyber_crawl`, `cyber_dir_enum`
   - Vulnerabilities: `cyber_vuln_scan`, `cyber_sqli`, `cyber_xss`
   - Exploitation: `cyber_exploit_search`, `cyber_exploit_run`, `cyber_poc`
   - Credentials: `cyber_hash_id`, `cyber_hash_crack`, `cyber_password_audit`, `cyber_secret_scan`
   - Active Directory: `cyber_ad_enum`, `cyber_ad_attack`
   - Wireless: `cyber_wireless_scan`, `cyber_wireless_crack`
   - IoT and hardware: `cyber_iot_scan`, `cyber_firmware_analysis`, `cyber_hid_attack`
   - Infrastructure: `cyber_pivot`, `cyber_cloud_enum`
   - CVE intelligence: `cyber_cve_lookup`, `cyber_cve_sync`, `cyber_exploit_map`
   - Engagement: `cyber_record_finding`, `cyber_report`, `cyber_journal`, `cyber_surface`
3. The slash commands: `/recon`, `/scan`, `/webtest`, `/exploit`, `/privesc`, `/ad`, `/wireless`, `/iot`, `/cve`, `/report`, `/status` and `/harness`. Each one takes an optional target argument.
4. The scope that is in effect right now. Read `.cyberpi/scope.json` and list the authorized targets, the techniques that are allowed and the authorization window. If there is no scope file, say that the harness is in fail-closed mode and that only the local machine can be reached.
5. How to use it: the findings are written under `.cyberpi/findings/`, the raw tool output under `.cyberpi/artifacts/`, the action journal is `.cyberpi/journal.jsonl`, the surface index is `.cyberpi/surface.json`, and the deliverable is produced with `/report`.

## Rules

- Use the exact tool names and command names listed above. Do not invent variants.
- Use `cyber_surface` and `cyber_journal` when you want to show the current state of the engagement rather than describing it in general terms.
- Keep the answer practical and short, unless the operator asked for more detail in the extra instructions.
