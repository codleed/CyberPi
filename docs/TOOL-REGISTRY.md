# CyberPi tool registry and extension contract

This document is the single source of truth for tool names, file layout and the
shared helper API. Every extension in `extensions/tools/` follows it, and the
skills in `skills/` refer to the tool names defined here.

## Layout

```
extensions/
├── index.ts          # registers everything (owned by the integrator)
├── lib/              # shared helpers (already implemented)
│   ├── config.ts     # paths, engagement layout
│   ├── platform.ts   # Linux/Kali gate
│   ├── scope.ts      # authorization engine
│   ├── exec.ts       # process runner
│   ├── journal.ts    # append-only action log
│   ├── findings.ts   # finding records
│   ├── surface.ts    # attack surface index
│   ├── cache.ts      # result cache
│   └── toolkit.ts    # defineCyberTool wrapper
└── tools/
    ├── recon.ts      # subdomain, dns, whois
    ├── network.ts    # portscan, service_scan, capture
    ├── web.ts        # http_probe, crawl, dir_enum
    ├── vuln.ts       # vuln_scan, sqli, xss
    ├── exploit.ts    # exploit_search, exploit_run, poc
    ├── creds.ts      # hash_id, hash_crack, password_audit, secret_scan
    ├── ad.ts         # ad_enum, ad_attack
    ├── wireless.ts   # wireless_scan, wireless_crack
    ├── iot.ts        # iot_scan, firmware_analysis, hid_attack
    ├── infra.ts      # pivot, cloud_enum
    ├── cve.ts        # cve_lookup, cve_sync, exploit_map
    └── report.ts     # record_finding, report, journal, surface
```

Each file in `extensions/tools/` exports an array of tool definitions:

```ts
import type { ToolDefinition } from "@earendil-works/pi-coding-agent";

export const reconTools: ToolDefinition[] = [ /* ... */ ];
```

`extensions/index.ts` imports every group and registers them:

```ts
for (const tool of [...reconTools, ...networkTools]) pi.registerTool(tool);
```

## Writing a tool

Use `defineCyberTool` from `extensions/lib/toolkit.ts`. It handles the
authorization check, the binary check, the timeout, the output truncation, the
artifact capture, the cache and the journal entry.

```ts
import { Type } from "@earendil-works/pi-ai";
import { defineCyberTool, lines } from "../lib/toolkit.ts";

export const portscanTools = [
	defineCyberTool({
		name: "cyber_portscan",
		label: "Port scan",
		description: "Fast SYN port scan of an authorized target.",
		promptSnippet: "cyber_portscan: fast SYN port scan of a scoped target",
		technique: "port-scan",
		requires: ["naabu"],
		parameters: Type.Object({
			target: Type.String({ description: "Host or IP to scan" }),
			ports: Type.Optional(Type.String({ description: "Port range, e.g. 1-1024 or 80,443" })),
			rate: Type.Optional(Type.Number({ description: "Packets per second" })),
		}),
		build: (params) => ({
			bin: "naabu",
			args: ["-host", params.target, "-json", "-silent", ...(params.ports ? ["-p", params.ports] : [])],
			label: "portscan",
		}),
		summarize: (results) => ({
			summary: `Scanned ${params.target}`,
			output: results[0]?.stdout ?? "",
		}),
	}),
];
```

Conventions:

- Import `Type` from `@earendil-works/pi-ai` (the host-provided copy).
- Use tabs for indentation, double quotes, semicolons. Match `extensions/lib/*.ts`.
- Tool names are `cyber_<verb>_<noun>` in snake_case and never change once shipped.
- Every tool declares `technique` so the scope allowlist can gate it.
- Every tool declares `requires` when it needs external binaries.
- Prefer `build` + `summarize`. Use `execute` only when the tool is not a
  single command (for example when it queries the local CVE database).
- Parse structured tool output (`-json` flags) instead of scraping human output.
- Never print raw credential material into the transcript. Summarise it and
  point at the artifact file.

## Tool names

| Tool | File | Technique | Requires |
|---|---|---|---|
| `cyber_subdomain` | recon.ts | recon | subfinder |
| `cyber_dns` | recon.ts | recon | dig |
| `cyber_whois` | recon.ts | recon | whois |
| `cyber_portscan` | network.ts | port-scan | naabu |
| `cyber_service_scan` | network.ts | service-enumeration | nmap |
| `cyber_capture` | network.ts | recon | tcpdump |
| `cyber_http_probe` | web.ts | recon | httpx |
| `cyber_crawl` | web.ts | web-testing | katana |
| `cyber_dir_enum` | web.ts | web-testing | ffuf |
| `cyber_vuln_scan` | vuln.ts | vulnerability-scan | nuclei |
| `cyber_sqli` | vuln.ts | web-testing | sqlmap |
| `cyber_xss` | vuln.ts | web-testing | dalfox |
| `cyber_exploit_search` | exploit.ts | exploit | searchsploit |
| `cyber_exploit_run` | exploit.ts | exploit | msfconsole |
| `cyber_poc` | exploit.ts | exploit | curl |
| `cyber_hash_id` | creds.ts | password-audit | hashcat |
| `cyber_hash_crack` | creds.ts | password-audit | hashcat |
| `cyber_password_audit` | creds.ts | password-audit | hydra |
| `cyber_secret_scan` | creds.ts | password-audit | trufflehog |
| `cyber_ad_enum` | ad.ts | active-directory | ldapdomaindump |
| `cyber_ad_attack` | ad.ts | active-directory | impacket-smbserver |
| `cyber_wireless_scan` | wireless.ts | wireless | airodump-ng |
| `cyber_wireless_crack` | wireless.ts | wireless | aircrack-ng |
| `cyber_iot_scan` | iot.ts | iot-hardware | nmap |
| `cyber_firmware_analysis` | iot.ts | iot-hardware | binwalk |
| `cyber_hid_attack` | iot.ts | iot-hardware | hidrd |
| `cyber_pivot` | infra.ts | pivot | chisel |
| `cyber_cloud_enum` | infra.ts | cloud-enumeration | aws |
| `cyber_cve_lookup` | cve.ts | vulnerability-scan | python3 |
| `cyber_cve_sync` | cve.ts | vulnerability-scan | python3 |
| `cyber_exploit_map` | cve.ts | exploit | python3 |
| `cyber_record_finding` | report.ts | - | - |
| `cyber_report` | report.ts | - | - |
| `cyber_journal` | report.ts | - | - |
| `cyber_surface` | report.ts | - | - |

## CVE database CLI contract

`tools/cvedb/cvedb.py` is the offline CVE intelligence backend. It uses only
the Python standard library (`sqlite3`, `urllib`, `json`).

```
python3 tools/cvedb/cvedb.py sync [--full] [--no-kev] [--no-epss]
python3 tools/cvedb/cvedb.py get <cve-id> [--json]
python3 tools/cvedb/cvedb.py search --product <name> [--cpe <cpe>] [--cwe <cwe>]
        [--cvss-min <n>] [--cvss-max <n>] [--kev] [--keyword <text>]
        [--limit <n>] [--json]
python3 tools/cvedb/cvedb.py by-cpe <cpe> [--limit <n>] [--json]
python3 tools/cvedb/cvedb.py kev [--limit <n>] [--json]
python3 tools/cvedb/cvedb.py stats [--json]
```

Every command prints a JSON object to stdout. The database lives at
`$CYBERPI_CVE_DB` or `~/.cyberpi/cve.db`.

Sources: NVD 2.0 API (`https://services.nvd.nist.gov/rest/json/cves/2.0`),
CISA Known Exploited Vulnerabilities catalog, and FIRST EPSS scores when
available.
