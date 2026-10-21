# CyberPi architecture

This document explains how CyberPi is built, how it plugs into the Pi coding
agent, and how a single tool call travels from the model to the Kali
toolchain and back into the engagement record.

For the authoritative list of tool names, techniques and required binaries, see
[`TOOL-REGISTRY.md`](./TOOL-REGISTRY.md). For the product-level decisions and
scope, see [`PLAN.md`](./PLAN.md). For how to build on CyberPi, see
[`DEVELOPMENT.md`](./DEVELOPMENT.md).

---

## 1. What CyberPi is

CyberPi is a **Pi package** that turns the Pi coding agent into a Kali Linux
security engagement harness. It does not fork Pi and does not patch Pi. It is
an ordinary package that supplies the four resource kinds Pi already knows
how to load — extensions, skills, prompt templates and themes — plus a small
Python sidecar for offline CVE intelligence.

Three capabilities make up the product:

| Capability | Where it lives | What it does |
|---|---|---|
| **Tools** | `extensions/tools/` | Model-callable wrappers around the Kali toolchain. They are the only path from the model to the network, so every action is scope-checked, journalled and cached. |
| **Skills** | `skills/` | Agent Skills that teach the model the engagement workflows (recon, enumeration, exploitation, credential attacks, AD, wireless, IoT, reporting). |
| **CVE intelligence** | `tools/cvedb/` | A local SQLite mirror of the NVD, the CISA KEV catalog and FIRST EPSS, queried offline in milliseconds. |

Everything else in the repository supports those three: the shared library in
`extensions/lib/` implements the guarantees, `extensions/index.ts` wires the
package into Pi, and `bin/` provides the launcher and diagnostics.

---

## 2. How CyberPi fits into Pi

### 2.1 The package model

Pi loads a *package* from npm, git or a local path. A package is a directory
with a `package.json`; resources are discovered either from conventional
directories (`extensions/`, `skills/`, `prompts/`, `themes/`) or from the
explicit `pi` manifest in `package.json`:

```json
{
	"pi": {
		"extensions": ["./extensions/**/*.ts"],
		"skills": ["./skills"],
		"prompts": ["./prompts/*.md"],
		"themes": ["./themes/*.json"]
	}
}
```

Paths are relative to the package root and accept glob patterns plus `!`
exclusions. CyberPi uses the explicit manifest so that the resource set is
visible in one place and cannot drift as directories are added.

The host-provided runtime packages (`@earendil-works/pi-coding-agent`,
`@earendil-works/pi-ai`, `@earendil-works/pi-agent-core`,
`@earendil-works/pi-tui`, `typebox`) are declared as **peer dependencies**
with a `"*"` range. Pi injects them into the extension module graph; they are
never bundled, so an extension never ends up with a second copy of a class
registry.

> A helper module under `extensions/lib/` is **not** an extension entry point:
> Pi expects every matched extension file to default-export a factory
> function. If the manifest uses a recursive glob, exclude `extensions/lib/`
> from it and keep the glob pointed at the entry points.

### 2.2 The resource loader

Pi's `DefaultResourceLoader` performs discovery once per session and again on
`/reload`. It resolves resource roots from, in order: the settings file
(personal `~/.pi/agent/settings.json`, project `.pi/settings.json`), the
packages declared in settings, and the command line (`-e`, `--extension`).

For each resource type the loader produces a list plus **diagnostics**. A
malformed skill, a duplicate theme name or a resource collision is reported
as a diagnostic and the rest of the session continues — CyberPi never depends
on a resource loading cleanly to stay usable.

The loader's output is what the rest of Pi consumes:

| Resource | Loader output | Consumed by |
|---|---|---|
| Extensions | `LoadExtensionsResult` — the extension objects with their tools, commands and event handlers | the agent loop, the tool registry |
| Skills | `Skill[]` + diagnostics | the system prompt (name, description, path only) |
| Prompt templates | `PromptTemplate[]` + diagnostics | the slash-command registry |
| Themes | `Theme[]` + diagnostics | the interactive renderer and the HTML exporter |

The skill rule matters for performance: the loader puts only the **name,
description and path** of each skill into the system prompt. The body of
`SKILL.md` is read by the model only when it decides the task needs it. That
is what keeps a 35-tool, 17-skill harness from flooding the context window
at startup.

### 2.3 The extension lifecycle

An extension is a TypeScript module whose **default export** is a factory
function that receives the `ExtensionAPI`. Pi loads the module through `jiti`,
so TypeScript extensions need no build step.

```
Pi start
  │
  ├─ resource loader resolves settings + packages + CLI paths
  │
  ├─ every extension module is imported (jiti, no separate compile)
  │     └─ default export factory is invoked with the ExtensionAPI
  │           ├─ pi.registerTool(...)        → agent tool registry
  │           ├─ pi.registerCommand(...)     → slash commands
  │           ├─ pi.registerToolRenderer(...)→ transcript rendering
  │           └─ pi.on("event", handler)     → lifecycle hooks
  │
  ├─ skills, prompts and themes are resolved and indexed
  │
  └─ session starts
        ├─ session_start   → engagement context, status line
        ├─ before_agent_start → engagement state injected into the prompt
        ├─ turn_end / tool_call / tool_result → live updates
        └─ session_shutdown → flush and release
```

Lifecycle rules CyberPi follows:

- **The factory does not start processes.** Some Pi invocations load
  extensions without starting a session. Long-lived resources belong in
  `session_start`; cleanup belongs in an idempotent `session_shutdown`.
- **The factory may be async.** Pi waits for an async factory before startup
  continues, which is how CyberPi can read the engagement scope before the
  first turn.
- **Handlers run in load order.** CyberPi registers exactly one extension
  entry point so that ordering is deterministic.
- **Errors never abort the session.** A failing handler is reported and Pi
  continues.

### 2.4 CyberPi's own extension surface

`extensions/index.ts` is the single entry point. It registers:

| Registration | Purpose |
|---|---|
| 35 tools from `extensions/tools/*.ts` | the model-callable surface |
| `/cyber` and related commands | dashboard, engagement status, reporting |
| `tool_call` / `tool_result` handlers | status-line refresh and run-level bookkeeping |
| `before_agent_start` handler | injects the engagement scope, surface summary and current phase into the prompt |
| a status line | engagement name, host/service counts, current phase |

The dashboard and the context injector live in `extensions/dashboard.ts` and
`extensions/context.ts` so that `index.ts` stays a wiring file.

The surface index is not maintained by the extension shell: each tool merges
what it discovered into `surface.json` itself, through `addHosts`,
`addServices` and `addEndpoints` in `extensions/lib/surface.ts`. That keeps
the merge next to the parser that produced the data.

---

## 3. Layers

```
┌──────────────────────────────────────────────────────────────────────────┐
│ L5  OPERATOR                                                             │
│     engagement directory, scope.json, kill switch, report deliverable    │
└───────────────────────────────▲──────────────────────────────────────────┘
                                │ journal / surface / findings
┌───────────────────────────────▲──────────────────────────────────────────┐
│ L4  DELIVERABLE                                                          │
│     report generator (extensions/tools/report.ts), bin/cyberpi-report    │
└───────────────────────────────▲──────────────────────────────────────────┘
                                │ markdown findings
┌───────────────────────────────▲──────────────────────────────────────────┐
│ L3  MODEL WORKFLOW                                                       │
│     skills/ (17 skills)   prompts/ (12 slash templates)                  │
│     Pi agent loop: turn -> tool call -> tool result -> next turn         │
└───────────────────────────────▲──────────────────────────────────────────┘
                                │ tool call: name + JSON arguments
┌───────────────────────────────▲──────────────────────────────────────────┐
│ L2  TOOL LAYER                    extensions/tools/*.ts (12 groups)      │
│     cyber_portscan  cyber_crawl  cyber_vuln_scan  cyber_exploit_run ...  │
│     each tool = one scanner + one structured parse + one summary         │
└───────────────────────────────▲──────────────────────────────────────────┘
                                │ defineCyberTool(spec)
┌───────────────────────────────▲──────────────────────────────────────────┐
│ L1  POLICY + EXECUTION CORE        extensions/lib/toolkit.ts             │
│     scope check -> technique check -> binary check -> cache -> spawn     │
│     -> artifact -> journal -> summarize                                  │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐         │
│  │ scope.ts    │ │ exec.ts     │ │ cache.ts    │ │ journal.ts  │         │
│  │ authz       │ │ spawn       │ │ results     │ │ append log  │         │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐         │
│  │ config.ts   │ │ surface.ts  │ │ findings.ts │ │ platform.ts │         │
│  │ paths       │ │ index       │ │ records     │ │ Kali gate   │         │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘         │
└───────────────────────────────▲──────────────────────────────────────────┘
                                │ spawn (no shell)
┌───────────────────────────────▲──────────────────────────────────────────┐
│ L0  KALI TOOLCHAIN                                                       │
│     nmap naabu httpx katana ffuf nuclei sqlmap dalfox hashcat hydra      │
│     aircrack-ng impacket-scripts binwalk metasploit tcpdump chisel       │
└──────────────────────────────────────────────────────────────────────────┘

        ┌──────────────────────────────────────────────────────────────┐
        │ L-SIDE  CVE INTELLIGENCE   tools/cvedb/cvedb.py              │
        │          SQLite: cves / kev / epss / cpe_index / meta        │
        │          offline queries, no live API during an engagement   │
        └──────────────────────────────────────────────────────────────┘
```

---

## 4. Module boundaries

```
extensions/
├── index.ts          # the only extension entry point; registers everything
├── dashboard.ts      # /cyber dashboard and the status line
├── context.ts        # engagement state injected into the model prompt
├── lib/              # shared helpers — no tool logic, no Pi API calls
│   ├── config.ts     # paths, engagement layout
│   ├── platform.ts   # Linux/Kali gate
│   ├── scope.ts      # authorization engine
│   ├── exec.ts       # process runner
│   ├── journal.ts    # append-only action log
│   ├── findings.ts   # finding records
│   ├── surface.ts    # attack surface index
│   ├── cache.ts      # result cache
│   └── toolkit.ts    # defineCyberTool wrapper
└── tools/            # 35 tools in 12 groups
    ├── recon.ts network.ts web.ts vuln.ts exploit.ts creds.ts
    ├── ad.ts wireless.ts iot.ts infra.ts cve.ts report.ts
```

### Boundary rules

1. **`lib/` never imports from `tools/`, and never imports Pi.** The helpers
   are plain Node code that happens to be loaded by an extension. They use
   only `node:` built-ins. This keeps them unit-testable without a Pi runtime
   and keeps the authorization engine auditable on its own.
2. **`tools/` never imports from `lib/scope.ts`, `lib/exec.ts`,
   `lib/journal.ts` or `lib/cache.ts` directly.** A tool declares *what* it
   needs; `toolkit.ts` decides *how* the guarantees are applied. A tool that
   spawns a process itself has bypassed the scope check.
3. **`tools/` may import `lib/config.ts`, `lib/findings.ts`, `lib/surface.ts`
   and `lib/platform.ts`** for engagement paths, finding records and surface
   merges — those are data helpers, not policy.
4. **`index.ts` contains no tool logic.** It imports arrays and registers
   them.
5. **A tool file owns one scanner family.** If a tool needs a different
   binary, it belongs in the file for that binary's domain.

### Where each guarantee lives

| Guarantee | Implemented in | Enforced for a tool by |
|---|---|---|
| Authorization (target in scope) | `lib/scope.ts` | `technique` + `target`/`port`/`protocol` declarations |
| Technique allowlist | `lib/scope.ts` | the `technique` field |
| Binary availability | `lib/exec.ts` | the `requires` field |
| Timeout and cancellation | `lib/exec.ts` | `timeoutMs`, inherited abort signal |
| Output truncation | `lib/exec.ts` | automatic |
| Artifact capture | `lib/exec.ts` + `lib/config.ts` | automatic, unless `artifacts: false` |
| Result caching | `lib/cache.ts` | `cacheTtlMs` |
| Audit trail | `lib/journal.ts` | automatic, including refusals |
| Platform gate | `lib/platform.ts` | automatic at launch, via `bin/cyberpi` |

---

## 5. The data flow of a tool call

A tool call is the only way the model affects the outside world. This is the
complete path, from the model's JSON arguments to the summary the model sees.

```
model
  │  cyber_portscan({ "target": "10.2.3.4", "ports": "1-1024" })
  ▼
Pi agent loop
  │  validates the arguments against the TypeBox schema
  ▼
pi.registerTool() registry  →  cyber_portscan.execute()
  │
  ▼
defineCyberTool wrapper (extensions/lib/toolkit.ts:152)
  │
  ├─ 1. LOAD SCOPE        loadScope(ctx.cwd)          → ScopeConfig | null
  ├─ 2. TECHNIQUE CHECK   checkTechnique(scope, "port-scan")
  │        └─ not allowed → journal "blocked" → return isError result
  ├─ 3. TARGET RESOLUTION resolveTarget(params, spec)
  │        └─ target string, port, protocol
  ├─ 4. AUTHORIZATION     checkTarget(scope, target, { port, protocol, technique })
  │        ├─ allowed  → continue
  │        └─ refused  → journal "blocked" → return isError result
  │                       (the refusal names the scope file to edit)
  ├─ 5. BINARY CHECK     missingBinaries(["naabu"])
  │        └─ missing → return isError result with an apt-get hint
  ├─ 6. CACHE LOOKUP     cacheKey(name, params) → cacheGet()
  │        └─ hit  → return the cached summary immediately (details.cached = true)
  ├─ 7. BUILD            build(params, ctx) → RunPlan | RunPlan[]
  ├─ 8. EXECUTE          runMany(plans, { cwd, timeoutMs, signal, artifactDir })
  │        ├─ spawn WITHOUT a shell, so a target can never become shell syntax
  │        ├─ capture stdout/stderr, truncate to 32 KiB (head + tail)
  │        ├─ write the full output to .cyberpi/artifacts/<label>.txt
  │        └─ honour the timeout and the turn's AbortSignal
  ├─ 9. JOURNAL          one entry per executed command:
  │        ts · tool · action · target · command · exitCode · durationMs · artifact
  ├─ 10. SUMMARIZE       summarize(results, params) → { summary, output, details }
  │                      (the tool merges what it discovered into surface.json)
  ├─ 11. CACHE STORE     cacheSet(cwd, key, summary, cacheTtlMs)
  └─ 12. RETURN          content: [{ type: "text", text: summary (+ output) }]
                           details: structured data for the renderer and for scripts
```

Two properties of this flow are worth naming explicitly.

**Refusals are journalled.** A blocked call writes a `blocked` entry to the
journal before returning. The engagement record therefore shows what was
*attempted*, not only what succeeded — which is what makes the record
defensible.

**The scope check is fail-closed.** With no `scope.json`, the only allowed
target is the local machine (self-test). A missing configuration file denies
rather than permits.

**Summaries replace raw output.** Tool output is truncated and the model
receives a structured summary. When the output is large or sensitive, the
summary points at the artifact file instead of repeating it. Credential
material is never echoed into the transcript: the tool says what it found and
where the full output was written.

### The `execute` path

A handful of tools are not a single command — the CVE tools query a local
SQLite database, the report tools read the engagement state. Those use the
`execute` field instead of `build` + `summarize`. The wrapper applies the
same scope, technique and journal handling, and skips the cache (the query
itself is already fast). `build` + `summarize` is the default and should
stay the default.

---

## 6. The engagement data model

An **engagement** is a directory. CyberPi keeps all of its state in a
`.cyberpi/` folder inside it, so an assessment is self-contained and can be
archived, zipped or handed over as a unit.

```
<engagement>/
├── .cyberpi/
│   ├── scope.json          authorization: targets, ports, techniques
│   ├── journal.jsonl       append-only log of every action, one JSON per line
│   ├── surface.json        merged attack-surface index
│   ├── findings/           one Markdown file per finding
│   │   └── F-001.md
│   ├── artifacts/          raw tool output
│   │   └── portscan.txt
│   ├── notes/              free-form operator notes
│   ├── reports/            generated deliverables
│   └── cache/
│       └── results.json    cached tool results with expiry
└── ...                     whatever the operator wants to keep next to it
```

The engagement root is the process working directory by default, and
`CYBERPI_ENGAGEMENT` overrides it. `lib/config.ts` resolves every path in
the table above through `engagementPaths(cwd)`.

### 6.1 `scope.json` — the authorization model

```jsonc
{
	"engagement": "acme-web-2025-03",
	"client": "Acme Corp",
	"authorization": {
		"statement": "Written authorization for external penetration testing",
		"authorizedBy": "CISO, Acme Corp",
		"start": "2025-03-01",
		"end": "2025-03-15"
	},
	"rules": [
		{ "target": "10.2.3.0/24", "ports": [80, 443, 8080], "notes": "web tier" },
		{ "target": "example.com", "notes": "all subdomains" },
		{ "target": "*.example.com", "notes": "subdomains only" },
		{ "target": "exact:api.example.com", "notes": "this host only" }
	],
	"techniques": ["recon", "port-scan", "service-enumeration", "web-testing"],
	"allowSelfTest": true
}
```

Target syntax:

| Form | Meaning |
|---|---|
| `10.0.0.0/24` | IPv4 CIDR (IPv6 CIDR works too) |
| `192.168.1.10` | one host |
| `example.com` | the domain and its subdomains |
| `*.example.com` | subdomains only, not the apex |
| `exact:example.com` | the host only |

A rule may narrow further with `ports`, `protocols` and `techniques`. The
engagement-level `techniques` list is a global allowlist; an empty list means
every technique is permitted for the listed targets.

The file is JSON with comments (`//` and `/* */`), stripped by
`stripJsonComments`, so an operator can annotate their own authorization.

### 6.2 `journal.jsonl` — the audit trail

One JSON object per line, appended and never rewritten:

```json
{"ts":"2025-03-04T09:12:44.201Z","tool":"cyber_portscan","action":"portscan","target":"10.2.3.4","command":"naabu -host 10.2.3.4 -json -silent","exitCode":0,"durationMs":14210,"summary":"exit 0","severity":"info","artifact":"/engagement/.cyberpi/artifacts/portscan.txt"}
```

The journal is the source of truth for the report's "what was done" section
and for the dashboard's activity feed. It is append-only so that it can be
trusted as a record: nothing in CyberPi rewrites or removes a line.

### 6.3 `surface.json` — the attack-surface index

Reconnaissance results are merged into one JSON document so that questions
about the target are answered by reading a small file instead of re-running
scanners.

```jsonc
{
	"hosts":     [{ "host": "10.2.3.4", "addresses": ["10.2.3.4"], "source": "naabu", "firstSeen": "2025-03-04T09:12:44.201Z" }],
	"services":  [{ "host": "10.2.3.4", "port": 443, "protocol": "tcp", "service": "nginx", "version": "1.24.0", "source": "nmap", "firstSeen": "..." }],
	"endpoints": [{ "url": "https://example.com/login", "host": "example.com", "status": 200, "title": "Login", "technology": ["nginx"], "source": "httpx", "firstSeen": "..." }],
	"updatedAt": "2025-03-04T09:20:01.000Z"
}
```

Merges are keyed (`host`, `host:port/protocol`, `url`), so a later scan
enriches an earlier entry instead of duplicating it. Writes are atomic
(temp file plus rename), so a crash mid-write cannot corrupt the index.

### 6.4 Findings

Each finding is a Markdown file with YAML frontmatter in
`.cyberpi/findings/`, named by its identifier (`F-001.md`):

````markdown
---
id: "F-001"
title: "Reflected XSS in search parameter"
severity: "high"
cvss: 8.2
cve: "CVE-2024-0001"
cwe: "CWE-79"
target: "https://example.com/search"
status: "confirmed"
tags: ["web", "xss"]
createdAt: "2025-03-04T10:02:11.000Z"
updatedAt: "2025-03-04T10:02:11.000Z"
---

# Reflected XSS in search parameter

## Description
...
## Impact
...
## Reproduction
```bash
...
```
## Evidence
- ...
````

Markdown with frontmatter is deliberate: the file is already half the report
and can be read, diffed and reviewed by a human without CyberPi.

### 6.5 Artifacts

Raw tool output is written to `.cyberpi/artifacts/<label>.txt` — the
untruncated stdout and stderr of the command. The transcript only ever
contains the truncated, summarized form, so a 40 MB nmap output costs 32 KiB
of context while the full evidence stays on disk and can be quoted into the
report.

### 6.6 Cache

`.cyberpi/cache/results.json` maps a cache key to a stored tool summary with
an expiry timestamp. Expired entries are dropped on read. The key is a
hash of the tool name and the sorted parameter set, so an identical repeat
call is a hit and a single changed parameter is a miss.

---

## 7. Concurrency and caching model

### Concurrency

Three different kinds of parallelism exist, and they do not interfere.

**Within one tool call.** `build` may return an array of `RunPlan`s.
`runMany` starts them all with `Promise.all`, so a multi-step scan (for
example `nmap` and `httpx` against the same host list) takes as long as its
slowest member instead of the sum of all of them.

**Between tool calls.** Pi runs the tool calls of a single assistant message
in parallel. CyberPi does not need a lock for its data files because every
writer is either append-only (`journal.jsonl`) or atomic
(`surface.json` writes via temp file plus rename; `findings/` files are
written whole). There is no read-modify-write sequence in the shared
library that two concurrent tools can interleave on.

**Cancellation.** The turn's `AbortSignal` is threaded into every spawn.
When the user interrupts, children are killed with `SIGKILL` and the tool
returns a result describing the interruption rather than hanging.

### Caching

The cache is opt-in per tool through `cacheTtlMs`. This is deliberate: a
cached scan is only useful if the target has not changed, and some actions
(exploit runs, credential attacks) must never be replayed from a cache.

| Tool class | Cache policy | Reason |
|---|---|---|
| Reconnaissance (subdomain, dns, whois, http probe) | long TTL | DNS and web metadata change slowly |
| Port and service scans | medium TTL | the network changes, but not every minute |
| Vulnerability scans | short TTL | templates update; results are cheap to re-verify |
| Exploitation, credential attacks, report generation | none | side effects must not be replayed |

A cache hit returns the stored summary with `details.cached = true`, so the
model and the dashboard can tell the user the result was reused rather than
freshly collected.

---

## 8. The CVE database

`tools/cvedb/cvedb.py` is the offline intelligence backend. It is a single
Python file that uses only the standard library (`sqlite3`, `urllib`,
`json`), so it runs anywhere Python 3.11+ exists and pulls in no
dependencies.

The **command-line contract** is authoritative and lives in
[`TOOL-REGISTRY.md`](./TOOL-REGISTRY.md#cve-database-cli-contract). This
section describes the storage design behind it.

### 8.1 Schema

The database lives at `$CYBERPI_CVE_DB` or `~/.cyberpi/cve.db`.

```sql
-- One row per CVE.
CREATE TABLE cves (
    id            TEXT PRIMARY KEY,     -- "CVE-2021-44228"
    published     TEXT,                 -- ISO 8601
    modified      TEXT,                 -- ISO 8601
    description   TEXT,
    cvss_score    REAL,
    cvss_vector   TEXT,                 -- "CVSS:3.1/AV:N/AC:L/..."
    cvss_severity TEXT,                 -- NONE LOW MEDIUM HIGH CRITICAL
    cwes          TEXT,                 -- JSON array, e.g. ["CWE-502","CWE-400"]
    cpes          TEXT,                 -- JSON array of affected CPE URIs
    references    TEXT,                 -- JSON array of URLs
    status        TEXT,
    source        TEXT,                 -- "nvd"
    fetched_at    TEXT
);

-- Normalised CPE -> CVE index; powers `by-cpe`.
CREATE TABLE cpe_index (
    cpe    TEXT,
    cve_id TEXT,
    vendor TEXT,
    product TEXT,
    version TEXT,
    PRIMARY KEY (cpe, cve_id)
);

-- CISA Known Exploited Vulnerabilities.
CREATE TABLE kev (
    cve_id     TEXT PRIMARY KEY,
    vendor     TEXT,
    product    TEXT,
    name       TEXT,
    date_added TEXT,
    due_date   TEXT,
    ransomware TEXT,                    -- "KnownRansomwareCampaignUse"
    required_action TEXT,
    notes      TEXT
);

-- FIRST EPSS probability scores.
CREATE TABLE epss (
    cve_id         TEXT PRIMARY KEY,
    score          REAL,                -- probability of exploitation, 0..1
    percentile     REAL,                -- 0..1
    model_version  TEXT,
    date           TEXT
);

-- Sync bookkeeping and schema version.
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE INDEX idx_cves_score     ON cves (cvss_score);
CREATE INDEX idx_cves_published ON cves (published);
CREATE INDEX idx_cpe_cve        ON cpe_index (cve_id);
CREATE INDEX idx_cpe_vendor     ON cpe_index (vendor, product);
CREATE INDEX idx_kev_added       ON kev (date_added);
```

`cve_index` exists so that `by-cpe` and `--product` searches are index
lookups rather than JSON scans over the whole table.

### 8.2 Sources

| Source | Endpoint | Nature |
|---|---|---|
| NVD 2.0 | `https://services.nvd.nist.gov/rest/json/cves/2.0` | paginated, supports incremental fetch by modification date |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | complete catalog, replaced wholesale |
| FIRST EPSS | `https://api.first.org/data/v1/epss` | complete daily score set, replaced wholesale |

### 8.3 Sync strategy

```
sync [--full] [--no-kev] [--no-epss]
```

**Incremental by default.** The last successful NVD watermark
(`lastModStartDate` / `lastModEndDate`) is stored in `meta`. A normal sync
asks NVD only for CVEs modified since that watermark, which keeps a daily
sync to a few hundred records instead of the whole corpus.

**`--full` rebuilds.** A full sync drops and recreates the tables and
re-crawls NVD from the beginning. It is the recovery path after a schema
change or a corrupted database.

**KEV and EPSS are wholesale.** Both sources publish complete sets. They are
fetched in full and upserted by primary key, so a partial fetch that fails
halfway leaves the previous rows intact.

**Every write is idempotent.** Rows are upserted by CVE identifier. Running
`sync` twice in a row produces the same database, which matters because the
tool can be run from a prompt template and from a skill.

**Pacing.** The NVD endpoint rate-limits unauthenticated clients. The sync
client paces itself conservatively and honours the API key when one is
present in the environment. A rate-limited or failed page is retried a small
number of times; if the retry budget is exhausted, the sync stops and the
watermark is *not* advanced, so the next run resumes from the same point.

**Transactions.** Each page is written in one transaction and the database
runs in WAL mode, so an interrupted sync leaves a consistent database.

**Reads are offline.** Once the database is populated, `get`, `search`,
`by-cpe`, `kev` and `stats` run entirely against SQLite — no network access
during an engagement, and answers in milliseconds.

---

## 9. Performance design

The harness has to feel fast, because an engagement is an iterative loop:
scan, look, decide, scan again. Five mechanisms keep that loop tight.

**1. Structured output, parsed and summarized.** Every tool asks its
scanner for JSON (`-json`, `-jsonl`) and parses it, instead of scraping
human-readable text. The model receives a short summary plus a pointer to
the artifact, not a screenful of scan output.

**2. Truncation with a head and a tail.** `truncateOutput` keeps 70 % of the
budget from the head and 25 % from the tail and marks the middle as omitted.
Errors at the end of a long run stay visible, and the context cost of a
tool result is bounded at 32 KiB regardless of how chatty the scanner is.

**3. Parallel command execution.** `runMany` starts every plan of a call at
once. Sweeps that would otherwise be serial (a port scan followed by a
service probe) are expressed as parallel plans where the dependency allows
it.

**4. Result caching.** Identical calls hit the cache and return in
milliseconds. The TTL is chosen per tool class (see §7).

**5. The surface index.** Reconnaissance is merged into `surface.json`, so
"what services are on this host?" is a small file read instead of a
re-scan. This is the single biggest saving in a real engagement: the agent
asks about the same hosts many times.

**6. Lazy skills.** Pi advertises skills by name and description. The body of
a `SKILL.md` is read only when the task needs it, so a session that never
touches Active Directory never pays for the Active Directory workflow.

The net effect: the tools that are inherently slow (nmap, nuclei, hashcat)
are the only slow parts, and everything around them — policy checks,
journaling, indexing, reporting — costs milliseconds.

---

## 10. Cross-references

| Topic | Document |
|---|---|
| Tool names, techniques, required binaries, CVE CLI contract | [`TOOL-REGISTRY.md`](./TOOL-REGISTRY.md) |
| Product scope, design decisions, dependency matrix | [`PLAN.md`](./PLAN.md) |
| Setup, style rules, adding tools/skills/prompts/themes, tests, release | [`DEVELOPMENT.md`](./DEVELOPMENT.md) |
