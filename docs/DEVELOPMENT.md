# Developing CyberPi

This guide is for contributors to CyberPi. It covers the development setup,
the house style, and the walkthroughs for adding a tool, a skill, a prompt
template and a theme.

For the architecture — how the pieces fit together and how a tool call flows
through the system — see [`ARCHITECTURE.md`](./ARCHITECTURE.md). For the
authoritative contract on tool names, techniques and required binaries, see
[`TOOL-REGISTRY.md`](./TOOL-REGISTRY.md). For product scope and design
decisions, see [`PLAN.md`](./PLAN.md).

---

## 1. Prerequisites

| Requirement | Version | Why |
|---|---|---|
| Node.js | 22.19 or newer | Pi's runtime requirement; `node --test` also runs the TypeScript test files directly |
| Python | 3.11+ | the CVE database sidecar (standard library only) |
| Kali Linux | any recent release | **running** the harness; not needed for type-checking or unit tests |

You do **not** need Kali, or the Kali toolchain, to build CyberPi. The
type-checker and the unit tests never spawn a scanner. The Kali binaries are
only required at engagement time, and `bin/cyberpi-doctor` tells you which
ones are missing.

---

## 2. Getting the source

```bash
git clone https://github.com/<org>/CyberPi.git
cd CyberPi
npm install --ignore-scripts
```

`--ignore-scripts` matters: the package declares Pi's host modules as peer
dependencies, and a postinstall hook would try to install or build a second
copy of them. The host provides those modules at runtime, so they are only
needed for type-checking, and the `devDependencies` block pins them for
exactly that.

Verify the checkout:

```bash
npm run typecheck
npm test
```

- `npm run typecheck` runs `tsc --noEmit` over `extensions/**/*.ts` and
  `tests/**/*.ts`. It must be clean before you push.
- `npm test` runs `node --test tests/*.test.ts`.

Both work on any host, including Windows. Nothing in the test suite touches
the network or the Kali toolchain.

---

## 3. Day-to-day commands

| Command | What it does |
|---|---|
| `npm run typecheck` | `tsc --noEmit` — the gate. Must be clean. |
| `npm test` | the `node:test` suite. |
| `npm run doctor` | `bash bin/cyberpi-doctor` — environment and toolchain diagnostics. |
| `npm run cve-sync` | `python3 tools/cvedb/cvedb.py sync` — refresh the CVE database. |
| `pi -e .` | load this package into Pi for a manual smoke test. |

A manual smoke test on Kali:

```bash
cd /path/to/engagement          # a directory containing .cyberpi/scope.json
pi -e /path/to/CyberPi
```

Then, inside Pi:

```
/cyber
/recon example.com
/report
```

`/cyber` renders the dashboard, which proves the extension loaded, the scope
parsed and the surface index is readable.

---

## 4. Code style

The house style is enforced by `tsconfig.json` and by review. Match
`extensions/lib/*.ts` — that is the reference implementation.

### Rules

- **Indentation: tabs.** Never spaces.
- **Strings: double quotes.** Template literals only when interpolating.
- **Semicolons.** Every statement.
- **Trailing commas** in multiline literals, arrays and object literals.
- **Strict TypeScript.** `strict: true` is on. No implicit `any`, no
  `any` at all.
- **Erasable syntax only.** `erasableSyntaxOnly` is on, so the output must
  be valid JavaScript after type stripping. That means:
  - no `enum` — use a union of string literals and a `const` array
  - no `namespace` — use modules
  - no parameter properties (`constructor(private readonly x: string)`) —
    declare the field and assign it
  - no `import =` / `export =`
- **Top-level imports only.** No dynamic `await import()`; use a static
  top-level import.
- **`verbatimModuleSyntax` is on.** Type-only imports must use
  `import type { ... }`; value imports must not be marked `type`.
- **Imports of Pi host modules:**
  - `import { Type } from "@earendil-works/pi-ai";` — the host-provided copy.
  - `import type { ToolDefinition } from "@earendil-works/pi-coding-agent";`
- **Relative imports carry the `.ts` extension** (`"../lib/toolkit.ts"`),
  because `allowImportingTsExtensions` is enabled and `rewriteRelativeImportExtensions`
  normalizes them.

### Example

```ts
import { Type } from "@earendil-works/pi-ai";
import type { ToolDefinition } from "@earendil-works/pi-coding-agent";
import { defineCyberTool, lines } from "../lib/toolkit.ts";

export const demoTools: ToolDefinition[] = [
	defineCyberTool({
		name: "cyber_demo",
		label: "Demo",
		description: "Demo tool.",
		technique: "recon",
		requires: ["dig"],
		parameters: Type.Object({
			target: Type.String({ description: "Host to query" }),
		}),
		build: (params) => ({
			bin: "dig",
			args: ["+short", params.target],
			label: "demo",
			target: params.target,
		}),
		summarize: (results) => ({
			summary: `Resolved ${params.target}`,
			output: lines(results[0]?.stdout ?? "").join("\n"),
		}),
	}),
];
```

### Hard constraints from the brief

- **Tools target Linux/Kali binaries.** No Windows fallbacks, no mocked or
  fake results. A scanner that is not installed produces an error naming the
  missing binary, not a fabricated result.
- **Never print raw credential material, session cookies or tokens into the
  transcript.** Summarise the finding and point at the artifact file.
- **Do not re-implement shared behaviour.** Scope checks, journalling,
  process spawning, output truncation, caching and artifact capture all live
  in `extensions/lib/`. Use `defineCyberTool`.

---

## 5. Adding a tool

### 5.1 Walkthrough

Suppose we want `cyber_ssl_scan` — TLS configuration auditing with `sslscan`,
in the web-testing family.

**Step 1 — pick the file.** `sslscan` is a web-testing tool, so it belongs in
`extensions/tools/web.ts`. Add the tool to the existing exported array.

**Step 2 — declare the contract.**

- **Name**: `cyber_<verb>_<noun>` in snake_case. Names never change once
  shipped — they end up in engagement journals and in saved transcripts.
- **Technique**: one of the identifiers in `TECHNIQUES` in
  `extensions/lib/scope.ts`. The value is matched against the engagement's
  technique allowlist, so it must be exactly one of them. `sslscan` audits a
  TLS endpoint, which is `web-testing`.
- **Requires**: the binaries that must exist. `["sslscan"]`.
- **Scope target**: the parameter that names what is being touched. The
  toolkit looks for `target`, `host`, `hostname`, `url`, `domain`, `ip` and
  `address` automatically; if your tool names it differently, declare
  `target: (params) => params.endpoint`.
- **Port**: likewise, `port` is found automatically; otherwise declare
  `port: (params) => params.port`.

**Step 3 — write the tool.**

```ts
import { Type } from "@earendil-works/pi-ai";
import { defineCyberTool, lines, parseJsonLines } from "../lib/toolkit.ts";

interface SslScanResult {
	host: string;
	port: number;
	version?: string;
	cipher?: string;
	certificate?: {
		subject?: string;
		issuer?: string;
		notAfter?: string;
	};
	findings?: Array<{ id: string; severity: string; text: string }>;
}

export const sslScanTools = [
	defineCyberTool({
		name: "cyber_ssl_scan",
		label: "TLS scan",
		description: "Audit the TLS configuration of an in-scope HTTPS endpoint.",
		promptSnippet: "cyber_ssl_scan: audit the TLS configuration of an in-scope endpoint",
		technique: "web-testing",
		requires: ["sslscan"],
		parameters: Type.Object({
			target: Type.String({ description: "Hostname or URL to audit" }),
			port: Type.Optional(Type.Number({ description: "TLS port, default 443" })),
		}),
		build: (params) => ({
			bin: "sslscan",
			args: [
				"--json",
				"--no-colour",
				`${params.target}:${params.port ?? 443}`,
			],
			label: "sslscan",
			target: params.target,
		}),
		summarize: (results, params) => {
			const parsed = parseJsonLines<SslScanResult>(results[0]?.stdout ?? "");
			const issues = parsed.flatMap((entry) => entry.findings ?? []);
			return {
				summary:
					issues.length > 0
						? `${issues.length} TLS issues on ${params.target}`
						: `No TLS issues reported for ${params.target}`,
				output: lines(results[0]?.stdout ?? "").slice(0, 40).join("\n"),
				severity: issues.some((issue) => issue.severity === "HIGH") ? "high" : "info",
				details: { target: params.target, issues },
			};
		},
	}),
];
```

**Step 4 — register it.** Add the array to the import and the registration
loop in `extensions/index.ts`:

```ts
import { sslScanTools } from "./tools/web.ts";

for (const tool of [...webTools, ...sslScanTools]) {
	pi.registerTool(tool);
}
```

**Step 5 — document it.** Add the row to the table in
[`TOOL-REGISTRY.md`](./TOOL-REGISTRY.md#tool-names):

| `cyber_ssl_scan` | web.ts | web-testing | sslscan |

If the tool discovers hosts, services or endpoints, merge them into the
surface index with the helpers in `extensions/lib/surface.ts`, tagging each
entry with the scanner that found it:

```ts
import { addEndpoints } from "../lib/surface.ts";

addEndpoints(cwd, [{ url, host, status, title, source: "sslscan" }]);
```

**Step 6 — check it.**

```bash
npm run typecheck
npm test
```

### 5.2 `build` + `summarize`, or `execute`?

**Use `build` + `summarize`** whenever the tool is one command. The wrapper
then handles the cache, the artifacts, the journal and the summary assembly
for you.

**Use `execute`** only when the tool is not a single command — for example
when it queries the local CVE database, reads the engagement state, or
composes several calls with logic in between. The scope check, the technique
check and the journal entry still apply; the cache does not (those tools are
already fast).

### 5.3 Checklist

Before you open a pull request, walk this list for every tool you touched.

- [ ] **Name** is `cyber_<verb>_<noun>`, snake_case, and did not change if
      the tool already shipped.
- [ ] **Technique** is one of the identifiers in `TECHNIQUES`
      (`extensions/lib/scope.ts`) and describes what the tool actually does.
- [ ] **Requires** lists every binary the tool needs. The wrapper turns a
      missing binary into an actionable "install this" message.
- [ ] **Scope target** is declared or named `target`/`host`/`hostname`/`url`/
      `domain`/`ip`/`address`. A tool that touches the network must have one;
      without it the scope check cannot run.
- [ ] **Journal**: the tool runs through `defineCyberTool`, so the command,
      the exit code, the duration and the artifact path are recorded. Check
      that `action` is meaningful (it defaults to the tool name).
- [ ] **Cache**: `cacheTtlMs` is set for read-only reconnaissance and left
      unset for anything with side effects (exploitation, credential
      attacks, writes).
- [ ] **Surface update**: if the tool discovers hosts, services or endpoints,
      it merges them into the index with `addHosts` / `addServices` /
      `addEndpoints` from `extensions/lib/surface.ts`, each entry tagged with
      the `source` that found it. The shapes are declared by
      `CyberToolSummary["surface"]` in `extensions/lib/toolkit.ts`.
- [ ] **Output is parsed structurally**, not scraped from human-readable
      text. Prefer the tool's `-json` / `-jsonl` flag.
- [ ] **No secrets in the transcript.** Credentials, cookies and tokens go to
      the artifact file; the summary says what happened and where the
      evidence is.
- [ ] **Time and output are bounded**: `timeoutMs` is set for anything that
      can run long, and the summary is a summary.
- [ ] **Documentation**: the row is in `TOOL-REGISTRY.md`, and if the tool
      introduces a new technique it is in `TECHNIQUES`.
- [ ] **Type-check and tests pass.**

---

## 6. Adding a skill

A skill is a directory containing a `SKILL.md`. CyberPi keeps them in
`skills/<skill-name>/`.

```
skills/ssl-audit/
├── SKILL.md
└── references/
    └── findings.md
```

### Frontmatter rules

```markdown
---
name: ssl-audit
description: Audit TLS configuration of in-scope web services and turn the results into findings. Use when the engagement involves HTTPS endpoints, certificate problems, or cipher/protocol weaknesses.
---

# TLS audit

Work through the steps below for every in-scope HTTPS endpoint.

1. Read `references/findings.md` to map the scanner output to severities.
2. Run `cyber_ssl_scan` for each host in the surface index.
3. Record anything HIGH with `cyber_record_finding`.
```

- `name` — lowercase letters, digits and hyphens. No leading, trailing or
  consecutive hyphens, at most 64 characters. Keep it identical to the
  directory name: that is the portable form.
- `description` — at most 1024 characters. It is the **routing** text: the
  only part of the skill the model sees at startup. Say both *what the skill
  does* and *when it applies*. "Helps with TLS" is not enough; the model
  cannot tell when to load it.
- Optional, from the Agent Skills specification: `license`,
  `compatibility`, `metadata`, `allowed-tools`, and
  `disable-model-invocation: true` for a skill that should only be reachable
  through `/skill:<name>`.

Malformed frontmatter, or a skill with no description, is silently not
loaded — check the startup diagnostics.

### Where the detail belongs

- `SKILL.md` holds the workflow: the ordered steps, the decision points, the
  tool names to call, and when to stop.
- `references/*.md` holds everything that is only needed occasionally: the
  full CVE background, the severity rubric, the per-tool flag reference.
  Refer to it with a path relative to the skill directory.
- `scripts/` holds a helper script the skill may run. Keep the skill
  self-contained.

Pi loads only the name, description and path of a skill into the system
prompt. The body is read when the model decides the task needs it — that is
what keeps the context small.

### Checklist

- [ ] `SKILL.md` exists with valid frontmatter and a routing-quality description.
- [ ] The directory name matches the `name` field.
- [ ] The skill names the tools it uses, and those names exist in
      `TOOL-REGISTRY.md`.
- [ ] Long detail moved into `references/`, referenced by relative path.
- [ ] The skill does not duplicate the tool contract — it describes *how to
      work*, the registry describes *what exists*.

---

## 7. Adding a prompt template

A prompt template is a Markdown file in `prompts/`. The filename becomes the
slash command.

```
prompts/ssl-audit.md
```

```markdown
---
description: Audit the TLS configuration of every HTTPS endpoint in scope
argument-hint: "[host]"
---

Audit the TLS configuration of ${1:-every HTTPS endpoint in the surface index}.

Use `cyber_ssl_scan` for each endpoint, then record a finding for every
HIGH and MEDIUM issue with `cyber_record_finding`. Summarize the outcome in
one paragraph and list the affected hosts.
```

- The frontmatter accepts `description` (shown in command completion) and
  `argument-hint`. Use `<angle brackets>` for required arguments and
  `[square brackets]` for optional ones.
- If `description` is omitted, Pi uses the first non-empty line of the body.
- Substitutions: `$1`, `$2`, … for positional arguments; `$@` or
  `$ARGUMENTS` for all of them; `${1:-default}` for an argument with a
  fallback; `${@:-default}`, `${@:N}` and `${@:N:L}` for the whole argument
  list.
- Run `/reload` after adding or editing a template in a live session.

CyberPi ships 12 templates: `/cyber`, `/recon`, `/scan`, `/exploit`,
`/report`, and the phase-specific ones.

---

## 8. Adding a theme

A theme is a JSON file in `themes/`. CyberPi ships `themes/cyber.json`.

```json
{
	"$schema": "https://pi.dev/schemas/theme.schema.json",
	"name": "cyber",
	"appearance": "dark",
	"vars": {
		"accent-hue": 195,
		"bg": "okhsl(220 24% 7%)"
	},
	"colors": {
		"accent": "okhsl(var(--accent-hue) 85% 55%)",
		"text": "okhsl(210 20% 88%)",
		"muted": "okhsl(210 12% 58%)",
		"border": "okhsl(215 18% 18%)",
		"toolSuccessBg": "okhsl(150 30% 12%)",
		"toolErrorBg": "okhsl(2 40% 13%)"
	}
}
```

Rules:

- `name` is required, must be unique across every loaded theme, must not
  contain `/`, and must not be `system` (that name is reserved).
- `appearance` is `"dark"` or `"light"`; Pi can also infer it from the
  colors.
- `vars` holds reusable color values. Variables may reference other
  variables; a missing or circular reference makes the theme invalid.
- `colors` assigns colors to interface roles. Only documented roles and
  documented top-level fields are accepted — custom keys under `colors` or
  `export`, and extra top-level metadata, are rejected.
- Color values may be RGB hex (`"#0af"`), OKLCH, OKHSL, a 256-color index,
  a variable reference, or `""` for the terminal default.

CyberPi's palette is an OKHSL near-black with a cyan accent, and the
severity colors used by the tool output follow the finding severities
(`info`, `low`, `medium`, `high`, `critical`). When you change the theme,
keep the severity colors distinguishable from each other and from the
background at 4.5:1 contrast or better.

---

## 9. Tests

The suite lives in `tests/` and runs with `node:test`:

```bash
npm test                          # node --test tests/*.test.ts
node --test tests/scope.test.ts   # one file
```

```ts
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { checkTarget } from "../extensions/lib/scope.ts";

describe("checkTarget", () => {
	it("refuses a target outside the scope", () => {
		const verdict = checkTarget(
			{ engagement: "test", rules: [{ target: "10.0.0.0/24" }], techniques: [], allowSelfTest: false },
			"10.1.2.3",
		);
		assert.equal(verdict.allowed, false);
	});
});
```

### What to test

Test the parts where a silent bug is dangerous or expensive:

- **The authorization engine** (`extensions/lib/scope.ts`): CIDR matching for
  IPv4 and IPv6, `*.example.com` and `exact:` semantics, the port,
  protocol and technique filters, the engagement-level technique allowlist,
  and the fail-closed behaviour when no scope file exists. A bug here is a
  bug in the product's central promise.
- **Target parsing** (`parseTarget`): URLs with schemes and paths, IPv6
  literals in brackets, `host:port`, embedded credentials.
- **The journal** (`extensions/lib/journal.ts`): entries are appended, not
  rewritten; malformed lines are skipped on read; the statistics roll up
  correctly.
- **Findings** (`extensions/lib/findings.ts`): the render/parse round trip
  preserves every field, and malformed documents are rejected rather than
  silently accepted.
- **The surface index** (`extensions/lib/surface.ts`): merges enrich rather
  than duplicate, keyed by host, `host:port/protocol` and URL.
- **The cache** (`extensions/lib/cache.ts`): keys are stable across
  parameter ordering, and expired entries are not returned.
- **Pure parsers** in `extensions/lib/toolkit.ts` (`lines`, `parseJsonLines`,
  `parseKeyValues`): malformed lines are skipped, not fatal.
- **The CVE CLI** (`tools/cvedb/cvedb.py`): the JSON contract of every
  command, run against a temporary database.

### What not to test

Do not write tests that spawn Kali binaries or touch the network. They would
fail on every contributor's machine that is not a Kali box with the full
toolchain installed. The behaviour of the scanners themselves is not
CyberPi's code; the behaviour of the *wrapper* is.

---

## 10. Release process

1. **Verify.** `npm run typecheck && npm test` must be clean. On a Kali
   machine, run `bin/cyberpi-doctor` and a smoke test (`pi -e .`, then
   `/cyber`).
2. **Update the docs.** If a tool was added, renamed or removed, update the
   table in `TOOL-REGISTRY.md`. If the architecture changed, update
   `ARCHITECTURE.md`. If the developer workflow changed, update this file.
3. **Bump the version** in `package.json`. CyberPi follows semver:
   - **patch** — bug fixes, documentation, new skills or prompts that add no
     tool surface.
   - **minor** — new tools, new techniques, new skills, new prompts.
   - **major** — a change to the engagement data model, the scope format, or
     the tool naming scheme. These break saved engagements, so they need a
     migration note in the release.
4. **Update the installer** (`install.sh`, `uninstall.sh`) if the Kali
   package list changed, and the version references in `bin/cyberpi*`.
5. **Commit and tag.** One commit per logical change, then
   `git tag v<version>` and push the tag.
6. **Publish.** `npm publish` (the package is tagged `pi-package` so it is
   eligible for the Pi package gallery). Verify with
   `npm view cyberpi-harness version`.
7. **Announce.** Release notes list the new tools, the new techniques and
   any scope-model changes, so an operator can widen `scope.json` if the
   new techniques need authorizing.

### Compatibility promises

- Tool names never change. A name in an old engagement journal must still
  resolve to the same tool.
- The `scope.json` format only gains optional fields. A new field that is
  absent must keep the old behaviour, so an old scope file still loads.
- The engagement directory layout (`.cyberpi/scope.json`, `journal.jsonl`,
  `surface.json`, `findings/`, `artifacts/`, `cache/`) is stable. A release
  that changes it must read the old layout too.
- The `cvedb.py` command-line contract is stable, because skills and prompt
  templates call it by name.

---

## 11. Where things live

| I want to change | I edit |
|---|---|
| A tool's behaviour | `extensions/tools/<group>.ts` |
| A shared guarantee (scope, journal, cache, exec) | `extensions/lib/<module>.ts` |
| The tool contract, names, techniques | `docs/TOOL-REGISTRY.md` |
| The engagement model, the data flow | `docs/ARCHITECTURE.md` |
| The workflow the model follows | `skills/<skill>/SKILL.md` |
| A slash command | `prompts/<name>.md` |
| The look of the terminal | `themes/cyber.json` |
| What Pi loads from this package | `package.json` (`pi` manifest) |
| The CVE intelligence | `tools/cvedb/cvedb.py` |

---

## 12. Troubleshooting for contributors

| Symptom | Cause and fix |
|---|---|
| `tsc` reports an error in a file you did not touch | Another agent's file is mid-edit. Only fix errors in files you own. |
| `Extension does not export a valid factory function` | The `pi.extensions` glob matched a helper module. Helper modules live in `extensions/lib/` and must be excluded from the glob. |
| A skill does not appear in the slash commands | Check the frontmatter: `name` and a non-empty `description` are both required, and the directory must contain `SKILL.md`. |
| A theme is rejected | Check `name` (unique, no `/`, not `system`) and that only documented roles appear under `colors`. |
| `Missing required tool(s)` at runtime | The Kali package is not installed. `bin/cyberpi-doctor` lists exactly what is missing. |
| A tool reports "Blocked by engagement scope" | Working as designed. Add the target to `.cyberpi/scope.json` if the client authorized it. |
| The CVE tool says the database is missing | Run `npm run cve-sync` (or `cyber_cve_sync` inside the session). |
