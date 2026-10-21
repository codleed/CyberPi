# CyberPi security model

## 1. Purpose and audience

CyberPi is a Pi package that turns the Pi coding agent into a Kali Linux
security engagement harness. It runs network scanners, credential auditors and
exploit tooling **with the full privileges of the operating-system user who
started it**. There is no sandbox, no capability drop and no container that
CyberPi itself creates. Pi, in turn, is a general-purpose coding agent that can
read files, write files and run arbitrary shell commands.

This document is therefore not a description of a hardened product. It is an
explicit statement of what CyberPi does and does not protect against, so that
the consulting team can decide, in writing, under what conditions the harness
is allowed to touch a client network.

Audience:

| Reader | What they need this for |
|---|---|
| Engagement operator | Day-to-day decisions: what may be scanned, what may be recorded, what must not be pasted into a chat window. |
| Technical director | Sign-off on the engagement, the tooling, and the isolation posture. |
| Reviewer | Evaluating a third-party skill, package or prompt before it is allowed near client data. |
| Client / client legal | Understanding what the harness does with data it collects. |

Read this document **before** the first engagement, not during one.

## 2. What CyberPi is

CyberPi is a set of model-callable tools, skills and an offline CVE database
that together let an operator run an authorized assessment with an AI agent
in the loop. Its distinguishing property is that every network-touching tool
goes through one shared wrapper (`extensions/lib/toolkit.ts`) that performs,
in a fixed order:

1. a **technique allowlist** check against the engagement scope;
2. a **target scope** check against the engagement scope;
3. a **binary availability** check;
4. the **command execution**, with a timeout, output truncation and artifact
   capture;
5. a **journal entry** recording what happened.

Because the wrapper is shared, the behaviour is identical for all 35 tools.
A tool author cannot forget the scope check, because `defineCyberTool` performs
it before the tool body runs.

CyberPi also provides a **CVE intelligence database** (NVD 2.0, CISA KEV, FIRST
EPSS) mirrored into a local SQLite file. It is queried offline. The only
outbound CVE traffic is the explicit `cyber_cve_sync` operation.

## 3. What CyberPi is not

These are not security features and are not claimed anywhere in the code:

- **It is not a sandbox.** Nothing confines a tool to a network range, a
  filesystem subtree, or a set of binaries.
- **It is not a privilege separator.** The tools run as the operator. If the
  operator is root, the tools are root.
- **It is not a content filter on the model.** CyberPi does not decide whether
  a target is "a bad target". It decides whether the target is in the written
  scope. Within that scope it will attempt the technique.
- **It is not a policy engine for Pi itself.** See section 5 — this is the
  single most important limitation in this document.

## 4. Threat model

### 4.1 Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Client authorization | `scope.json`, the signed RoE | Losing or altering it destroys the legal basis of the engagement. |
| Operator credentials | `$HOME/.pi/agent`, provider API keys, cloud CLI profiles, SSH keys | Compromise of these is compromise of the operator, not just the engagement. |
| Collected evidence | `.cyberpi/artifacts/`, `.cyberpi/findings/`, `.cyberpi/journal.jsonl` | May contain session cookies, credentials, personal data and proprietary source code. |
| Client network | Everything the operator's machine can reach | A mis-scoped scan is an outage, a breach notification, or a legal event. |
| The report | `.cyberpi/reports/` and the delivered document | The professional deliverable. Its accuracy depends on the journal. |
| CyberPi itself | The package, its dependencies, the CVE database | A compromised harness produces a compromised report. |

### 4.2 Threat actors

| Actor | Capability assumed | Primary concern |
|---|---|---|
| **Hostile target** | Controls a web page, DNS record, mail server or service banner that CyberPi reads. Can inject arbitrary text into scanner output. | Prompt injection via tool output; scanning of unintended hosts. |
| **Third-party package or skill author** | Publishes code or instructions that the operator installs. | Arbitrary code execution, data exfiltration, scope bypass. |
| **Careless operator** | Types a target from a stale note, runs the harness in the wrong directory, pastes a credential into the chat. | Out-of-scope traffic, leaked credentials, lost evidence. |
| **Model misbehaviour / prompt injection** | Induces the agent to call an unintended tool, or to exfiltrate a local file through a network tool. | Local file disclosure, out-of-scope network actions. |
| **Compromised workstation** | Full control of the operator account. | Everything. Out of scope for CyberPi's controls. |

### 4.3 Trust boundaries

```
┌─ operator workstation ─────────────────────────────────────────────────────┐
│                                                                            │
│    ┌─ UNTRUSTED INPUT ────────────────────────────────────────────────┐    │
│    │ target web pages . DNS answers . service banners . scan output   │    │
│    │ CVE text . file contents . third-party skill instructions        │    │
│    └──────────────────────────────────────────────────────────────────┘    │
│                                      |                                     │
│                                      |  prompt injection                   │
│                                      v                                     │
│    ┌─ PI AGENT PROCESS ───────────────────────────────────────────────┐    │
│    │ model + built-in tools (bash, read, write, edit, find, grep)     │    │
│    │ + CyberPi extension tools                                        │    │
│    │ [!] the built-in tools are NOT scope-checked  (see section 5)    │    │
│    └──────────────────────────────────────────────────────────────────┘    │
│                                      |                                     │
│                                      |  cyber_* tool calls                 │
│                                      v                                     │
│    ┌─ CYBERPI TOOLKIT ────────────────────────────────────────────────┐    │
│    │ scope check -> binary check -> run -> truncate -> journal        │    │
│    └──────────────────────────────────────────────────────────────────┘    │
│                                      |                                     │
│                                      |  spawn(), no shell                  │
│                                      v                                     │
│    ┌─ KALI TOOLCHAIN ─────────────────────────────────────────────────┐    │
│    │ nmap . naabu . httpx . nuclei . hydra . msfconsole . ...         │    │
│    │ network egress as the operator: their identity and reach         │    │
│    └──────────────────────────────────────────────────────────────────┘    │
│                                                                            │
│ TRUSTED   scope.json (signed, reviewed) . .cyberpi/ state dir              │
│           pinned CyberPi package                                           │
└────────────────────────────────────────────────────────────────────────────┘
```

Three boundaries matter, and they are not equally strong.

**B1 — Untrusted content → model.** Attacker-controlled text (a page body, a
DNS TXT record, a service banner) enters the transcript. It can try to make
the model do something else. CyberPi does not defend this boundary directly;
it is mitigated by the fact that *tools are scope-checked*, so a successful
injection still cannot reach outside the written scope — **provided** the
injection does not use Pi's built-in shell.

**B2 — Model → tool.** The model requests a tool with parameters. This is the
boundary CyberPi actually controls. Every `cyber_*` call is checked against
`scope.json` before a process is spawned, and the check is not advisory.

**B3 — Operator → Pi package.** The operator installs code that will run with
their privileges. This is the boundary Pi's package and project-trust systems
address, and it is the boundary an operator most often gets wrong. See
section 6 and section 10.

### 4.4 Assumptions

- The operator's account is not already compromised.
- `scope.json` accurately reflects what the client authorized, and has been
  reviewed by someone other than the person who typed it.
- The Kali toolchain is installed from the distribution's repositories.
- The operator understands that the harness can reach any host the operator's
  machine can reach, including hosts that are not in scope and hosts that are
  not the client's.

### 4.5 Out of scope

- The model behaving as a model (hallucination, refusal, over-eagerness).
- Prompt injection from untrusted content, unless the report demonstrates a
  bypass of the scope engine, a privilege-boundary bypass, or disclosure of a
  file the operator could not already read.
- Behaviour originating in user-installed third-party packages or skills.
- The absence of a built-in sandbox. Use an isolated VM or container; see
  section 11.

## 5. The authorization scope model, and why it fails closed

### 5.1 The scope file

The engagement's authorization lives in `<engagement>/.cyberpi/scope.json`.
It is JSON with comments allowed. Its shape is defined by
`extensions/lib/scope.ts`:

```jsonc
{
  "engagement": "acme-web-pentest-2025-03",
  "client": "Acme Corp",
  "authorization": {
    "statement": "Written authorization letter AC-2025-03, signed 2025-03-01.",
    "authorizedBy": "J. Doe, CISO",
    "start": "2025-03-10T00:00:00Z",
    "end": "2025-03-21T23:59:59Z"
  },
  "techniques": ["recon", "port-scan", "service-enumeration", "web-testing"],
  "allowSelfTest": true,
  "rules": [
    { "target": "10.20.0.0/24", "ports": [80, 443, 8080], "protocols": ["tcp"], "notes": "Production web tier" },
    { "target": "*.acme.example", "notes": "Staging subdomains only" },
    { "target": "exact:acme.example", "notes": "Apex, no subdomains" }
  ]
}
```

### 5.2 Target matching

| Specification | Matches |
|---|---|
| `10.20.0.0/24` | IPv4 CIDR |
| `2001:db8::/32` | IPv6 CIDR |
| `192.168.1.10` | That single address |
| `acme.example` | The host **and** its subdomains |
| `*.acme.example` | Subdomains **only** — not the apex |
| `exact:acme.example` | The host **only** — not subdomains |

A bare domain is the most permissive form. When in doubt, use `exact:` or a
wildcard, and say so in the RoE.

Per-rule filters narrow a rule further: `ports`, `protocols` and `techniques`.
The global `techniques` list is an engagement-wide allowlist; a technique that
is not on it is refused everywhere, even against a target that is in scope.
The technique vocabulary is fixed in `scope.ts` (`recon`, `port-scan`,
`service-enumeration`, `web-testing`, `vulnerability-scan`, `exploit`,
`password-audit`, `privilege-escalation`, `active-directory`, `pivot`,
`wireless`, `iot-hardware`, `cloud-enumeration`, `forensics`,
`social-engineering`).

### 5.3 Why it fails closed

With **no** `scope.json` present, the scope engine does not fall back to
"allow everything" and does not fall back to "allow nothing at all and crash".
It allows exactly one thing: a self-test against the local machine.

- `allowSelfTest` defaults to `true`, and a host is a self-test target when it
  is `localhost`, `127.0.0.1`, `::1`, `0.0.0.0`, or one of the operator's own
  interface addresses.
- Every other target is refused with: *"no scope.json found. Create
  `<engagement>/.cyberpi/scope.json` and add the authorized targets before
  running this action."*
- Setting `allowSelfTest: false` removes even that exemption. In-scope
  targets still work; nothing outside the written rules does, not even
  `localhost`.

The refusal is specific and actionable rather than a blanket denial, and — this
is the part that matters for a defensible engagement — **the refusal is
journalled**. An attempt to reach an out-of-scope target is itself a record.
A scope file that is accidentally too narrow is therefore visible in the
audit trail rather than silently converted into an untested system.

The same is true of the technique allowlist. A refused technique is journalled
as an action named `blocked` before the process is spawned.

### 5.4 What the scope engine does **not** cover

This is the part a professional reviewer must read twice.

1. **Pi's built-in tools are not scope-checked.** Pi ships `bash`,
   `powershell`, `read`, `write`, `edit`, `find`, `grep` and `ls`. Those tools
   bypass `defineCyberTool` entirely. `nmap 10.9.9.9` typed into the chat
   window reaches 10.9.9.9 regardless of `scope.json`. **The scope file
   constrains the `cyber_*` toolset; it does not constrain the agent's general
   shell access.** The only control over that access is the operating system:
   run the harness in a VM or container whose network egress is restricted, or
   under an account with no shell access to the wider network.
2. **Discovery is not containment.** A `cyber_*` tool that is pointed at an
   in-scope host may itself contact a third party: an HTTP redirect to a
   vendor CDN, an SMB session to a name server, a DNS resolver, a cloud
   metadata endpoint. The scope check sees the target you named, not every
   host the underlying tool subsequently speaks to.
3. **The check uses the declared target.** Tools declare their target through
   a `target` (or `port`/`protocol`) resolver; when none is declared, the
   toolkit looks for `target`, `host`, `hostname`, `url`, `domain`, `ip` or
   `address` in the parameters. A tool that resolves its own target from a
   DNS record or a redirected URL is checked against the name it was given.
4. **The scope file is configuration, not a control on the operator.** An
   operator can write `0.0.0.0/0` into `scope.json`, and it will be honoured.
   The scope file records the authorization; it does not create it.

## 6. The Pi package trust boundary

### 6.1 What a Pi package can do

A Pi package is a directory or npm package that can ship extensions, skills,
prompt templates and themes. A package installed this way:

- **executes TypeScript/JavaScript inside the Pi process**, with the Pi
  process's full privileges;
- may declare runtime `dependencies` that Pi installs for it;
- may ship skills whose `SKILL.md` body instructs the model to run arbitrary
  programs, and supporting `scripts/`, `references/` and `assets/` files.

There is no capability manifest, no permission prompt at install time, and no
runtime sandbox for extension code. A package is, in effect, "code that runs
as you".

### 6.2 Project trust

Pi's project-trust mechanism controls whether Pi loads project-supplied
resources found in the working directory. It requires a decision when it
finds:

- `.pi/settings.json`
- `.pi/mcp.json`
- `.pi/extensions`, `.pi/skills`, `.pi/prompts`, `.pi/themes`
- `.pi/SYSTEM.md`, `.pi/APPEND_SYSTEM.md`
- project `.agents/skills` in the current directory or an ancestor

A bare `.pi` directory does not require trust. The decision is resolved in
this order: a command-line `--approve`/`--no-approve` override, then an
extension that handles the `project_trust` event, then a saved decision for
the directory or its nearest ancestor (`~/.pi/agent/trust.json`), then the
`defaultProjectTrust` setting, which defaults to `"ask"`.

**This matters for CyberPi specifically.** An engagement directory contains
`.cyberpi/`, not `.pi/`, so the engagement state directory is not itself a
protected resource. But the *working directory* of the harness is the
engagement directory, and if anyone drops a `.pi/` or `.agents/skills/` tree
into it, the trust decision applies. Treat "someone added a folder to the
engagement directory" as an event that requires a trust review.

### 6.3 What project trust does not do

- It does not limit what a tool call can reach. After startup, enabled tools
  use the operating-system permissions of the Pi process.
- It does not undo the initial `sessionDir` lookup, which happens before the
  trust decision is resolved.
- It does not make content safe. Context files such as `AGENTS.md` and
  `CLAUDE.md` load regardless of the trust decision, and their contents steer
  the model.
- It does not protect against a hostile package installed at the user level,
  which is loaded outside the project-trust decision entirely.

## 7. The engagement journal as the audit trail

Every action CyberPi takes is appended as one JSON object per line to
`.cyberpi/journal.jsonl`.

| Field | Meaning |
|---|---|
| `ts` | ISO 8601 timestamp. |
| `tool` | The tool that produced the entry, e.g. `cyber_portscan`. |
| `action` | What happened: the tool's action label, `finding`, or `blocked`. |
| `target` | The target the action applied to. |
| `command` | The exact command line that was executed. |
| `exitCode` | The process exit code. |
| `durationMs` | Wall-clock duration. |
| `summary` | One line: `exit 0`, `command timed out`, or the refusal reason. |
| `severity` | `info`, `low`, `medium`, `high`, `critical`. |
| `artifact` | Path to the captured output file, when one was written. |
| `tags` | Free-form labels. |

The journal is **append-only** in practice: the code only ever calls
`appendFileSync`. It is not cryptographically tamper-evident, and it is not
signed. Treat it as a strong operational record and a weak evidentiary one:
copy it to the client's evidence store at the end of each day, and let the
client's own systems provide the chain of custody.

What the journal is *not*:

- It does not record what Pi's built-in shell tool ran.
- It does not record the full stdout of a scan. The summary is one line; the
  full output lives in the artifact file, and only if the tool labelled its
  run plan (`<engagement>/.cyberpi/artifacts/<label>.txt`).
- It does not record tool calls that were refused by the *binary* check —
  a missing `nmap` produces an error, not a journal entry.

Because refusals are journalled, the journal is also the evidence that the
scope was enforced: an entry with `action: "blocked"` is a recorded attempt to
go outside the authorized scope.

## 8. Handling credentials and sensitive data

### 8.1 Credentials discovered during an engagement

This is the most common way a professional assessment causes a breach of its
own client.

**Rules.**

1. **Never place raw credential material, session cookies, bearer tokens,
   private keys or password hashes into the chat transcript.** The transcript
   is retained, indexed, summarised by the model, and may be exported. A
   credential in the transcript should be treated as disclosed.
2. **Credential output belongs in the artifact file, not in the summary.**
   CyberPi's credential tools (`cyber_secret_scan`, `cyber_hash_id`,
   `cyber_hash_crack`, `cyber_password_audit`) summarise and point at the
   artifact rather than echoing the material. Keep it that way: do not
   "improve" a summary by inlining the hash or the recovered password.
3. **Do not paste a credential into a prompt, a finding's frontmatter, a
   report, or a ticketing system.** A finding records that a credential
   *exists* and where it was found; the value itself stays in the evidence
   store.
4. **Rotate or revoke at the end of the engagement.** Credentials recovered
   during an assessment must be treated as compromised by the client. This
   belongs in the RoE and in the closure checklist.
5. **Deletion of the evidence is the client's decision, not yours.** Do not
   delete artifacts containing credentials to "clean up" the engagement
   directory. The client signs off on destruction, in writing.

### 8.2 Operator credentials

CyberPi inherits the operator's credentials and does not manage them.

- The provider API key that pays for the model lives in `$HOME/.pi/agent`.
  A compromised engagement directory must not be able to read it, and
  `~/.pi/agent` must not be mounted into an engagement container.
- `cyber_cloud_enum` drives the `aws` CLI and therefore uses whatever cloud
  credentials the operator's environment exposes. Confirm with the client
  whose cloud account that is and that a read-only role is in use. An
  engagement against a client's AWS estate should never use the client's
  production credentials without an explicit written instruction.
- `cyber_pivot` (`chisel`) and `cyber_ad_attack` (`impacket-smbserver`) can open
  listeners. Know which address they bind to, and tell the client that the
  source address will appear in their logs.

### 8.3 At-rest protection

**Encryption at rest of the engagement directory is explicitly out of scope
for this release.** CyberPi does not encrypt `.cyberpi/`, and it does not
manage its keys. What it does instead:

- The engagement directory is created with the operator's default umask. Set a
  restrictive umask (`umask 077`) before creating the engagement so that
  `.cyberpi/artifacts/`, `.cyberpi/findings/`, `.cyberpi/journal.jsonl` and
  `.cyberpi/reports/` are readable only by the operator.
- The repository `.gitignore` excludes `.cyberpi/`, `engagements/`, `*.pcap`
  and `*.pcapng`, so an engagement directory that sits inside a Git working
  tree cannot be committed by accident. Verify with `git status` before the
  first commit of an engagement week.
- `.cyberpi/cache/` holds cached tool output, including outputs that may
  contain sensitive material. Clear it (`rm -rf .cyberpi/cache`) before
  archiving the engagement if the archive is going somewhere less protected.
- Treat the engagement directory as the single most sensitive artifact of the
  engagement and move it to the client's evidence store under their access
  control at the end of each day.

## 9. Outbound traffic

### 9.1 The rule

**The harness can reach anything the operator's machine can reach.** There is
no egress filter, no destination allowlist and no rate limit at the harness
level. A scanner started by the agent will send packets to a destination the
operator's own laptop could reach. On a corporate network that includes
internal services, cloud metadata endpoints, and the network the client
believes is isolated from the internet.

Practical consequences:

- **The operator's position on the network is part of the threat model.**
  Running the harness from the client's office network means client-internal
  hosts are reachable. Where the engagement allows it, that is a feature; where
  it does not, it is the most likely way to cause damage.
- **Restricted targets are not protected by the scope file.** The scope file
  governs the `cyber_*` tools, not the routing table.
- **Egress is observable to third parties.** Passive DNS resolvers, CT logs,
  certificate transparency and destination-side logs will show that the
  client's assets were enumerated. Some engagements explicitly forbid active
  enumeration for this reason.

### 9.2 Rules for outbound traffic

1. **Only touch destinations named in the RoE.** The scope file is the
   authoritative machine-readable form of that list. If a scan suggests a new
   host, add it to the RoE, get it approved, and update `scope.json` before
   touching it.
2. **Resolve names inside the scope.** A CNAME to a third-party host, an
   open redirect, or a CDN in front of the target will produce traffic to
   that third party. Treat this as in-scope traffic and get it acknowledged.
3. **No third-party scanning.** Never point a scanner at a CDN, a SaaS
   tenant, a shared host, or a service the client does not own. If a finding
   depends on it, report it as an observation and ask the client how to
   proceed.
4. **Respect rate limits and maintenance windows.** Intensity is part of the
   RoE. CyberPi's scanning tools expose rate parameters — `cyber_portscan`
   takes a packets-per-second rate, for example — and the default posture
   should be the conservative end of the range the tool allows.
5. **No denial-of-service testing** unless the RoE names it, names the method
   and names the window. CyberPi's toolset does not include a dedicated DoS
   capability, and it should not be improvised with the built-in shell.
6. **The CVE database is offline by default.** `cyber_cve_lookup` and
   `cyber_exploit_map` read a local SQLite mirror. Only `cyber_cve_sync`
   talks to the NVD, CISA and FIRST, and it fetches vulnerability data, not
   client data.
7. **Log the egress you caused.** The journal records the commands; the
   client's own network monitoring is the authoritative record. Be ready to
   reconcile the two.

## 10. Reviewing a third-party skill, package or prompt

Pi's own guidance is that extension code executes inside the Pi process and
that skills can instruct the model to run programs, so unfamiliar packages
must be reviewed before they are installed. The following procedure is the
minimum for anything that will be used during a client engagement.

### 10.1 Review procedure

1. **Pin the source.** Use a versioned npm specifier or a git tag/commit, not
   a floating range. Record the exact version in the engagement notes.
2. **Read the manifest first.** `package.json` — what does it declare under
   `dependencies`? A package that pulls in an obfuscated or freshly published
   transitive dependency is a no-go for a client environment. Host-provided
   packages (`@earendil-works/pi-ai`, `@earendil-works/pi-coding-agent`,
   `@earendil-works/pi-agent-core`, `@earendil-works/pi-tui`, `typebox`) must
   be `peerDependencies` with a `"*"` range and must **not** be in
   `dependencies`; a physical copy can create duplicate class registries and
   is flagged by Pi as a misconfiguration.
3. **Read every extension file.** Extensions run in-process with your
   privileges. Look for: `child_process` / `exec` / `spawn` calls; `fs` writes
   outside the engagement directory; `fetch`/`http` to hosts that are not the
   tool being used; `process.env` reads that touch credentials; base64 or
   otherwise obscured strings; writes to `~/.pi`, `~/.ssh`, `~/.aws`, or shell
   rc files.
4. **Read every skill body.** A `SKILL.md` is instructions to the model, and
   the model will follow them. A skill that says "run this script", "upload the
   results", "include the credentials in the summary", or "ignore the scope
   file" is a finding, not a style choice. Check the frontmatter
   (`name`, `description`, `license`, `compatibility`, `metadata`,
   `allowed-tools`, `disable-model-invocation`) and every file under
   `scripts/`, `references/` and `assets/`.
5. **Check the `description` field.** It is what routes the model to the
   skill. An over-broad description ("Use for anything security-related")
   causes the skill to be loaded on unrelated tasks, which widens the blast
   radius of whatever is inside it.
6. **Check for network destinations.** Every host the package can reach is a
   host that can exfiltrate the engagement. Enumerate them and confirm each
   one has a legitimate reason to exist in a client environment.
7. **Try it outside the engagement.** `pi -e ./local-package` runs a package
   for a single invocation without adding it to settings. Do this in a
   scratch directory with no client data and no client network.
8. **Record the review.** Package name, version, source URL, reviewer, date,
   and the outcome, in the engagement notes. When the engagement closes, the
   record is part of the deliverable's defensibility.

### 10.2 Red flags

| Observation | Why it matters |
|---|---|
| A post-install script (`preinstall`, `postinstall`) | Runs with your privileges at install time, before you have read anything. |
| A dependency published very recently, or by a different owner than the package | Common supply-chain pattern. |
| A skill body that instructs the model to bypass, widen or ignore the scope | A direct attempt to defeat the only enforcement CyberPi provides. |
| An extension that reads `process.env` broadly, or `~/.ssh`, `~/.aws`, `~/.pi` | Credential access. |
| A `curl`/`wget` to a raw IP, a paste site, or a URL shortener | Exfiltration. |
| Obfuscated or minified code, or a `bin` field pointing at a compiled blob | Cannot be reviewed; refuse. |
| A package that asks to be installed with `--local` into the engagement directory | It will be loaded whenever the harness starts in that directory. |
| A prompt template that instructs the model to perform actions the operator did not request | Prompt-layer bypass of the human's intent. |

### 10.3 Pi's own resource filters

Pi supports narrowing what a package loads, which is a useful second line of
defence once you have decided to trust a package:

```json
{
  "packages": [
    {
      "source": "npm:@example/pi-tools",
      "extensions": ["extensions/*.ts", "!extensions/legacy.ts"],
      "skills": [],
      "prompts": []
    }
  ]
}
```

Omit a property to load everything the package exposes; set it to `[]` to load
none of that type; use `!pattern` to exclude, `+path` to include exactly one
path, and `-path` to exclude exactly one path. These filters narrow the
package manifest; they cannot expose a resource the package did not declare.
For a client engagement, loading **no skills and no prompts** from a
third-party package, and only reviewed extension files, is the sensible
default.

## 11. Operational hardening checklist

Run through this before the first engagement and re-check it for each new
client.

- [ ] Run the harness inside a dedicated VM. Give it network access to the
      client range and nothing else.
- [ ] Use a dedicated operating-system account for the engagement. Not root.
- [ ] `umask 077` before creating the engagement directory.
- [ ] Write `scope.json` from the signed RoE, and have a second person review
      it against the letter of authorization before the first scan.
- [ ] Review the `techniques` list; remove anything not explicitly authorized.
      `exploit` and `password-audit` in particular should be off by default.
- [ ] Consider `allowSelfTest: false` once self-testing is done.
- [ ] Pin CyberPi to a released version. Do not run an unreleased working tree
      against a client.
- [ ] Review every third-party package and skill per section 10, and record
      the review.
- [ ] Disable Pi's built-in shell tool if the Pi version supports it, or
      constrain it with the OS. The scope engine does not cover it.
- [ ] Set the provider API key to a short-lived, spend-limited credential.
- [ ] Verify `.gitignore` covers the engagement directory, and run
      `git status` before every commit.
- [ ] Agree the evidence store and its access control with the client before
      day one.
- [ ] Confirm the clock, the timezone and the NTP sync on the harness
      machine; the journal is the audit trail and its timestamps matter.
- [ ] Run `bin/cyberpi-doctor` and confirm the toolchain versions you expect.

## 12. Reporting a vulnerability in CyberPi

### 12.1 What is in scope

A report is in scope when it demonstrates one of:

- a bypass of the engagement scope engine — an action reaching a target that
  `scope.json` does not authorize, or a technique outside the allowlist;
- a bypass of the tool-level controls — a tool that runs despite a missing
  binary, a missing scope file, or a refused technique;
- disclosure of credential material, session cookies or tokens into the
  transcript by a CyberPi tool;
- a journal or artifact integrity problem that allows a recorded action to be
  misrepresented;
- an injection path that lets untrusted target content cause a `cyber_*` tool
  to run with unintended arguments;
- privilege escalation from the engagement directory to the operator account
  or to the wider system.

### 12.2 What is not in scope

- The model refusing, hallucinating, or being excessively eager. That is
  model behaviour, not a CyberPi vulnerability.
- Prompt injection from untrusted content that does **not** produce a scope
  bypass or disclosure of material the local user could not already read.
- Behaviour caused by a third-party package or skill that the operator
  installed. Report those upstream; check the version and configuration
  before filing.
- The absence of a sandbox, or the harness's ability to reach the operator's
  reachable network. These are documented, deliberate properties of the
  design (sections 4.5 and 9).
- Findings that require an already-compromised host account.

### 12.3 How to report

Use the repository's **private** reporting channel, not a public issue:

- GitHub Security Advisories on `github.com/<org>/CyberPi` ("Report a
  vulnerability" on the Security tab), or
- the maintainers' security contact, which is recorded in the repository's
  `SECURITY.md` file.

Do not open a public issue, a public pull request or a social-media post for a
security-sensitive report. If a report needs to be shared with a client
before it is fixed, agree a private channel with them in writing first.

Include:

1. the CyberPi version (`pi list`, and the commit if you are on a development
   build);
2. the platform and toolchain versions (`bin/cyberpi-doctor` output);
3. the exact scope file used, with credentials removed;
4. the reproduction steps and the observed versus expected behaviour;
5. the journal excerpt and artifact paths that evidence the issue.

### 12.4 What to expect

- An acknowledgement within three business days.
- An assessment within ten business days, and a decision on whether the report
  is accepted, in that assessment.
- A fix and a release for accepted issues. The reporter is credited unless
  they ask not to be, and the credit is in the release notes.
- Not every accepted report results in a CVE identifier; a fix and a
  disclosure are the goal.

If a report concerns an actively exploited issue in a client environment,
tell the client immediately through the agreed communication channel
(`docs/ENGAGEMENT.md`) rather than waiting for the triage cycle.
