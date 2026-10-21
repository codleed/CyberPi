---
name: credential-attacks
description: Assess credential strength in an authorized engagement - identify hash types, crack hashes offline, audit passwords against a scoped service, and find exposed secrets in code and configuration. Use when a task involves cracking or identifying a password hash, testing default or reused credentials against a host, spraying or auditing a service with a credential list, checking a repository or build pipeline for leaked API keys and private keys, or reporting a credential finding without disclosing the secret itself.
---

# Credential attacks

Credential work is the phase where an engagement turns into access, and it is
the phase where a mistake turns into an incident. A password spray that runs
faster than the client expected locks their users out during business hours. A
recovered password pasted into a transcript leaks into a chat log, a ticket,
and a screen share. A hash cracked against the wrong mode produces a confident
wrong answer.

The order below is the spine of this skill: **do the offline work first, then
the online work.** Offline work costs the client nothing, generates no log
events, cannot lock an account, and cannot be observed. Online work is the
opposite on every axis. Reach for the network only when offline analysis has
already told you what you are looking for.

| Tool | Binary | Technique | What it is for |
|---|---|---|---|
| `cyber_hash_id` | hashcat | `password-audit` | Identify the algorithm behind one or more hashes, so the cracking mode is right |
| `cyber_hash_crack` | hashcat | `password-audit` | Crack a hash offline against a wordlist, a rule set or a mask |
| `cyber_password_audit` | hydra | `password-audit` | Test a credential list against one authorized service |
| `cyber_secret_scan` | trufflehog | `password-audit` | Find API keys, tokens, passwords and private keys in code, history and configuration |

The tool schemas published in the current session are authoritative for
parameter names. The names used below (`target`, `service`, `path`, `hash`,
`mode`, `wordlist`, ...) are the conventional ones; if the schema offers a
different name, use the schema's.

`references/hash-modes.md` holds the hash-mode numbers, the John the Ripper
format names, and the wordlist and rule paths that ship with Kali. Read it
before the first cracking run rather than guessing a mode number.

## Scope comes first

Every action is checked against `.cyberpi/scope.json` and appended to
`.cyberpi/journal.jsonl` before it runs.

- All four tools declare the `password-audit` technique. If the engagement's
  technique allowlist does not contain it, every call is refused and the
  refusal is journalled.
- `cyber_password_audit` names a host, so the target rules apply to it as
  well: the host, and the port if the rule restricts ports.
- `cyber_hash_id`, `cyber_hash_crack` and `cyber_secret_scan` operate on
  local material. The scope engine still gates them on the technique, but a
  hash file or a repository path is not a network target.
- A refusal is a scope decision, not a broken tool. Report it, name the scope
  line that would have to change, and stop. Do not re-spell the target, reach
  the same host by another route, or edit `scope.json` yourself.

The operator amends the authorization. Your job is to make the request
precise enough that they can answer it in one line.

## Phase 0 - Preconditions

Nothing below is safe without these four answers, and they take minutes to
obtain while guessing costs hours.

1. **The authorization.** Which hosts and which services the client
   authorized for credential testing, whether the authorization names a
   window, and whether the client wants a spray, a brute force, or neither.
2. **The lockout policy.** The threshold, the counter window, and the
   duration - for every service in scope. For a directory that is the domain
   lockout policy (`LockoutThreshold`, `LockoutDuration`, `ResetCount`, and
   whether the counter is per user or global). For a host it is the local
   policy, `pam_faillock` / `pam_tally2` settings, the `MaxAuthTries` setting
   in `sshd_config`, or the fail2ban jail's `maxretry` / `findtime` /
   `bantime`.
3. **The noise budget.** The agreed window, the client's contact, and the
   ticket number the alerts are filed under. Get this before the first
   online attempt, not after the SOC asks who is spraying them.
4. **The material.** Where the hashes come from, whether they are in scope to
   crack, and where the recovered credentials may be stored and handed over.

Write all four into `.cyberpi/notes/` before the first attempt.

## Phase 1 - Identify the hash

Never crack a hash whose algorithm you have not confirmed. The same 32
hexadecimal characters can be MD5, NTLM, MD4 or a truncated SHA-256, and the
wrong mode produces a confident "not cracked" that hides a real weakness.

```
cyber_hash_id  hash: 5f4dcc3b5aa765d61d8327deb882cf99
cyber_hash_id  path: /path/to/hashes.txt
```

`cyber_hash_id` runs hashcat's identification and returns the candidate
algorithms with their mode numbers. Read the output as a shortlist, not a
verdict, and narrow it with the context you have:

- **Length and alphabet.** 32 hex characters is MD5, NTLM, MD4 or a truncated
  SHA-256. 40 hex is SHA-1 or NTLM with a salt. A `$`-prefixed blob is
  self-describing: `$1$` is md5crypt, `$5$` sha256crypt, `$6$` sha512crypt,
  `$2y$` bcrypt, `$P$` phpass, `$y$` yescrypt, `$argon2` argon2.
- **Where it came from.** A hash out of `/etc/shadow` on a Linux host is
  almost always md5crypt, sha256crypt or sha512crypt. A hash out of a
  Windows registry `SAM` hive is NT. A hash out of a `.kdbx` is KeePass. The
  origin is stronger evidence than the shape.
- **The salt.** A salted hash needs the salt to be cracked at all. If the
  identifier gives you `hash:salt` or `user:hash:salt`, keep them together;
  separating them guarantees a failure.

`references/hash-modes.md` lists the mode numbers for the common algorithms
and the John the Ripper names for the same formats.

If identification is ambiguous, do not guess: try the two most likely modes
against a short, cheap wordlist and see which one behaves like a real
password. A mode that cracks nothing on `rockyou` is usually the wrong mode.

## Phase 2 - Crack offline

```
cyber_hash_crack  path: /path/to/hashes.txt  mode: 1000  wordlist: /usr/share/wordlists/rockyou.txt.gz
```

Cracking offline is the good part of credential work: the target is not
involved, nothing is logged on the client side, no account can be locked, and
the run can go as fast as the hardware allows. It is also the step that
decides whether you need to go online at all - a cracked hash often means the
password is reused and the audit becomes a set of known answers instead of a
guess.

- **Start with the cheapest attack.** A straight dictionary attack (`-a 0`)
  against a good wordlist with a good rule set (`best66.rule`,
  `dive.rule`) resolves most real-world passwords in seconds. Only reach for
  a mask when the wordlist and rules have failed.
- **Use the potfile.** hashcat keeps every cracked password in its potfile
  and skips those pairs in later runs, so repeated runs across engagements
  get cheaper instead of more expensive. `hashcat --show` reports what is
  already cracked.
- **Order the work by value.** Crack the hashes of the accounts that matter
  to the engagement first: service accounts, admin accounts, accounts the
  surface index shows reaching something interesting. A hash of a test
  account nobody uses is not worth GPU hours.
- **Bound the run.** A mask attack over a large keyspace can run for days.
  Set a time budget and a session, and record what was left unattacked. An
  unfinished run is a result; an unbounded one is a resource abuse.
- **Do not use recovered passwords to move sideways without approval.** A
  cracked hash that gives you another host's password is a new decision, not
  a continuation.

John the Ripper ships with Kali and covers formats hashcat does not, and it
handles dynamic (`$dynamic_*$`) hashes that need a custom expression. It is
not wrapped by the registry, so it is an explicitly approved extended step:
agree it with the operator, run it against the local hash file only, and
record the command, the timestamp and the artifact path in
`.cyberpi/notes/` so the journal and the notes tell the same story.

## Phase 3 - Audit passwords online

This is the loud phase. Every attempt is a failed authentication on a live
service, and it is the only part of this skill the client can feel.

```
cyber_password_audit  target: app01.corp.local  service: http-post \
                      username_file: users.txt  password_file: passwords.txt \
                      rate_limit: 1  threads: 2  stop_on_success: false
```

### Rate limiting

Hydra's defaults are far above what an authorized test should use. Hydra runs
up to 16 parallel tasks per target by default and the toolkit's wrapper adds
its own rate control; set both low.

- **Start at one attempt per second with one or two threads.** Raise it only
  if the lockout policy and the agreed window allow it.
- **Watch the client's own protection, not just the lockout policy.** A
  fail2ban jail with `maxretry = 5` and `findtime = 10m` bans the operator's
  source address - which means the engagement stops and the client's
  administrator has to unban it. `sshd_config`'s `MaxAuthTries` (default 6)
  closes a connection after six attempts, so a long list against SSH needs
  many connections rather than many attempts per connection.
- **Prefer a single service.** Testing one service is one kind of log event.
  Testing five services against the same host is five.
- **Use `stop_on_success` deliberately.** It defaults to true, which is right
  for one account and wrong for a spray: with it off, the run continues and
  reports every account that accepted a credential.

### Spray, never brute force

One password against many accounts, or a small set of passwords against one
account. Brute force against a real account is a denial of service against
the identity system, because failed logon counters are frequently global
rather than per account. An AD domain whose `Netlogon` lockout policy
counts failures for the whole domain can be locked out by one careless run.

Against a cloud identity provider the numbers are different but the direction
is the same: Microsoft Entra smart lockout triggers after 10 failed sign-in
attempts by default (3 in Azure US Government tenants), with a lockout
period that starts at one minute and lengthens on each subsequent failure,
and the counter tracks the last three bad password hashes so repeating the
same wrong password does not advance it. That last detail is what makes a
spray of *distinct* passwords the risky shape: a spray of the *same* wrong
password repeatedly is the case the service is built to tolerate.

### Know the lockout consequence before the first attempt

| Target | What you need to know | Default if unset |
|---|---|---|
| Windows domain | `LockoutThreshold`, `LockoutDuration`, `ResetCount`, and whether the counter is per user or global | Threshold `0` - accounts are never locked, which removes the lockout risk and usually means the client is relying on monitoring instead |
| Microsoft Entra ID | Smart lockout threshold and duration, and how it interacts with the on-premises threshold | 10 failed attempts, 60-second lockout, lengthening on repeat |
| Linux host (PAM) | `pam_faillock` / `pam_tally2` `deny` and `unlock_time` | Depends on the distribution's PAM configuration |
| SSH | `MaxAuthTries` in `sshd_config` | 6 attempts per connection |
| fail2ban jail | `maxretry`, `findtime`, `bantime` | `maxretry = 5`, `findtime = 10m`, `bantime = 10m` |
| Network appliance | Vendor lockout for the management interface | Varies; ask the client |

The Windows default is worth reading twice: the built-in account lockout
threshold is `0`, meaning the account is never locked. A client in that
configuration has made a deliberate choice to tolerate unlimited failed
attempts, and the finding is usually about the missing detection rather than
the missing lockout. Confirm which configuration the client is actually in
before you rely on it - and never assume a `0` threshold means it is safe to
run a full brute force against their domain.

### Choose the right service

`cyber_password_audit` covers the hydra service modules the wrapper
exposes - `ssh`, `ftp`, `smtp`, `http-post`, `http-get`, `ssh-key`. Check the
tool's schema for the full list it accepts. The service you pick changes what
you prove:

- A **login form** proves the account works for that application. That is
  usually the finding the client can act on.
- **SSH** proves remote access to the host, which is worth much more, and
  generates a different class of log event.
- **Mail protocols** prove access to a mailbox, which is a data-protection
  finding in its own right.

Hydra itself ships many more modules than the wrapper exposes - `ldap2`,
`ldap3`, `smb`, `mssql`, `mysql`, `postgres`, `oracle`, `rdp`, `vnc`,
`telnet`, `imap`, `pop3` and the rest. A domain-native spray - an LDAP bind
or an SMB session - is therefore an extended-toolchain step: run it with the
operator's approval against a scoped host, and note the command in the
engagement record.

### Default and weak credential checks

Default and weak credential testing is a small, fast, high-yield activity
that fits inside the same rate budget:

- Use the client's own product and service inventory to pick the credential
  pairs, not a generic list. A database server running the vendor's default
  password is a real finding; the same password against a host that never
  had it installed is noise.
- `/usr/share/seclists/Passwords/Default-Credentials/` holds per-vendor
  default lists (`ssh-betterdefaultpasslist.txt`, `mysql-betterdefaultpasslist.txt`,
  `tomcat-betterdefaultpasslist.txt`, `default-passwords.txt` and the
  router set). `/usr/share/seclists/Usernames/` holds the matching username
  lists.
- Test one vendor's defaults at a time, against the host where the surface
  index says that product actually runs.
- A default credential that works is a **critical** finding on an
  internet-facing service and a **high** finding anywhere else. It is also
  the finding most likely to be closed the same day, so make the
  reproduction easy to repeat.

## Phase 4 - Secrets in code and configuration

```
cyber_secret_scan  path: /path/to/client/repo  include_history: true
cyber_secret_scan  path: /path/to/mounted/share
```

Secret detection is offline work, and it finds exposure that no password
list would ever reach: a service account password in a `*.gpp.xml` Group
Policy Preferences file, a connection string in `web.config`, an API key in
a CI workflow, a private key committed two years ago and deleted from the
working tree.

- **Scan the history, not only the tree.** A deleted credential is still in
  the git objects. A secret in the history of a public repository is
  compromised already, and rotation is the only remedy.
- **Point it at what the client gave you.** Their repositories, their build
  output, their mounted shares, their container images. Not at a third-party
  code host you happen to find.
- **Read the surrounding code before reporting.** A high-entropy string in a
  test fixture is not a credential; a live production key in a config file
  is. The detector finds candidates; you decide.
- **Verification status matters.** Trufflehog reports whether a discovered
  credential is verified against the issuing service, unverified, or
  unknown. A verified live key is a **critical** finding. An unverified
  candidate is a lead: say so, and do not inflate it.

## Reporting credential findings without leaking secrets

This is the part that decides whether the report is useful to the client or
a liability for both of you.

**Never put the secret in the transcript, the finding body, or the report.**
A finding that contains a working password is a finding that ends up in a
ticketing system, a shared drive, and an email thread. The value of the
finding is that the credential exists and where it does - the value itself
belongs in the engagement directory.

Report these:

| Report | Do not report |
|---|---|
| The service and target the credential works on | The password |
| The account or key identifier | The key or token value |
| The class of credential (default password, reused password, leaked API key, NTLM hash) | The raw hash |
| The count of affected accounts | The full account list when it is long |
| The artifact path that holds the material | The material itself |
| Verification status (verified live / unverified) | A guess presented as verified |

Practical rules:

- **Name the class, not the value.** "The database service account uses the
  vendor's default password" is a complete finding. "The password is
  `P@ssw0rd`" is a finding plus a breach.
- **Point at the artifact.** The tool writes the raw output to
  `.cyberpi/artifacts/`. The finding cites the path; the reader opens it
  under the engagement's access controls.
- **Redact partial values where the client asks for them.** A masked form
  (`AKIA…7QF2`) is enough for the client to find the key in their own
  inventory. A full value is not needed for them to fix it.
- **Hand credentials over through the agreed channel.** When the operator
  confirms a credential is real, the delivery mechanism - encrypted transfer,
  a sealed handover, the artifact path - is the operator's decision and is
  recorded in the engagement notes. It is never a line in the chat.
- **Keep the journal clean too.** The journal holds commands and summaries.
  A password in a command line ends up in the journal, in `ps` output on the
  Kali box, and in the shell history. Prefer a file over an argument wherever
  the tool allows it.

### Severity

| Condition | Severity |
|---|---|
| A working default or reused credential on an internet-facing service | critical |
| A verified live API key, cloud credential or private key in a repository | critical |
| A cracked password for an account with administrative privilege | critical |
| A working credential for a normal account on an internal service | high |
| A verified live credential of limited scope, with no path to more | high |
| A default password for a service the client does not expose externally | high |
| An unverified secret candidate in a repository | medium, and label it unverified |
| A password policy that permits the weakness, with no exploitable account | medium |
| A credential weakness that was tested and did not reproduce | low, or a note |

The severity follows the impact of the credential in this engagement, not the
number of credentials found. Ten weak passwords on ten low-value accounts
are one finding.

## Recording results

1. **The journal** - automatic for every `cyber_*` tool. `cyber_journal`
   shows the command, the target, the exit code, the duration and the
   artifact path. Never edit it. Any step outside the registry - a
   `john` run, an LDAP bind spray, a `secretsdump` - goes into
   `.cyberpi/notes/` with the command, the timestamp and the artifact path.
2. **The surface index** - `.cyberpi/surface.json`. Read it with
   `cyber_surface` before testing a service; it tells you which host runs
   which product, and that is what makes a default-credential test targeted
   rather than a scattergun.
3. **Findings** - `.cyberpi/findings/`, written with `cyber_record_finding`
   as each issue is confirmed. File a finding for:
   - a default credential on a named service;
   - a password reused across services or accounts;
   - a cracked hash belonging to a privileged account;
   - an API key, token or private key committed to a repository or pipeline;
   - a credential policy that permits the weakness;
   - a lockout policy that turns a spray into a denial of service against
     the client;
   - a detection gap for the action that was tested.

   Each finding carries the exact target, the exact command, the credential
   class, and evidence lines that point at artifact files instead of inline
   credentials.

## When a tool fails

- **A non-zero exit is not a finding.** Read the stderr, report the real
  error, and do not imitate the output of a tool that did not run.
- **"Missing required tool(s)" means the Kali package is not installed.**
  Relay the install line and stop that phase.
- **A hash that does not crack is not proof of a strong password.** It may
  be the wrong mode, a missing salt, a wordlist that does not contain the
  pattern, or a hash that was not a hash at all. Go back to Phase 1 before
  reporting "strong password".
- **Output is truncated for the transcript.** The full output is in the
  artifact file the journal points at. Read the file when the summary is
  not enough.
- **A refusal is a scope decision.** Report it and name the scope line that
  would have to change. Do not route around it.
- **The client stopped the test.** Take the stop at face value, write down
  what was running when it stopped, and do not resume without a new
  approval. A client that pulls the plug has given you information.
