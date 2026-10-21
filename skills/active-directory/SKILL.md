---
name: active-directory
description: Assess an Active Directory domain - domain reconnaissance, LDAP and DNS enumeration, SMB share and session review, Kerberos and delegation analysis, password spraying and credential attacks against domain services, privilege and ACL path analysis, ADCS abuse, and BloodHound graph collection. Use when asked to enumerate a Windows domain, list domain users, groups or computers, dump LDAP, review SMB shares, find kerberoastable or AS-REP roastable accounts, spray domain passwords, collect a BloodHound graph, find DCSync or ADCS paths to Domain Admin, or assess Active Directory detection coverage. Covers the quiet enumeration phase, the credential phase, and the loud actions the operator has to approve first.
---

# Active Directory assessment

An AD assessment answers three questions: what does the directory contain, what
can be reached from what, and what would a defender have seen. CyberPi wraps
four tools for this phase; the sequencing, the noise budget and the client
coordination around them are the rest of the skill.

| Tool | Binary | Technique | Returns |
|---|---|---|---|
| `cyber_ad_enum` | ldapdomaindump | `active-directory` | The directory: users, groups, computers, trusts, sessions and ACLs, plus SMB share listings and the DNS service records, and optionally the BloodHound graph |
| `cyber_ad_attack` | impacket-smbserver | `active-directory` | The active actions: SMB share enumeration and writes, an SMB relay listener, Responder, Kerberos ticket requests and an LDAP privilege check |
| `cyber_password_audit` | hydra | `password-audit` | Credential testing against an authorized service: ssh, ftp, smtp, http-post, http-get, ssh-key |
| `cyber_secret_scan` | trufflehog, gitleaks | `password-audit` | Credentials and keys exposed in a directory, a file or a git history, reported by type, file and line with a redacted preview |

The tool schemas published in the current session are authoritative for
parameter names and accepted values. `references/ad-techniques.md` has the
per-technique detail: what each one proves, the evidence to keep, the event IDs
the defender sees and the finding it produces.

### The extended AD toolchain

A complete AD assessment needs more than the four wrappers: kerberoasting,
DCSync, ADCS enumeration and the BloodHound graph analysis are not covered by
a single registry call. The BloodHound *collection* is
`cyber_ad_enum bloodhound: true`; the analysis is offline. The rest runs from
the operator's Kali box, and the rules for it are strict:

- Only against a host or domain that the scope file already authorizes. The
  wrapper tools are scope-checked; these are not, so the scope check has to
  happen in the operator's head and in the notes.
- Only the ones this skill names, and only after the operator has approved
  them where the skill says approval is required.
- Every run is written into `.cyberpi/notes/` with the command, the target,
  the timestamp and the artifact path, so the journal and the notes tell the
  same story of the engagement. A step that is not in the notes did not
  happen as far as the report is concerned.
- Never shell out to something that fabricates a result. If a command fails,
  report the failure.

## Scope comes first

Every network action is checked against `.cyberpi/scope.json` before it runs,
and every action is appended to `.cyberpi/journal.jsonl`. For AD this matters
more than for any other phase, because the target is usually a whole domain
rather than one host:

- A bare domain (`corp.local`) covers the domain and its subdomains, so a
  DC named `dc01.corp.local` is in scope when the rule says `corp.local`.
- The domain controllers and the member hosts are usually **different** rules
  with **different** technique allowlists. Enumeration against a DC and a
  credential attack against a member host are different scopes, and the tool
  that is refused is telling you something real.
- `cyber_password_audit` and `cyber_secret_scan` carry the `password-audit`
  technique, so they need that technique allowed even when the host is in
  scope. `cyber_ad_enum` and `cyber_ad_attack` carry `active-directory`.
- Both AD tools are scope-checked against the **domain controller**. A
  member host that is in scope still needs a rule that names it.

Two rules to respect:

1. If a call comes back **"Blocked by engagement scope"**, do not try another
   spelling, another tool or a different host form to get around it. Report the
   refusal verbatim and say which scope line would need to change. The
   operator amends the scope, not the agent.
2. A host discovered during enumeration but not covered by a scope rule is
   **out of scope**, even when it obviously belongs to the client. Record it as
   a note and mention it to the operator. Do not point a tool at it.

## Phase 0 - Establish the context

Nothing in this skill works without these answers, and getting them from the
client takes minutes while guessing them costs hours.

- **The domain and the forest.** The DNS name, the NetBIOS name, the domain
  SID if the client will share it, the domain functional level, and whether
  there are child domains, trusts or an Azure AD tenant in the picture.
- **The domain controllers.** Which hosts, which IPs, which ones are also
  DNS servers, and which are global catalog servers. The `_ldap._tcp` SRV
  record answers this without touching the directory at all.
- **The credentials.** The engagement usually provides either a dedicated test
  account or a real user's credential. Record which, and what group it is in.
  A read-only "domain user" account cannot enumerate everything, and knowing
  that up front avoids a phase that returns half a directory.
- **The domain policies that decide what is safe.** The account lockout policy
  (`LockoutThreshold`, `LockoutDuration`, `ResetCount`, and whether the
  lockout counter is global or per user), the Kerberos policy (the AES
  requirement and the maximum ticket lifetime), and the NTLM policy
  (`LmCompatibilityLevel`, `NoLmHash`, inbound and outbound NTLM
  restrictions).
- **The noise budget.** The agreed test window, the client contact who
  acknowledges the alerts, and the ticket number the alerts are filed under.

Write these into `.cyberpi/notes/` before running anything. The lockout policy
in particular decides whether the credential phase is safe to run at all.

## Phase 1 - The quiet phase

Everything in this phase is either a read that the domain serves to anyone who
asks politely, or a read that costs the client nothing they will notice. It
produces the material every later phase depends on, and it is the phase that
must be thorough, because re-running it later is expensive and noisy.

### 1.1 Domain layout from DNS

```
cyber_dns  domain: corp.local  record_type: ALL
```

The domain's own records describe the estate: the name servers, the mail
hosts, the SPF and DMARC policy, and any TXT record that names an internal
service.

The service records are the domain controller list, and `cyber_ad_enum` reads
them together with the reverse lookup and the LDAP rootDSE:

```
cyber_ad_enum  target: dc01.corp.local  domain: corp.local  methods: dns
```

That returns the `_ldap._tcp` and `_kerberos._tcp` SRV records, the name
servers, the PTR record for the DC and the naming contexts from the
rootDSE. Compare the SRV result with the domain controllers the client
named: a DC that exists in DNS but not in the client's asset register, or the
other way round, is a finding.

A zone transfer is not part of the tool set. If the client wants the zone
checked, that is a `dig AXFR` against the domain's DNS server, run as an
approved extended step and recorded in the notes. A successful AXFR on a
domain zone discloses every host in it.

The DNS server is a target too. An unauthenticated recursion or a stale zone
transfer is worth a line in the report.

### 1.2 Which management ports are open

```
cyber_portscan      target: 10.0.0.10
cyber_service_scan  target: 10.0.0.10  nse_scripts: smb-os-discovery,smb2-security-mode,ldap-rootdse
```

The ports that matter on a domain member or a DC: 53 (DNS), 88 (Kerberos), 135
(RPC), 139 and 445 (SMB), 389 and 636 (LDAP), 3268 and 3269 (Global Catalog),
9389 (ADCS/RPC) and 5985/5986 (WinRM). Nmap's `smb-os-discovery`,
`smb2-security-mode`, `ldap-rootdse` and `msrpc-*` scripts give the version,
the signing mode and the LDAP rootDSE without authentication.

Record for each DC: the domain functional level, the signing requirement, and
whether LDAP signing is enforced. Those three answers decide how the loud
phase can work.

### 1.3 The directory

```
cyber_ad_enum  target: dc01.corp.local  domain: corp.local  collection: all
```

`collection` narrows the dump to `users`, `groups`, `computers`, `trusts`,
`sessions` or `acl`; `all` covers users, groups, computers, trusts and
sessions. ACL collection needs elevated rights, so expect it to be empty
unless the engagement account is privileged - that is worth asking about.

Read the output as structure, not as a list:

- **Users with a `userPrincipalName`** are Kerberos principals.
- **Users whose `userAccountControl` includes `0x100000`** (normal, not
  temporary) are the sprayable population. Note `0x400000` (`DONT_EXPIRE`) and
  `0x800000` (`PASSWD_NOTREQD`), which change the risk.
- **Tier-0 membership.** Members of `Domain Admins` (512), `Administrators`
  (519), `Enterprise Admins` (519 in the forest root), `Schema Admins`,
  `Backup Operators`, `Account Operators`, `DnsAdmins`, and the forest root
  admins. Also the ADCS roles: `CA Administrators` and any custom group that
  holds CA or template permissions.
- **Service accounts and their SPNs.** An SPN on a *user* object is a
  kerberoasting target; an SPN on a *computer* object is normal.
- **Delegation attributes.** `msDS-AllowedToDelegateTo`,
  `msDS-AllowedToActOnBehalfOfOtherIdentity`, and
  `msDS-User-Account-Control-Computed` with `DONT_REQ_PREAUTH`.
- **Trusts.** Child domains, external trusts, and forest trusts. A trust with
  an external domain is an authorisation question for the client, not just a
  technical finding.
- **Group membership depth.** Nested groups hide the tier-0 path. A user three
  groups away from Domain Admins is still a path.

Save the raw collection where the artifact directory keeps it and quote the
counts and the names in the notes. A directory with 12,000 users is not a
finding; a list of 40 accounts that can reach Domain Admins is.

### 1.4 SMB shares and sessions

```
cyber_ad_enum  target: dc01.corp.local  methods: smb
```

That lists the shares anonymously (netexec or crackmapexec, then `smbclient
-N -L`) and, where `smbmap` is installed, maps them. For every host that
answered SMB:

- The share list, and which of them are readable with the current session.
- `ADMIN$` and `C$` reachable without credentials are critical.
- The `srvsvc`, `winreg` and `samr` named pipes are the relay targets, so
  note their presence.
- The SMB signing mode: `Message signing enabled` is the difference between
  a relay finding and a non-finding.

Do not copy file contents into the transcript. A file name and the artifact
path are the evidence; the file itself stays in the engagement directory.

### 1.5 Kerberos inventory

Turn the collected attributes into three lists:

1. **Kerberoastable accounts** - users with an SPN.
2. **AS-REP roastable accounts** - users with `DONT_REQ_PREAUTH`.
3. **Delegation** - who may delegate to what, and whether any of the targets
   is a domain controller or a service running as a domain admin.

The count of accounts with an SPN and whether the domain issues AES tickets
decide whether the loud phase has anything to work with.

Where the dump does not carry an attribute the decision depends on, query it
directly with `ldapsearch` against the DC the scope covers, and record the
query in the notes:

```bash
ldapsearch -H ldap://dc01.corp.local -b 'DC=corp,DC=local' \
  '(&(objectClass=user)(servicePrincipalName=*))' \
  userPrincipalName servicePrincipalName userAccountControl \
  msDS-AllowedToDelegateTo msDS-User-Account-Control-Computed
```

### 1.6 BloodHound graph collection

The graph is the deliverable for path analysis, and collecting it is cheaper
than any series of manual queries.

```
cyber_ad_enum  target: dc01.corp.local  domain: corp.local  bloodhound: true  collection: acl
```

- Collect `Group`, `ACL` and `Container` against a DC. Those three cover the
  edges that matter (membership, generic control, delegation, DCSync rights,
  computer object ownership) in one read of the directory.
- Collect session data only against hosts the engagement names, and only in
  the loud phase: it authenticates as every machine account and produces a
  burst of logon events.
- Keep the graph file on the operator's machine. Do not upload it to a
  third-party BloodHound instance without the client's written consent; it is
  the entire privileged graph of their domain.
- The graph query and the path analysis are **offline** work. They cost the
  client nothing at the network layer, which is why they belong here even
  though the analysis is the most valuable part of the engagement.

### 1.7 Secrets in the client's own material

```
cyber_secret_scan  path: /path/to/client/repo  include_history: true
cyber_secret_scan  path: /path/to/mounted/share
```

Domain credentials leak from the client's own files: service account passwords
in `*.gpp.xml` Group Policy Preferences, connection strings in `web.config`,
`.env` files, CI pipeline variables, `settings.py`, and scripts that still
contain the password of a retired administrator. A domain administrator's
password in a git history is a domain-takeover finding.

Scan the repositories and the file shares the engagement names, and nothing
else. This is a `password-audit` technique and needs its own authorisation.
The tool reports the secret by type, file and line with a redacted preview -
the value never enters the transcript.

## Phase 2 - Credential attacks against domain services

The credential phase is where most engagements are won. The actions that
touch the network generate log events on purpose, and they run inside an
agreed window; the path analysis that surrounds them is free.

### 2.1 Password spraying

```
cyber_password_audit  target: app01.corp.local  service: http-post \
                      username_file: users.txt  password_file: passwords.txt \
                      rate_limit: 1  threads: 2  stop_on_success: false
```

Spray, never brute force:

- One password against many accounts, a small set of passwords against one
  account. Brute force against a domain account is a denial of service
  against the whole domain, because a global `Netlogon` lockout policy
  counts failures for the entire domain.
- **Rate and volume come from the policy.** With `LockoutThreshold` of 5 and
  a global counter, five failed attempts per account are the whole budget.
  Set `rate_limit` low, keep `threads` at 1 or 2, and count the failures per
  account before the next password. The tool defaults to 10 attempts per
  second and 10 threads, which will trip a lockout policy on its own.
- **`stop_on_success` defaults to true**, which is the right default for a
  single account and the wrong one for a spray: with it off, the run
  continues through the list and reports every account that accepted a
  credential.
- **Target the right service.** `cyber_password_audit` covers the hydra
  service modules it accepts (ssh, ftp, smtp, http-post, http-get, ssh-key).
  The domain-native services - an LDAP bind or an SMB session - are not in
  that list. Test the domain-facing services the client exposed to the
  engagement with the wrapper, and treat an LDAP or SMB spray as an extended
  toolchain step (`netexec`, or a targeted `ldapsearch` bind test) that needs
  the operator's approval and a note in the engagement record.
- Never spray a service outside the scope file, and never spray the domain
  controllers with a large password list without the operator's explicit
  approval.

The result is a list of accounts that accepted a credential. **Never print
the password into the transcript.** Name the account, count the successes,
and point at the artifact file that holds the credential material.

### 2.2 Kerberoasting and the ticket attack

For each kerberoastable account, request a service ticket for its SPN and
crack it offline. The crack is `cyber_hash_id` and `cyber_hash_crack`; the
ticket request is an extended toolchain step (`GetUserSPNs`) against a scoped
DC, approved first and recorded in the notes.

The result is a service account password. Its impact depends entirely on
where the account sits: a service account that is a member of Domain Admins
is a domain compromise, and that is the finding. A service account used by
one application is a credential to rotate.

Report the SPN, the encryption type the domain issued and the impact of the
account. Never print the recovered password or hash.

### 2.3 Delegation paths

Cross-reference the delegation attributes from phase 1 with the ACL edges
from the graph:

- A **user** account with `msDS-AllowedToDelegateTo` set to a domain
  controller's service can impersonate to that DC. That is a direct path.
- **Constrained delegation** to a privileged target service, where the
  requesting account is low-privileged, is the same path with extra steps.
- **RBCD** - a principal that can write `msDS-AllowedToDelegateTo` on a
  computer account can impersonate to anything that computer authenticates
  to, which includes the DC.

These are analysed from the collected data and documented as paths. Exercising
them is a loud action (see phase 3).

### 2.4 ADCS

Enumerate the CA: the CA host, the templates published in the `Certificate
Templates` container, the enrollment permissions on each template, and the
`msPKI-*` attributes that decide whether the template can be abused.

The cases worth proving are ESC1 (enroll with a supply-controlled subject
alternative name, authenticate as anyone), ESC3 (the same against a template
that requires enrollment rights), ESC4 (the enrollment agent path via
`msPKI-Certificate-Name-Flag`), ESC6 (`ENROLLEE SUPPLIES SUBJECT` plus
`EDIT PERMISSIONS` over the SAN), and ESC8 (a CA whose issuance policy is
writable by a low-privileged user). PKINIT with a certificate and key
belonging to a low-privileged account is a domain takeover.

Enumeration of the templates is cheap and quiet. Requesting the certificate
is not - it is a loud action, and the client should know that a certificate
was issued before it shows up in their CA log.

### 2.5 Privilege and ACL path analysis

The graph is the evidence. Read it for the edges that grant control:

- `GenericAll` on a user, group or computer: full control, including adding
  yourself to the group.
- `GenericWrite` on a user: set `memberOf`, `scriptPath`, or a logon script.
- `WriteDacl` on a user or group: rewrite the permission and take over.
- `AddMember` or `AddSelf` edges into a tier-0 group.
- `Owns` the domain object, the `Domain Admins` group, or a DC computer
  account.
- `WriteSPN` plus a known password: add an SPN and kerberoast the account.
- `WriteDacl` on a computer account plus delegation rights: the RBCD path to
  a DC.
- DCSync rights (`DS-Replication-Get-Changes`,
  `DS-Replication-Get-Changes-All`, `DS-Replication-List-Changes`) on the
  domain object: full domain compromise. Membership of `Domain Admins`,
  `Administrators` or `Enterprise Admins` implies them implicitly.

The analysis is offline work on the collected graph, so it costs the client
nothing at the network layer and it can be done before the loud phase. The
dangerous part is not the analysis, it is exercising the path.

## Phase 3 - The loud phase

This phase breaks something. Not always the domain - often just the log
pipeline, the help desk, or a morning shift. Each action below needs the
operator's explicit approval, in writing, before it runs.

### 3.1 The approval list

Present this table to the operator before the loud phase and get a decision
per line. An action that is not approved does not run, and a run that was not
approved is the end of the engagement's usefulness.

| Action | How it runs | What it triggers on the client | Approval |
|---|---|---|---|
| Password spray | `cyber_password_audit` | 4625 and 4771 in bulk, possible account lockout | Required, per service, per window |
| Kerberoasting | `GetUserSPNs` (extended toolchain) | 4769 with RC4 tickets, possible credential exposure | Required |
| Kerberos ticket request | `cyber_ad_attack action: kerberos-ticket-request` | 4769, and a TGT the client did not expect | Required |
| SMB relay listener | `cyber_ad_attack action: smb-relay-setup` | 4624 type 3, 4776, relay alerts in the SIEM | Required |
| NTLM coercion (LLMNR/NBT-NS) | `cyber_ad_attack action: responder-relay` | 4624 type 3 from the coerced host to the listener, EDR alerts | Required, named hosts only |
| Directory replication (DCSync) | `impacket-secretsdump` (extended toolchain) | 4662 with the replication GUID on 389 | Required, named account only |
| SMB share write | `cyber_ad_attack action: smb-share-write` | File creation events on the share | Required, with a cleanup plan |
| ADCS certificate request | certipy / PKINIT (extended toolchain) | 4883 in the CA log, 4768 and 4769 on the DC | Required |
| BloodHound session collection | `cyber_ad_enum collection: sessions bloodhound: true` | One 4624 type 3 per host, 4648 | Required, named hosts only |
| LDAP privilege check | `cyber_ad_attack action: ldap-privilege-check` | 4662 reads on the privileged groups | Recommended, quiet |

Say what each action would do, what the defender sees, and what the client
wins. The client gets a finding they can reproduce and a ticket they can
close. The operator gets a defensible engagement.

### 3.2 The relay test

```
cyber_ad_attack  action: smb-relay-setup  target: dc01.corp.local  domain: corp.local  duration_seconds: 60
cyber_ad_attack  action: responder-relay  target: dc01.corp.local  duration_seconds: 120
```

`smb-relay-setup` runs the rogue SMB server that receives the authentication
a coerced host sends; `responder-relay` poisons LLMNR and NBT-NS so the host
sends it on its own. Both bind the listener locally, so they need root, and
both capture credential material that goes to the engagement artifacts and
never into the transcript.

The test only proves something when the target service allows unsigned or
unconstrained NTLM, so read the effective policy from phase 1 first:

- `Network security: LAN Manager authentication level` - `Send NTLMv2
  response only` blocks the classic downgrade.
- `Network client: Digitally sign communications` - `Always` blocks relay.
- `Restrict NTLM: Outgoing NTLM traffic to remote servers` and the inbound
  NTLM auditing level - these decide whether the coercion even works.
- `Channel binding and signing` on the target service - a service that
  requires channel binding cannot be relayed to.

The finding when it works is critical, and the remediation is straightforward:
require signing, restrict NTLM to local traffic, audit NTLM, and turn on
channel binding where the client can.

The evidence is that a challenge/response was captured and that the target
accepted it. **Never print the captured hash into the transcript.** Record
that a capture occurred, the source host, the target service and the artifact
path.

### 3.3 DCSync and the share enumeration trap

```
cyber_ad_attack  action: smb-share-enum  target: dc01.corp.local  domain: corp.local  username: '<domain>\<account>'
```

Supplying a username to `smb-share-enum` does more than list the shares: it
also runs `impacket-secretsdump` against the domain controller, which is a
directory replication attempt. That is the DCSync action, it needs the
operator's approval like any other loud action, and its output is credential
material that stays in the artifacts. Without a username the action is a
read-only share listing.

A successful sync reproduces the whole directory, including the KRBTGT
account, which is a domain takeover for the next password reset cycle. The
finding is "this principal can replicate the directory", and the remediation
is to move the replication rights to a tier-0 group and remove them from the
account.

### 3.4 Writing to a share

```
cyber_ad_attack  action: smb-share-write  target: dc01.corp.local  share: '<share>'  payload: '<content>'
```

Writing a file is how a share becomes a delivery path. It needs approval, the
client needs to know which file will appear and where, and the file has to be
removed again afterwards. Say in the report exactly what was written and that
it was removed.

### 3.5 Running the loud phase well

- **Announce the window.** Source IP of the operator machine, the account in
  use, the named hosts, the start and end time. The client's SOC closes the
  tickets as a known test.
- **One action at a time.** Run the spray, wait, read the client-side
  confirmation, then run the next. A burst of four loud actions is how a
  client loses trust in the engagement.
- **Stop on the first success that proves the path.** A relay that works does
  not need a second relay. Escalate in scope only with a fresh approval.
- **Leave the environment as you found it.** Remove the rogue listener, remove
  the file written to the share, remove the added group member, delete the
  issued certificate. Say what you cleaned up.

## Detection considerations

An AD assessment that only looks at the domain leaves the client's detection
capability unmeasured, and the client asked for that measurement as much as
for the findings. For every loud-phase action, report what fired:

| Action | Events the defender sees |
|---|---|
| Password spray | 4625 (failed logon), 4771 (pre-auth failed) |
| Kerberoasting | 4769 (service ticket), encryption type `0x17` |
| Kerberos ticket request | 4769 (TGT issued) |
| AS-REP roasting | 4769 for an account with pre-auth disabled |
| NTLM relay | 4624 type 3, 4776 (NTLM authentication attempt) |
| Coercion | 4624 type 3 from the victim host, DNS suffix anomalies |
| DCSync | 4662 with the directory replication GUID, 5136 on the domain object |
| ADCS abuse | 4883 in the CA log, 4768/4769 for a PKINIT request |
| BloodHound session collection | 4624 type 3 (machine accounts), 4648 (explicit credentials) |
| LDAP enumeration | 4662 (directory object reads) in volume |
| SMB share read | 5140 and 5145 |

Then ask the client the questions that make the report actionable:

- Does a rule exist for a spray pattern (many failures across many accounts
  in a short window), and does it fire on 4625 volume alone or only with the
  source IP correlated?
- Is 4769 monitored for RC4 ticket requests? A domain that enforces AES is
  not exposed to kerberoasting, and the monitor should know that.
- Is 4662 monitored for the replication GUID? DCSync is a high-signal event
  with few false positives, and it is usually not monitored.
- Does the EDR treat an outbound NTLM authentication to an unusual address as
  an incident? The coercion test is designed to trip it, and the client needs
  to know that a trip is expected.
- What is the retention on the DC security log, and does the client have the
  4883 CA log?

Report coverage gaps as findings. "Nothing detects a DCSync request" is a
finding with a severity, even when the DCSync itself was not tested.

## Credential hygiene

- **Never print a password, a hash, a ticket or a session cookie into the
  transcript.** Summarise the outcome, name the affected account, and point at
  the artifact file under `.cyberpi/artifacts/`. The credential is evidence,
  and evidence belongs in the engagement directory.
- The same rule applies to the `cyber_ad_attack` captures, to the Kerberos
  ticket it writes, and to any credential recovered by
  `cyber_password_audit`.
- When handing credentials to the client, hand them over through the agreed
  channel, in the artifact, not in the chat transcript and not in the finding
  body.
- Do not reuse a recovered credential to move sideways. A second action with a
  stolen credential is a second loud action.

## Recording results

1. **The journal** - automatic for every `cyber_*` tool. `cyber_journal`
   shows the full action record: command, target, exit code, duration and
   artifact path. Never edit it. The steps that ran outside the registry
   (`GetUserSPNs`, `secretsdump`, certipy) go into `.cyberpi/notes/` with the
   command, the timestamp and the artifact path, so the journal and the notes
   agree.
2. **The surface index** - `.cyberpi/surface.json`. Hosts and services found
   during the port and service scans belong there; read it with
   `cyber_surface` instead of re-scanning the DCs.
3. **Findings** - `.cyberpi/findings/`, written with `cyber_record_finding`.
   A directory dump is not a finding. File findings for:
   - a path from a low-privileged account to Domain Admin, naming the exact
     edge (`GenericAll`, `WriteDacl`, `AddMember`, `Owns`, `WriteSPN`,
     delegation attribute, DCSync rights);
   - an exposed domain administrator or KRBTGT credential;
   - a service account with a cracked password whose account holds privilege;
   - a delegation configuration that allows impersonation to a DC;
   - an ADCS template that lets a low-privileged user authenticate as anyone;
   - NTLM relay or signing misconfiguration on a DC;
   - a domain credential exposed in a repository, share or configuration file;
   - a lockout policy that makes a spray a denial-of-service risk;
   - a detection gap for the action that was tested.

   Each finding carries the concrete path, the verification command and its
   output, and evidence lines that point at artifact files instead of inline
   credentials.

## Handoff

- The domain controller operating system build and the server versions -> the
  CVE phase (`cyber_cve_lookup`, `cyber_exploit_map`, `cyber_cve_sync`).
- Recovered hashes and service account credentials -> the credential phase
  (`cyber_hash_id`, `cyber_hash_crack`). Note that `cyber_password_audit`
  tests credentials; `cyber_secret_scan` finds secrets.
- Exposed hosts and services on the domain member hosts -> the network phase
  (`cyber_portscan`, `cyber_service_scan`), and the ADCS web interface on
  port 9389 to the web phase.
- A path that ends at a specific host -> the privilege-escalation skill for the
  local half of that host, once a session exists.

## When a tool fails

- A non-zero exit is not a finding. Read the stderr before drawing a
  conclusion and report the real error. An LDAP bind that fails with
  `INVALID_CREDENTIALS` against one host and succeeds against another is a
  routing or DNS problem, not a domain weakness.
- "Missing required tool(s)" means the Kali package is not installed. Relay
  the install line and stop that phase; do not imitate the output of a tool
  that did not run.
- Output is truncated for the transcript. The full output is in the artifact
  file the journal points to - read the file when the summary is not enough.
- A refused call is a scope decision. Report it and name the scope line that
  would have to change; do not route around it.
