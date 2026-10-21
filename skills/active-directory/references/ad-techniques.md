# Active Directory technique reference

Per-technique detail for the `active-directory` skill. Each entry states what the
technique proves, how CyberPi exercises it, the evidence worth keeping, what the
client's defenders will see, and the finding it produces when it succeeds.

Tool names below are the registry names (`docs/TOOL-REGISTRY.md`). The tool
schemas published in the current session are authoritative for parameter
names; the arguments shown are the usual ones.

| Tool | Technique tag | Binary | Notes |
|---|---|---|---|
| `cyber_ad_enum` | `active-directory` | ldapdomaindump | `methods` = ldap, smb, dns; `collection` = users, groups, computers, trusts, sessions, acl, all; `bloodhound: true` collects the graph |
| `cyber_ad_attack` | `active-directory` | impacket-smbserver | `action` = smb-share-enum, smb-share-write, smb-relay-setup, responder-relay, kerberos-ticket-request, ldap-privilege-check |
| `cyber_password_audit` | `password-audit` | hydra | `service` = ssh, ftp, smtp, http-post, http-get, ssh-key |
| `cyber_secret_scan` | `password-audit` | trufflehog, gitleaks | `path` is a directory, a file or a repository |

---

## 1. Domain discovery and layout

**What it proves.** Where the domain lives, which hosts are domain controllers,
which domain controllers are also DNS servers, what the forest looks like, and
whether the perimeter team exposed anything that should not have been.

**Technique IDs.** T1016, T1018, T1069.001, T1482, T1087.002.

**How to test it.**

- DNS SRV records are the cheapest reliable source. `_ldap._tcp.dc._msdcs.<domain>`
  lists the domain controllers; `_kerberos._tcp.dc._msdcs.<domain>` lists KDCs;
  `_kerberos._tcp.<domain>` lists the KDCs of the domain itself.
  `cyber_ad_enum target: <dc> domain: <domain> methods: dns` reads the
  `_ldap._tcp` and `_kerberos._tcp` SRV records, the name servers, the PTR
  record and the LDAP rootDSE in one run.
- A zone transfer (`AXFR`) on the domain's DNS server discloses the whole zone,
  including records for hosts that are not in the asset register.
- Compare what DNS publishes against the client's asset inventory. The gap is
  the finding.

**Evidence.** The SRV records, whether AXFR succeeded, and the list of
discovered names that the client did not list.

**Defender view.** Ordinary recursive DNS queries. A zone transfer succeeding is
loud and is usually its own finding (unnecessary exposure).

---

## 2. LDAP enumeration

**What it proves.** The contents of the directory: users, groups, computers,
organizational units, group membership, and the attributes that later attacks
depend on.

**Technique IDs.** T1087.002, T1069.002, T1018.

**How to test it.** `cyber_ad_enum target: <dc> domain: <domain>
collection: all` runs the LDAP inventory against a domain controller. The
`collection` parameter narrows it to `users`, `groups`, `computers`,
`trusts`, `sessions` or `acl`; ACL collection needs elevated rights, so an
empty ACL set is a statement about the engagement account, not about the
domain.

`cyber_ad_attack action: ldap-privilege-check target: <dc> domain: <domain>`
is the focused version: it lists the members of Domain Admins, Enterprise
Admins, Schema Admins, Backup Operators, Account Operators and DnsAdmins and
resolves SIDs with `impacket-lookupsid`.

Read the results as structure, not as a flat list:

- Users with a `userPrincipalName` are Kerberos principals.
- Users whose `userAccountControl` has `0x100000` (normal, non-temporary) set
  are candidates for password spraying.
- Groups with the primary group id 512 (`DOMAIN Admins`) or 519 (`Enterprise
  Admins`) are tier-0 targets.
- Service accounts in `msDS-AllowedToDelegateTo` are delegation targets.
- `msDS-User-Account-Control-Computed` shows `DONT_REQ_PREAUTH` accounts.

**Evidence.** Counts per object class, the list of tier-0 group members, and
the list of accounts that carry delegation attributes.

**Defender view.** One LDAP bind per run plus a series of search requests. A
single directory dump is visible to anyone reviewing DC logs, but it is not
alarming on its own. Anonymous binds that succeed are worth reporting.

---

## 3. SMB share review and session enumeration

**What it proves.** Which shares exist, which of them are readable without
credentials, which host shares (`ADMIN$`, `C$`) are exposed, and whether the
current session has already been handed a privileged token.

**Technique IDs.** T1135, T1021.002, T1557.001 (as a precondition).

**How to test it.**

- Anonymous share listing: `cyber_ad_enum target: <dc> methods: smb`, which
  runs netexec or crackmapexec, `smbclient -N -L` and `smbmap`.
- Authenticated listing: `cyber_ad_attack action: smb-share-enum target: <dc>
  username: '<domain>\<account>'`. Supplying a username also triggers a
  `secretsdump` run, so treat it as a loud action, not as a share listing.
- Anonymously accessible shares are the finding; a share named `Users$` or
  `Public` on a server is normal.
- `C$` and `ADMIN$` reachable without credentials means anonymous
  administrative share access, which is critical.
- Check for the IPC$ named pipe `srvsvc`, `winreg`, or `samr` on the target;
  those pipes are the ones NTLM relay targets.

**Evidence.** The share list per host and which of them were readable
anonymously. Do not copy file contents into the transcript; record the path and
point at the artifact file.

**Defender view.** Anonymous share access generates 5140/5145 events with an
anonymous or guest account. Authenticated share access generates 5145 with the
account used.

---

## 4. Kerberos analysis

**What it proves.** Which accounts have service principals, which accounts can
request a service ticket without pre-authentication, and which accounts are
trusted to delegate — the three conditions that turn a password into a ticket
and a ticket into a domain controller.

**Technique IDs.** T1558.003 (kerberoasting), T1558.004 (AS-REP roasting),
T1134.005, T1649.

**How to test it.**

- **Service principals.** For every user, the `SPN` attribute. SPNs ending in
  `MSSQLSvc`, `Http`, `host`, `cifs` or `exchangemdb` on a user account are
  kerberoastable.
- **AS-REP roastable.** Accounts with `DONT_REQ_PREAUTH` can get a TGT without
  a password, so a hash can be requested and cracked offline.
- **Unconstrained delegation.** `msDS-AllowedToDelegateTo` on a *user* means
  that user can impersonate to any service. `msDS-AllowedToDelegateTo` on a
  *computer* account is the normal case; on a user it is a finding.
- **Constrained delegation.** `msDS-AllowedToDelegateTo` set to a privileged
  target such as a domain controller's CIFS or HOST service allows a ticket to
  be obtained for that service, which is a direct path to DC compromise.
- **Resource-based constrained delegation (RBCD).** A user or group holding
  `msDS-AllowedToDelegateTo` on a computer account can impersonate to anything
  that computer authenticates to. Look for write access to that attribute.

**Evidence.** The list of SPNs, the list of AS-REP roastable accounts, and the
full delegation matrix (principal -> delegation target).

**Defender view.** Kerberoasting shows up as event 4769 (service ticket
requested) with ticket encryption type `0x17` (RC4-HMAC) and a short lifetime.
A domain controller that only issues AES tickets makes the attack useless, so
the client's Kerberos policy is the first thing to check and the most common
remediation.

---

## 5. Password spraying and credential attacks against domain services

**What it proves.** Whether a single password works across many accounts
against LDAP, SMB, or an HTTPS service, and whether the lockout policy turns a
spray into a denial of service.

**Technique IDs.** T1110.003, T1110.002, T1078 (valid accounts).

**How to test it.**

- `cyber_password_audit` runs the credential attempt with hydra. Its service
  modules are ssh, ftp, smtp, http-post, http-get and ssh-key, so it audits
  the services the engagement exposed - an SMB or LDAP front end, a mail
  gateway, an administrative web login.
- **The domain-native services are a separate step.** An LDAP bind spray or an
  SMB session spray is not one of the modules the wrapper exposes. Run it
  with the extended toolchain (`netexec`, or a targeted bind test) against a
  domain controller the scope covers, with the operator's approval and a note
  in the engagement record.
- **Spray, do not brute force.** One password against many accounts, a small
  password set against one account. Brute force against a domain account is a
  denial-of-service vector against the whole domain, because the account lockout
  policy is per account but the security group's failed-logon counters are
  often global.
- **Watch the lockout policy first.** Ask the client for the domain lockout
  policy before the first attempt. If there is a global lockout
  (`LockoutThreshold` with `ResetCount`), a spray can lock out accounts and
  interrupt the client's business. If so, the operator must approve the spray
  in writing and the run must be slow enough to stay under the threshold.
  Set `rate_limit` low and `threads` to 1 or 2, and turn `stop_on_success`
  off so the run reports every account that accepted a credential instead of
  stopping at the first.
- Never print a recovered password into the transcript. The tool summarises the
  outcome; the credential itself stays in the artifact file, and the finding
  reports the affected account and the credential class, not the value.

**Evidence.** Which service was sprayed, how many attempts, the lockout policy
that applied, and which accounts accepted a credential (identified by account
name only).

**Defender view.** 4625 (`An account failed to log on`) in bulk, and 4771
(pre-authentication failed) for Kerberos. This is the phase that pages a SOC.
See "Detection and coordination" below for what to tell the client before
running it.

---

## 6. Privilege and ACL path analysis

**What it proves.** The shortest path from the accounts the engagement can
obtain to a domain administrator, and which misconfigured ACL makes it short.

**Technique IDs.** T1098 (account manipulation), T1222.001, T1098.003, T1134.002, T1069.

**How to test it.**

The graph is the evidence. Collect it, then reason about the edges:

- `GenericAll` on a user, group or computer: full control, add yourself to
  the group.
- `GenericWrite` on a user: set `memberOf`, `scriptPath`, or a logon script.
- `WriteDacl` on a user or group: rewrite the permission and take over.
- `AddMember` / `AddSelf` edges to tier-0 groups.
- `Owns` the domain object, the `Domain Admins` group, or a DC computer
  account.
- `WriteSPN` plus a known password: add an SPN and kerberoast the account.
- `WriteDacl` on a computer account plus delegation rights: the RBCD path to
  a DC.
- DCSync rights (`DS-Replication-Get-Changes`, `DS-Replication-Get-Changes-All`,
  `DS-Replication-List-Changes`) on the domain object: full domain
  compromise. Membership of `Domain Admins`, `Administrators`, or
  `Enterprise Admins` implies these rights implicitly.

**How to test it.** Path analysis is offline work on the collected graph, so it
costs the client nothing at the network layer and can be done in the loud
phase. The dangerous part is not the analysis, it is exercising the path.

**Evidence.** The concrete path, node by node, with the exact edge that grants
control. A report that says "user A can reach Domain Admins" without naming
the edge is not a finding.

**Defender view.** ACL analysis itself is invisible. Every *use* of the path is
not: see technique 9.

---

## 7. Delegation and ADCS abuse

**What it proves.** Whether the domain's certificate infrastructure can be used
to obtain a Kerberos ticket for any account, and whether the delegation
configuration lets a low-privileged account impersonate to a domain controller.

**Technique IDs.** T1649 (steal or forge authentication certificates),
T1606.002, T1134.005, T1558.003.

**How to test it.**

- **Enumerate the CAs.** Find the CA host, list the templates published in the
  `Certificate Templates` container, and note which of them have enrollment
  permissions that a low-privileged user holds.
- **ESC1** — a template that a user can enroll with and that allows client
  authentication with a supply-controlled subject alternative name (the UPN
  extension) produces a certificate that authenticates as any user, including
  a domain administrator.
- **ESC3** — enrollment with an arbitrary template id and supply-controlled
  SAN on templates that require enrollment rights but not the right to set that
  SAN.
- **ESC4** — abuse of the Certificate Enrollment Agent (CEP) service by a user
  who can write the `msPKI-Certificate-Name-Flag` attribute.
- **ESC6** — a template with `ENROLLEE SUPPLIES SUBJECT` and `EDIT PERMISSIONS`
  over the SAN.
- **ESC7 / ESC8** — weak enrollment agent permissions, or a CA whose
  `msPKI-Enrollment-CSP` or issuance policies can be altered by a low-privileged
  user.
- **PKINIT** — a certificate plus a private key held by a low-privileged
  account allows a Kerberos request for any user, which is why a certificate
  found in a repository is a domain-takeover finding.
- **Delegation** — unconstrained delegation to a domain controller, or
  constrained delegation with a privileged target, is the classic path.

**Evidence.** The template CN, its configuration (`msPKI-*` attributes), the
principal that holds the enrollment right, and the CA host.

**Defender view.** Certificate issuance is logged (4768, 4769, 4883 in the CA
log), and PKINIT appears as a Kerberos TGT request with the `cname` flag.
Enrolling as an administrator is not noisy, but the resulting privilege is
total, so report it as critical even when it was quiet.

---

## 8. BloodHound graph collection

**What it proves.** The relationships that make privilege escalation possible,
collected in one pass so that the analysis does not have to touch the domain
again.

**Technique IDs.** T1087.002, T1069.

**How to test it.**

- Collect the graph with `cyber_ad_enum target: <dc> domain: <domain>
  bloodhound: true collection: acl`, which runs `bloodhound-python` against
  the domain controller and writes the result into the engagement artifacts.
  `SharpHound` on Windows produces the same data.
- Collection types matter:
  - `Session` — who is logged in where; needs to run on hosts, not the DC.
  - `Group` — group membership of all principal types.
  - `ACL` — the dangerous one: security descriptors, delegation attributes,
    DCSync rights.
  - `Container` — computer object ownership, useful for the "Owns" edge.
- Prefer `Group`, `ACL` and `Container` against the DC. They cover the path
  analysis that matters and are a single read from the domain.
- Do not run `Session` collection across the estate during the quiet phase. It
  authenticates as every machine account and produces a burst of logon events.
- The graph file stays on the operator's machine. Import it into the BloodHound
  GUI or query it with `bloodhound-python` locally; do not upload it to a
  third-party instance without the client's written consent — it contains the
  entire privileged graph of their domain.

**Evidence.** The collection type, the timestamp, the size of the graph, and
the list of high-value edges found offline.

**Defender view.** Collection is an LDAP bind plus directory reads, so it is
mostly invisible except as a single high-volume read. The important thing to
tell the client is that the data never leaves their infrastructure.

---

## 9. NTLM relay, coercion and the loud phase

**What it proves.** Whether an authentication to a service can be relayed to a
domain controller, which is the difference between one compromised account and
a compromised domain.

**Technique IDs.** T1187 (forced authentication), T1557.001, T1557.002, T1021.002, T1021.006.

**How to test it.**

- `cyber_ad_attack action: smb-relay-setup target: <dc> domain: <domain>
  duration_seconds: 60` runs the rogue SMB server (impacket
  `impacket-smbserver`) that captures the NTLM challenge/response a coerced
  host sends.
- `cyber_ad_attack action: responder-relay target: <dc>
  duration_seconds: 120` poisons LLMNR and NBT-NS so the host authenticates
  to the attacker on its own. This is the noisiest action in the whole
  engagement: it makes the host send an outbound authentication to an address
  it does not trust, which many EDR products treat as a high-severity event.
- `cyber_ad_attack action: kerberos-ticket-request target: <dc>
  username: <account> payload: <password-or-hash>` requests a ticket for an
  account with impacket-ticketer and writes it to the artifacts as a `.kirbi`
  file. It is the tool for a ticket-based escalation (pass the ticket, not the
  password) and for confirming a cracked credential.
- Both listeners bind on the operator's machine, so they need root, and both
  capture credential material that stays in the artifacts.
- The relay test only proves something when the target service allows
  unsigned or unconstrained NTLM. Check the effective settings first:
  `Computer Configuration -> Policies -> Windows Settings -> Security Settings
  -> Local Policies -> Security Options` for
  `Network security: LAN Manager authentication level`,
  `Network client: Digitally sign communications`, and
  `MSFT settings for the LSA server` (`NoLmHash`).
- **DC protections to test:** `Restrict NTLM: Outgoing NTLM traffic to remote
  servers`, `Incoming NTLM` (NTLM auditing / `LmCompatibilityLevel`),
  `NTLM restrictions`, and `Channel binding / signing requirements`.
- If the relay succeeds, the finding is critical and the remediation is
  straightforward: require signing, restrict NTLM to local traffic, and audit
  NTLM.

**Evidence.** The captured challenge/response existence (never the hash or the
password), the target service, and the effective NTLM policy of the target.

**Defender view.** 4624 (logon type 3) from the source host to the attacker's
listener, 4776 (NTLM authentication attempt), and on the defender side an
explicit `NTLM relay` alert. Expect the client's EDR to fire.

---

## 10. Detection and coordination

**The rule.** Every action in the loud phase is announced to the client before
it runs, and the window is agreed in writing. A pentest that pages the SOC at
3am is a failed engagement even when every technique worked.

**What to request from the client before the loud phase.**

- The domain lockout policy, and the `Netlogon`/Kerberos policy.
- The NTLM policy and the SMB signing requirements on the domain controllers.
- A copy of the relevant event logs for the test window: 4624, 4625, 4648,
  4662 (directory replication), 4672, 4720, 4728, 4732, 4768, 4769, 4771,
  4776, 5136, 5140, 5145.
- The EDR/SIEM contact who will acknowledge the test window, and the ticket
  number the alerts should be filed under.
- A test account in a dedicated group with a known password, unless the
  engagement is explicitly testing real credentials.

**Event mapping for the noisy actions.**

| Action | Events | Note |
|---|---|---|
| Password spray | 4625, 4771 | Volume is the signal; one failure is noise |
| Kerberoasting | 4769 (RC4, `0x17`) | Missing if the client enforces AES |
| AS-REP roasting | 4769 with pre-auth disabled | Rare |
| Kerberos ticket request | 4769 (TGT issued) | `cyber_ad_attack action: kerberos-ticket-request` |
| NTLM relay | 4624 type 3, 4776 | Usually EDR alerts as well |
| Coercion | 4624 type 3 from the victim host | `cyber_ad_attack action: responder-relay` |
| DCSync | 4662 with the replication GUID on 389 | High-signal, few false positives |
| ADCS abuse | 4883 (CA), 4768/4769 (PKINIT) | Certificate issuance is logged |
| BloodHound session collection | 4624 type 3 (machine accounts), 4648 | One per host |
| ACL enumeration | 4662 (directory reads), 5136 | Volume of directory reads |
| SMB share read | 5140, 5145 | Quiet unless the share is sensitive |

**The DCSync trigger.** `cyber_ad_attack action: smb-share-enum` with a
username also runs `impacket-secretsdump` against the domain controller. That
is a directory replication attempt, not a share listing, and it has to be
approved like any other loud action.

**What to hand back.** The agreed test window, the account used, the source IP
of the operator machine, and the list of expected alert signatures, so the
client's SOC can close the tickets as a known test rather than escalating
them.

---

## 11. Credential hygiene

- Never print a password, a hash, a ticket or a session cookie into the
  transcript. Summarise the outcome, name the affected account, and point at
  the artifact file in `.cyberpi/artifacts/`.
- `cyber_secret_scan` finds committed credentials in the client's source
  repositories, configuration and cloud configuration files. A domain
  administrator's password in a git history is a domain-takeover finding.
- Secrets found in a repository are reported by location and type; the value
  itself stays in the artifact and is handed over through the agreed channel.
- Use `cyber_password_audit` for credential testing, and use it only against
  services inside the authorized scope and only at the rate the client agreed.
  Its service modules are ssh, ftp, smtp, http-post, http-get and ssh-key; an
  LDAP or SMB spray is an extended toolchain step with its own approval.
