---
description: Run an Active Directory assessment and summarise the domain privilege paths
argument-hint: "[domain]"
---
Assess the Active Directory environment at ${1:-the domain in the engagement scope} and map the privilege paths through it.

## Arguments

- Domain: $1
- Extra instructions: $@

## Steps

1. `cyber_ad_enum` - enumerate the directory: domains, forests, trusts, users, groups, computers, service principals, group memberships, ACLs and the domain controllers themselves. Put the domain name in `domain` and the address of the controller in `target`, then choose what to collect with `methods` and `collection`.
2. `cyber_service_scan` - probe the domain controllers and any hosts the enumeration surfaced, to see which of LDAP, Kerberos, SMB, WinRM and RDP are actually reachable from here.
3. `cyber_cve_lookup` - check the Windows, Exchange and SQL versions that step 1 and step 2 found against the local CVE database, so you know which of the observed services are known-vulnerable.
4. `cyber_ad_attack` - only for an enumeration the operator has explicitly approved. This tool can relay traffic and impersonate hosts, so it is not a passive step. Ask for approval that names the target, pick the `action` you need, and use the least invasive form of it that still proves the path.
5. `cyber_record_finding` - record each privilege path as a finding: the source principal, the path (the group nesting or the ACL that grants it), the sink it reaches, and the evidence.

## Rules

- Use only the CyberPi tools named above. Do not run ldapdomaindump, impacket scripts, bloodhound or responder yourself.
- Do not create accounts, change group membership or modify any directory object. Report the path, do not walk it.
- If a call is refused by the engagement scope, report the refusal and continue with the rest of the assessment.
- Keep credential material out of the transcript. Point at the artifact file instead.

## Report back

- The domain topology: the domain controllers, the trusts, and the counts of users, groups, computers and service accounts.
- The privilege paths, ordered from the shortest path to domain admin.
- The accounts that look like escalation targets: privileged group members, service accounts with interactive logon rights, stale accounts carrying privileged ACLs, accounts with weak password policy, and accounts whose passwords never expire.
- The domain password policy and anything that weakens it.
