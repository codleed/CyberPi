---
name: privilege-escalation
description: Escalate privileges on a host where a foothold already exists, from an unprivileged user to root or SYSTEM. Use when asked to gain root, to enumerate sudo, SUID, cron, systemd and PATH misconfigurations, to abuse Windows tokens, privileges, service DACLs and impersonation, to escape a container, or to analyse local file permissions for a write primitive. Covers Linux and Windows, and ends every path with an explicit verification step.
---

# Privilege escalation

Local privilege escalation is a *post-exploitation* activity: you already have a
session on the host, and the goal is a higher-privilege identity on that same
host. The engagement scope authorises the hosts; this skill decides how to
climb inside one.

## How the work is split

CyberPi's `cyber_*` tools are the only things that touch the network, and they
are scope-checked and journalled. They cover the *remote* half of a privilege
escalation assessment: which services are exposed, which CVEs apply, which
exploits exist, and whether a payload you planted answers.

The *local* half runs where the shell is. When the foothold is a session on the
target, run the enumeration commands from `references/privesc-checks.md` inside
that session. When the foothold is the machine the agent is running on (a
self-test, or a container that the target has given you), run them with the
agent's own shell tool.

Rules that apply to both halves:

- Enumerate first, exploit second. Every finding needs the enumeration output
  that supports it.
- Never print raw credentials, session cookies or tokens into the transcript.
  Summarise the credential and point at the artifact file under
  `.cyberpi/artifacts/`.
- Keep network calls on the `cyber_*` tools so the engagement journal stays a
  complete record. A raw `curl` from the shell is invisible to the journal.
- Add the target host to `.cyberpi/scope.json` before pointing `cyber_*` tools
  at it. The loopback address and the local interfaces are allowed by default
  for self-testing.
- Do not run a payload against a host that is not in the scope file, even when
  the exploit is trivially safe. Record the refusal instead.

## Step 0 — establish the context

Never skip this. Most of the escalation surface depends on the identity, the
kernel, the container and the privileges the session actually carries, and the
answers decide which of the later checks are worth running.

On Linux, inside the session:

```bash
id; whoami; groups; umask
uname -a; cat /etc/os-release; cat /proc/version
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)' /proc/self/status
capsh --print 2>/dev/null
ls -l /.dockerenv 2>/dev/null; cat /proc/1/cgroup
```

On Windows, inside the session:

```powershell
whoami /all
whoami /priv
whoami /groups
net localgroup Administrators
systeminfo
```

Record the answers in the engagement notes before continuing. The enumeration
output is the evidence for the finding later.

## Linux path

### 1. Map the escalation surface

Run the enumeration set from `references/privesc-checks.md` for the host:

- SUID, SGID and world-writable binaries (`find / -xdev -perm -4000`).
- `sudo -l` and the contents of `/etc/sudoers` and `/etc/sudoers.d/`.
- systemd units: `FragmentPath`, `ExecStart`, `ExecStartPre`, `User=` and the
  writability of every path the unit touches.
- Cron: `/etc/crontab`, `/etc/cron.d/`, `/var/spool/cron/crontabs/`, timers and
  `at` queues.
- The loader: `/etc/ld.so.preload`, `/etc/ld.so.conf.d/`, and every directory
  on `PATH` that is writable by the current user.
- The filesystem: world-writable files and directories without the sticky bit,
  and permissive ACLs on anything a privileged job reads.

The catalogue lists the exact command for every check.

### 2. Rank the candidates

Rank by reachability, not by novelty:

1. **Direct configuration mistakes** — a `NOPASSWD: ALL` rule, a writable
   service unit, a writable `ld.so.preload`, a cron job running a script the
   current user can rewrite. These are the findings that actually escalate.
2. **Known-exploitable SUID binaries** — a SUID `find`, `vim`, `perl`, `python`,
   `tar`, `rsync`, `env`, `busybox`, `gdb`, `docker` or `systemd-run` gives a
   shell as the owner of the binary, which is usually root.
3. **Kernel and userspace bugs** — map the kernel and glibc versions to CVEs
   with `cyber_cve_lookup` and `cyber_exploit_map`, then look for a working
   exploit with `cyber_exploit_search`. Notable families on modern Linux:
   PwnKit (`CVE-2021-4034`, glibc 2.34–2.35), Dirty Pipe (`CVE-2022-0847`,
   kernel 5.8–5.16), DirtyCred (`CVE-2022-0185`, kernel 5.8–5.17) and
   OverlayFS `CVE-2023-0386` (`kernel 6.2` on unprivileged user namespaces).
   `cyber_cve_sync` refreshes the local CVE database before a lookup.
4. **Container escapes** — see the next step.

### 3. Container escape

When the context shows a container, check the escape surface before anything
else, because it is worth more than any local bug:

- Docker socket mounted at `/var/run/docker.sock` — a write to it is a host
  root shell.
- `CAP_SYS_ADMIN` in `capsh --print`, which turns the container into a host
  namespace entry point via `nsenter -t 1 -m -u -i -n -p`.
- A writable `/proc/sys/kernel/core_pattern` or a writable cgroup v1
  `release_agent`, or cgroup v2 `notify_on_release`.
- Host paths bind-mounted inside the container, and `/proc/1/root` as a way
  back to the host filesystem.
- `CAP_SYS_MODULE`, which allows loading a kernel module.
- A container runtime with a known escape CVE — look it up with
  `cyber_cve_lookup` against the runtime version.

### 4. Build the write primitive

Turn the configuration mistake into an action. A writable service file becomes
a replaced unit; a writable cron script becomes an edited command; a writable
`PATH` entry becomes a planted binary; a writable `ld.so.preload` becomes an
injected library.

Keep the write primitive minimal and reversible: write to a temporary file
first, confirm the write landed, then move to the privileged path.

### 5. Verify — Linux

The escalation is only a finding when the identity actually changed. Confirm
all of the following, in the escalated session:

```bash
id                      # expect uid=0(root) gid=0(root)
sudo -n id              # for a sudo-rule escalation
cat /etc/shadow | head -3
capsh --print | grep cap_sys_admin
```

For a container escape, confirm the identity belongs to the *host*, not the
container:

```bash
cat /proc/1/root/etc/os-release
nsenter -t 1 -m -u -i -n -p -- id
```

For a write primitive that is not yet an escalation, confirm the write landed
and that the privileged consumer picked it up:

```bash
ls -l /path/to/the/planted/file
journalctl -u <unit> --since "-5 min" --no-pager
```

Record the verification command and its output in the finding. A primitive
without a verified escalation is a finding in its own right, at lower
severity.

## Windows path

Windows escalation runs in two places. The remote half is done from the Kali
box with the `cyber_*` tools; the local half runs in the session you already
have on the Windows host.

### 1. Remote half — from Kali

Enumerate the Windows attack surface with the service scanner, using the NSE
script families that apply to Windows: `smb-os-discovery`, `smb2-security-mode`,
`smb-vuln-ms17-010`, `smb-vuln-ms08-067`, `smb-enum-users`, `rpc-enum` and the
`vuln` family. `cyber_portscan` first tells you which of the Windows
management ports are open at all: SMB 445, WinRM 5985/5986, RDP 3389, RPC 135,
LDAP 389/636 and MSSQL 1433.

```text
cyber_portscan      -> which management ports are reachable
cyber_service_scan  -> service versions and the NSE script results
cyber_http_probe    -> local web services that may run a writable script path
cyber_vuln_scan     -> template coverage for the exposed services
```

Look for the two remote clues that change the local plan: a **known
vulnerable service version** and a **writable or misconfigured share**. Map the
OS build and the service versions to CVEs with `cyber_cve_lookup` and
`cyber_exploit_map`, and search for public exploits with
`cyber_exploit_search`.

### 2. Local half — inside the Windows session

Run the Windows checks from `references/privesc-checks.md`:

- **Service configuration** — `sc.exe qc <service>` and
  `wmic service get Name,PathName,StartName` for unquoted paths, relative
  paths, and binaries in a directory the current user can write.
- **Service and object DACLs** — `sc.exe sdshow <service>` and `icacls` for
  `(A;;RPWPWL;;;WD)`-style entries that let a non-admin rewrite a service that
  runs as SYSTEM.
- **Registry and policy** — `EnableLUA`, `ConsentPromptBehaviorAdmin`,
  `AlwaysInstallElevated`, `fodhelper.exe` and `computerdefaults.exe`
  hijack keys, and the auto-run keys.
- **Token and impersonation** — `whoami /priv` for `SeImpersonatePrivilege`,
  `SeAssignPrimaryTokenPrivilege`, `SeCreateTokenPrivilege`,
  `SeTcbPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`,
  `SeLoadDriverPrivilege` and `SeDebugPrivilege`. These are the privileges the
  potato family, `ntdsutil` credential extraction and driver loading abuse.
- **Impersonation sinks** — a privileged service that creates a named pipe in
  a world-writable path, a writable service directory, and the print-spooler
  and COM object paths that the classic impersonation tools use.
- **Credential material** — Group Policy Preferences `Groups.xml` and
  `Groups.csv` under `%SystemRoot%\System32\mssecsvc\Groups`, `gpt.ini` in the
  user profile, and any service or config file with an embedded password.
  Extract with `cyber_secret_scan` where the file is on a reachable share, and
  never print the recovered value into the transcript.
- **Writable paths** — `%TEMP%`, `C:\Windows\Temp`, service working
  directories, and any directory on the DLL search path of a privileged
  process.

### 3. Build the write primitive

The Windows write primitives are: replacing a service binary, replacing or
hijacking a DLL in a service's search path, hijacking a COM object or a
registry key that a privileged process reads, planting an MSI that
`AlwaysInstallElevated` will elevate, or abusing an impersonation sink to
borrow a SYSTEM token.

### 4. Verify — Windows

Do not report a Windows escalation until the token is proven:

```powershell
whoami /groups | findstr /i "S-1-5-32-544"
whoami /priv
net localgroup Administrators
net session
```

`S-1-5-32-544` (BUILTIN\Administrators) shown as an *enabled* group and
`net session` succeeding are the two signals that the token is high integrity.
`whoami` returning only `High Mandatory Level` with no enabled admin group is
not an escalation.

For a write primitive that is not yet an escalation, confirm the write landed
and that the privileged consumer picked it up:

```powershell
sc.exe qc <service>
dir C:\Windows\Temp\<planted-file>
```

For a web or HTTP service, use `cyber_poc` to confirm the planted content is
served, and for an HTTP-triggered exploit, use `cyber_poc` to confirm the
response shows the escalated identity.

## Validating a write primitive with `cyber_poc`

`cyber_poc` drives `curl` against a URL you name, and it is the fastest way to
close the loop on a write primitive:

- Planted web shell or script in a web root — request it through `cyber_poc`
  and confirm the response body shows the expected command output.
- Hijacked library or replaced service binary behind an HTTP endpoint — trigger
  the endpoint with `cyber_poc`, then confirm the side effect on the host.
- Replaced binary behind an HTTP/management service — confirm the service now
  answers with the new behaviour through `cyber_poc`.

`cyber_poc` is scope-checked, so the target host must be in
`.cyberpi/scope.json`. A refusal is a scope decision, not a tool failure: add
the host to the scope file when the client authorised it.

## Close out

- Record the finding with `cyber_record_finding`: the misconfiguration, the
  exact primitive, the verification command, and the verification output.
- Keep credentials out of the transcript. Point at the artifact file instead.
- `cyber_journal` shows the full action record for the engagement; use it to
  confirm the escalation attempt is documented.

Read `references/privesc-checks.md` for the concrete command behind every
check named above.
