# Privilege escalation check catalogue

Every check in this file is a command with the finding it produces. Run the
Linux checks inside the session on the Linux host, the Windows checks inside the
session on the Windows host, and the remote checks from the Kali box through
the `cyber_*` tools.

Notation: `$` marks a prompt line, `#` a comment, and every command is safe to
run read-only.

---

## 1. Linux — context and privilege

| Check | Command | What to look for |
|---|---|---|
| Identity | `id; whoami; groups` | The baseline. Everything else is judged against this. |
| Umask | `umask` | `0000` or `0002` widens what the session can create. |
| Kernel | `uname -a; cat /proc/version` | Exact kernel release — the input to the CVE lookup. |
| Distro | `cat /etc/os-release` | Distro and version; ties to the package CVEs. |
| Capabilities | `grep -E '^Cap' /proc/self/status` | `CapEff` bits. `CapBnd` is the ceiling. |
| Capabilities (readable) | `capsh --print` | `cap_sys_admin=ep` alone is an escalation. |
| Container | `ls -l /.dockerenv; cat /proc/1/cgroup` | A cgroup path with `docker`/`kubepods`/`containerd` means you are in a container. |
| Namespace | `ls -l /proc/self/ns/` | `mnt`, `pid`, `user` namespace identity. |
| Mounts | `cat /proc/self/mountinfo \| head -30` | Host bind mounts, `/proc/1/root`, overlay roots. |

## 2. Linux — sudo

| Check | Command | What to look for |
|---|---|---|
| Rules for this user | `sudo -l` | `NOPASSWD: ALL` is a direct finding. `sudoedit` is an arbitrary root file write. |
| Rules for another user | `sudo -l -U <user>` | Only useful if the current user can query it. |
| Sudoers file | `cat /etc/sudoers` | `!` negations — a negated command is bypassable with a shell or a path prefix. |
| Sudoers drop-ins | `ls -la /etc/sudoers.d/; cat /etc/sudoers.d/*` | A drop-in the current user can write is a root escalation. |
| Wildcard sudoers | `grep -nE '\*|ALL' /etc/sudoers /etc/sudoers.d/*` | `(ALL) NOPASSWD: /bin/vi *` style entries are command injection, not a restriction. |
| Group membership | `groups` | Membership in `sudo`, `admin`, `wheel`, `lxd`, `docker` is itself a privilege. |

## 3. Linux — SUID, SGID and capabilities on binaries

| Check | Command | What to look for |
|---|---|---|
| SUID | `find / -xdev -type f -perm -4000 2>/dev/null` | Anything owned by root with the setuid bit. |
| SGID | `find / -xdev -type f -perm -2000 2>/dev/null` | Group-root binaries; escalation depends on the group. |
| SUID+SGID | `find / -xdev -type f -perm -6000 2>/dev/null` | Highest-value set. |
| SGID directories | `find / -xdev -type d -perm -2000 2>/dev/null` | A SGID directory lets the user create files with the directory's group. |
| File capabilities | `getcap -r / 2>/dev/null` | `cap_sys_admin`, `cap_dac_override`, `cap_setuid` on a reachable binary. |
| Known-exploitable SUID | `find / -xdev -type f -perm -4000 2>/dev/null \| grep -E '/(find\|vim\|nano\|vi\|less\|more\|man\|perl\|python\|ruby\|tar\|zip\|gzip\|rsync\|env\|busybox\|gdb\|dash\|bash\|awk\|ed\|ftp\|socat\|docker\|systemd-run\|chfn\|chsh\|newgrp\|passwd\|su\|mount\|umount\|flock\|pgrep\|dpkg\|apt-get)$'` | `find -exec /bin/sh -p \;`, `vim -c ':!/bin/sh'`, `tar -cf /dev/null x --checkpoint=1 --checkpoint-action=exec=id`, `rsync` with a crafted module path, `env` on an arbitrary program, `perl -e 'exec ...'`, `python` on a script, `gdb -p`, `systemd-run` — all give a shell as the binary owner. |

## 4. Linux — systemd services

| Check | Command | What to look for |
|---|---|---|
| Enabled units | `systemctl list-unit-files --type=service --state=enabled` | The service inventory. |
| Unit definition | `systemctl show <unit> -p FragmentPath -p ExecStart -p ExecStartPre -p ExecStartPost -p User -p ExecStart` | `User=` is not root but the unit still runs privileged. |
| Unit file | `cat $(systemctl show <unit> -p FragmentPath --value)` | The unit file itself. |
| Writable unit file | `ls -l $(systemctl show <unit> -p FragmentPath --value)` | A world- or user-writable `FragmentPath` is a root escalation. |
| Drop-ins | `ls -la /etc/systemd/system/*.d/ /run/systemd/system/*.d/ 2>/dev/null` | A writable drop-in overrides the unit. |
| `ExecStart` path abuse | `systemctl show <unit> -p ExecStart --value` | A relative program name, a missing absolute path, or a `~` in the path is a hijack. |
| `ExecStart` script | `systemctl show <unit> -p ExecStart --value \| grep -oE '/[^ ]+\.sh'` | A script the current user can rewrite is executed as the unit's user. |
| Reload and run | `systemctl daemon-reload; systemctl restart <unit>` | The write primitive. `daemon-reload` picks up the edited unit. |

## 5. Linux — cron, timers and `at`

| Check | Command | What to look for |
|---|---|---|
| System crontab | `cat /etc/crontab` | `PATH=` lines and the commands run as root. |
| Cron drop-ins | `ls -la /etc/cron.d/; cat /etc/cron.d/*` | A cron file the current user can write. |
| User crontabs | `ls -la /var/spool/cron/crontabs/; crontab -l` | The current user's jobs and their permissions. |
| Cron output | `cat /var/spool/cron/crontabs/<user>` | Readable user crontabs. |
| Timers | `systemctl list-timers --all` | A timer whose unit is writable. |
| `at` queue | `atq` | Queued jobs owned by root. |
| Cron script perms | `ls -l /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/` | Scripts in a writable directory. |
| Wildcard in cron | `grep -R '\*' /etc/crontab /etc/cron.d/ /var/spool/cron/crontabs/ 2>/dev/null` | A `*` in the command field is an injection point when the file is writable. |

## 6. Linux — PATH, environment and the dynamic loader

| Check | Command | What to look for |
|---|---|---|
| PATH | `echo $PATH` | The list. |
| Writable PATH entries | `ls -ld $(echo $PATH \| tr ':' ' ')` | Any directory the current user can write is a hijack target. |
| Relative PATH entries | `echo $PATH \| tr ':' '\n' \| grep -v '^/'` | A relative entry resolves against the working directory of a privileged job. |
| `ld.so.preload` | `cat /etc/ld.so.preload; ls -l /etc/ld.so.preload` | A writable preload file injects a library into every process, including suid. |
| `ld.so.conf.d` | `ls -la /etc/ld.so.conf.d/; cat /etc/ld.so.conf.d/*` | A writable entry adds a library directory, then `ldconfig` re-links the cache. |
| Library cache | `ldconfig -p \| head -30` | The libraries every binary resolves. |
| Environment | `env` | `LD_PRELOAD`, `LD_LIBRARY_PATH`, `IFS`, `BASH_ENV` inherited into a privileged script. |
| Shell profile | `cat ~/.bashrc ~/.profile 2>/dev/null` | A profile the current user can write is executed by the next login of that user. |
| Root shell rc | `ls -l /root/.bashrc /root/.profile 2>/dev/null` | Writable only when the session is already root. |

## 7. Linux — filesystem permissions

| Check | Command | What to look for |
|---|---|---|
| World-writable files | `find / -xdev -type f -perm -002 2>/dev/null \| head -50` | Files any user can replace, especially inside a service directory. |
| World-writable dirs, no sticky | `find / -xdev -type d -perm -002 ! -perm -1000 2>/dev/null` | A world-writable directory without the sticky bit lets the user delete other users' files. |
| Group-writable | `find / -xdev \( -type f -o -type d \) -perm -020 2>/dev/null \| head -50` | Group-writable paths that a privileged group member can abuse. |
| ACLs | `getfacl -R <path> 2>/dev/null` | `user:<name>:rwx` entries and a permissive default ACL. |
| Service working dir | `systemctl show <unit> -p WorkingDirectory --value` | The directory a privileged process writes into. |
| Temp directories | `ls -ld /tmp /var/tmp /dev/shm` | World-writable staging areas. |
| SSH keys | `ls -la ~/.ssh/ 2>/dev/null; cat ~/.ssh/authorized_keys 2>/dev/null` | The `authorized_keys` file grants a login without any credential. |
| Shell rc and profile | `ls -l ~/.bashrc ~/.profile ~/.bash_profile 2>/dev/null` | Writability of the files a login shell sources. |

## 8. Linux — kernel and userspace vulnerabilities

Map the versions from section 1 to CVEs, then look for a working exploit.

| Step | Tool | Purpose |
|---|---|---|
| Refresh the local database | `cyber_cve_sync` | Pulls NVD, CISA KEV and EPSS into the offline SQLite database. |
| Map a version to CVEs | `cyber_cve_lookup` | Kernel, glibc, sudo, systemd, OpenSSL, busybox and the rest. |
| Map a CVE to an exploit | `cyber_exploit_map` | Links a CVE to a public exploit and to the CyberPi technique. |
| Find public exploits | `cyber_exploit_search` | `searchsploit` over the local exploit database. |
| Run a module | `cyber_exploit_run` | `msfconsole` against a module that the scope allows. |

Checks that feed the lookup:

| Check | Command | What to look for |
|---|---|---|
| User namespaces | `cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null; cat /proc/sys/user/max_user_namespaces` | `1` and a high limit open the unprivileged-overlay and DirtyCred family. |
| Kernel config | `grep -E 'CONFIG_(USER_NS|SECCOMP|DEFAULT_USER_NS)' /boot/config-$(uname -r) 2>/dev/null` | `CONFIG_USER_NS` and `CONFIG_USER_NS_UNPRIVILEGED`. |
| OverlayFS | `grep -E 'CONFIG_(OVERLAY_FS|USER_NS)' /boot/config-$(uname -r) 2>/dev/null` | OverlayFS plus unprivileged user namespaces is the `CVE-2023-0386` precondition. |
| glibc | `ldd --version \| head -1` | `2.34`–`2.35` is the PwnKit (`CVE-2021-4034`) range. |
| Exposed services | `cyber_service_scan` | The service versions on the host, which are the other CVE inputs. |

## 9. Linux — container escape

| Check | Command | What to look for |
|---|---|---|
| Docker socket | `ls -l /var/run/docker.sock /run/docker.sock 2>/dev/null` | A mounted socket is a host root shell. |
| Privileged markers | `grep -E 'CapEff|CapBnd' /proc/self/status`; `capsh --print` | `cap_sys_admin` and `cap_sys_module` in the effective set. |
| Host mounts | `cat /proc/self/mountinfo` | Host paths mounted into the container. |
| Host root | `ls -la /proc/1/root/ 2>/dev/null` | Reaches the host filesystem when PID 1 is the host init. |
| cgroup v1 release agent | `ls -l /sys/fs/cgroup/release_agent; cat /sys/fs/cgroup/release_agent 2>/dev/null` | A writable `release_agent` executes a command as root on cgroup teardown. |
| cgroup v2 | `cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null`; `ls -l /sys/fs/cgroup/cgroup.events` | `cgroup.freeze` and the `release_agent`-equivalent paths. |
| `core_pattern` | `cat /proc/sys/kernel/core_pattern` | A writable pattern executes a helper as root on the next crash. |
| Namespace tools | `which nsenter unshare capsh` | `nsenter` is the pivot once `CAP_SYS_ADMIN` is present. |
| Escape CVE | `cyber_cve_lookup` against the runtime version | `runc`, `containerd` and `Docker` escapes are published regularly. |

## 10. Windows — services

| Check | Command | What to look for |
|---|---|---|
| Service inventory | `Get-CimInstance Win32_Service \| Select-Object Name,StartName,PathName \| Format-Table -AutoSize` | The service list with the account each one runs as. |
| Service inventory (legacy) | `wmic service get Name,PathName,StartName` | Same data on older builds; `wmic` is removed on current Windows. |
| One service | `sc.exe qc <service>` | `BINARY_PATH_NAME` — unquoted path with spaces, relative path, or `svchost` group membership. |
| Service DACL | `sc.exe sdshow <service>` | `BA;(A;;RPWPWL;;;WD)` or `BU;(A;;RPWPCRWL;;;BU)` — a non-admin can rewrite the service. |
| Service state | `sc.exe queryex <service>` | `STATE` and the owning PID. |
| Service ACL on the binary | `icacls "C:\path\to\service.exe"` | `(W)` or `(M)` for `Everyone`, `Users` or `Authenticated Users`. |
| Service directory ACL | `icacls "C:\Program Files\App"` | A writable directory next to a privileged binary enables DLL hijacking. |
| Temp and work dirs | `icacls C:\Windows\Temp; icacls C:\ProgramData` | Staging directories a service loads from. |

Unquoted-path test: a path such as `C:\Program Files\App\svc.exe` is searched as
`C:\Program.exe`, `C:\Program Files\App\svc.exe` and, if the first is
writable, the service runs the planted binary. Check every directory in the
path with `icacls`.

## 11. Windows — registry and policy

| Check | Command | What to look for |
|---|---|---|
| UAC enabled | `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA` | `0x0` means UAC is off and every user is effectively an administrator. |
| Admin prompt | `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin` | `0x0` auto-elevates administrators without a prompt. |
| AlwaysInstallElevated (machine) | `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v AlwaysInstallElevated` | `0x1` with the user-side value also set elevates any MSI. |
| AlwaysInstallElevated (user) | `reg query "HKU\<sid>\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v AlwaysInstallElevated` | Both sides are required for the elevation to fire. |
| Installer policy | `reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated` | The group-policy form of the same setting. |
| fodhelper hijack | `reg query "HKCU\Software\Classes\ms-settings\Shell\Open\command" /ve` | A `DelegateExecute` or `command` value under a writable HKCU key is a UAC bypass. |
| computerdefaults hijack | `reg query "HKCU\Software\Classes\mscfile\shell\open\command" /ve` | Same pattern. |
| Auto-run | `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" /ve` | Persistence and, with a privileged context, escalation. |
| Service image paths | `reg query "HKLM\SYSTEM\CurrentControlSet\Services" /v ImagePath /s` | The registry view of the service list. |
| User SID map | `wmic useraccount get name,sid` | Finds the `HKU\<sid>` key for the AlwaysInstallElevated check. |

## 12. Windows — tokens and impersonation

| Check | Command | What to look for |
|---|---|---|
| Privileges | `whoami /priv` | `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`, `SeCreateTokenPrivilege`, `SeTcbPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeLoadDriverPrivilege`, `SeDebugPrivilege`, `SeTakeOwnershipPrivilege`. |
| Token groups | `whoami /groups` | `BUILTIN\Administrators` (`S-1-5-32-544`) and the mandatory integrity label. |
| Admin membership | `net localgroup Administrators` | The session account inside the group. |
| Admin check | `net session` | Succeeds only with an elevated token — the cleanest verification. |
| Local users | `Get-LocalUser \| Format-Table Name,Enabled,PasswordRequired -AutoSize` | Accounts that still work and whether they are locked out. |
| Local admins | `Get-LocalGroupMember Administrators` | The same list in PowerShell. |
| Named pipes | `[System.IO.Directory]::GetFiles("\\.\pipe\")` | Pipes a privileged service creates; a writable path to the same name is an impersonation sink. |
| Service processes | `Get-CimInstance Win32_Service \| Where-Object { $_.State -eq 'Running' -and $_.StartName -eq 'LocalSystem' }` | The SYSTEM services that may be impersonation sinks. |
| Print spooler | `Get-Service Spooler` | The classic `PrintSpoofer` sink when it is running. |

## 13. Windows — write primitives

| Check | Command | What to look for |
|---|---|---|
| Writable application directory | `icacls "C:\Program Files\<app>"` | A user-writable directory holding a privileged binary enables a planted DLL or EXE. |
| DLL search order | `Get-ChildItem "C:\Program Files\<app>" -Filter *.dll` | A DLL that the binary loads but that is not present in the expected location. |
| Planted file proof | `echo cyberpi-poc > C:\Windows\Temp\cyberpi-poc.txt; type C:\Windows\Temp\cyberpi-poc.txt` | Confirms the write primitive works before it is used against a privileged path. |
| Service replacement | `sc.exe qc <service>` | The `BINARY_PATH_NAME` after the write. |
| MSI elevation | `msiexec /i <package>.msi /qn` | Runs under the AlwaysInstallElevated policy when it is set. |
| GPP credentials | `dir C:\Windows\System32\mssecsvc\Groups C:\Windows\SysWOW64\mssecsvc\Groups` | `Groups.xml` and `Groups.csv` hold `cpassword` values. |
| GPP templates | `dir C:\Windows\System32\mssecsvc\GptTmpl; dir "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\NTFAG-*"` | The scheduled-task and preference files. |
| Plaintext credentials | `cyber_secret_scan` over a reachable share or repository | Service configs and deployment scripts with embedded passwords. |

## 14. Remote checks from the Kali box

These run against the target through the CyberPi tools, so they are
scope-checked and journalled.

| Tool | Binary | Use in a privilege escalation |
|---|---|---|
| `cyber_portscan` | naabu | Establish which management ports are reachable: 445, 135, 139, 5985, 5986, 3389, 389, 636, 1433. |
| `cyber_service_scan` | nmap | Service versions and the NSE script results. The script families that matter on Windows: `smb-os-discovery`, `smb2-security-mode`, `smb-vuln-ms17-010`, `smb-vuln-ms08-067`, `smb-enum-users`, `rpc-enum`, `vuln`. |
| `cyber_http_probe` | httpx | Local web services on the target, and their technology stack. |
| `cyber_vuln_scan` | nuclei | Template coverage for the exposed services. |
| `cyber_cve_lookup` | python3 | Map a service or OS version to its CVEs. |
| `cyber_cve_sync` | python3 | Refresh the offline CVE database before a lookup. |
| `cyber_exploit_map` | python3 | Link a CVE to a public exploit. |
| `cyber_exploit_search` | searchsploit | Search the local exploit database by product, CVE or title. |
| `cyber_exploit_run` | msfconsole | Run a module the scope allows. |
| `cyber_poc` | curl | Validate a write primitive and confirm the escalated identity over HTTP. |
| `cyber_secret_scan` | trufflehog | Recover credential material from the target's files and shares without printing it into the transcript. |
| `cyber_ad_enum` | ldapdomaindump | The service account a Windows service runs as. |
| `cyber_surface` | — | What is already known about the host; read it before scanning again. |
| `cyber_record_finding` | — | Record the escalation with its verification evidence. |
| `cyber_journal` | — | The full action record for the engagement. |

The equivalent nmap invocation for the Windows service scan, useful when the
tool's parameters do not cover script selection:

```bash
nmap -Pn -sV -p 445,139,135,5985,5986,3389,389,636,1433 \
  --script smb-os-discovery,smb2-security-mode,smb-vuln-ms17-010,smb-vuln-ms08-067,smb-enum-users,rpc-enum,vuln \
  <target>
```

## 15. Validating a write primitive with `cyber_poc`

`cyber_poc` runs `curl` against a URL you name. It closes the loop on a write
primitive and is scope-checked, so the host must be in `.cyberpi/scope.json`.

| Scenario | What to point `cyber_poc` at | What a positive result looks like |
|---|---|---|
| Planted script in a web root | The URL of the planted file | The response body contains the command output, e.g. `uid=0(root)`. |
| Hijacked library behind a service | The endpoint that triggers the load | The response changes behaviour and the side effect appears on the host. |
| Replaced service binary behind HTTP | The service endpoint | The response reflects the new binary. |
| Exploit that returns a shell | The vulnerable endpoint | The response body shows the escalated identity. |

Keep the confirmation minimal: one request, one observation, and the artifact
file that holds the full response.

## 16. Verification commands

Escalation is proven by the identity, not by the exploit.

Linux:

```bash
id                                  # expect uid=0(root) gid=0(root)
sudo -n id                          # for a sudo-rule escalation
cat /etc/shadow | head -3           # root-only read
capsh --print | grep cap_sys_admin
cat /proc/1/root/etc/os-release     # host identity, for a container escape
nsenter -t 1 -m -u -i -n -p -- id   # host identity, for a container escape
```

Windows:

```powershell
whoami /groups | findstr /i "S-1-5-32-544"
whoami /priv
net localgroup Administrators
net session                          # succeeds only with an elevated token
```

For a write primitive that has not yet produced an escalation, confirm the
write landed and that the privileged consumer picked it up:

```bash
ls -l <planted file>
journalctl -u <unit> --since "-5 min" --no-pager
```

```powershell
sc.exe qc <service>
dir C:\Windows\Temp\<planted file>
```
