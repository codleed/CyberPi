# nmap recipes for service enumeration

Concrete invocations for the services that show up in a Kali engagement. Every recipe
lists the nmap command, what it reveals, and the caveats that decide whether it is safe
to run.

## How to use these

- **Prefer the harness.** `cyber_service_scan` runs
  `nmap -sV -Pn -T<0|3|4> -oX -` plus `-p <ports>` and `--script <nse_scripts>`. Pass the
  script list through `nse_scripts` in nmap's own syntax (`http-title,safe`,
  `smb-enum-*`, `discovery`). That keeps the action scope-checked and journalled.
- **What the harness cannot do.** The service scan has no UDP scan type and no way to
  add extra flags, so recipes that need `-sU`, `-sC`, `--script-args` or a different
  scan type are for the operator to run by hand. Hand over the exact command and say
  what it proves; do not run it yourself, because a raw nmap is not in the engagement
  record.
- **UDP discovery** does work through the harness: `cyber_portscan` with a `u:` port
  prefix, for example `ports="u:53,u:123,u:161,u:514,u:1900"`.
- **Root.** SYN scans (`-sS`), UDP scans and most NSE scripts need root or
  `CAP_NET_RAW`. Without it use connect scans (`-sT`) and expect less.
- **Categories matter.** `safe` and `discovery` scripts are unproblematic. `auth`,
  `brute`, `vuln` and `intrusive` scripts need the matching authorization and carry
  real risk: a brute script can lock an account, an intrusive script can crash the
  service, a vuln script is a vulnerability test and not enumeration.
- **Output.** The harness parses nmap's XML and writes the raw run to
  `.cyberpi/artifacts/`. For a hand-run command, prefer `-oA <prefix>` so the report
  generator has a normal, grepable and XML copy.

## Baseline

Through the harness:

```
cyber_portscan(target="10.0.0.5")                                  # default port set
cyber_portscan(target="10.0.0.5", ports="1-65535", rate=1000)      # full range
cyber_portscan(target="10.0.0.0/24", ports="1-1024,2222,3389,8080")
cyber_portscan(target="10.0.0.5", top_ports=1000)                  # most common ports
cyber_service_scan(target="10.0.0.5", ports="22,80,443,445")       # version detection, no scripts
cyber_service_scan(target="10.0.0.5", ports="22,80,443,445", nse_scripts="ssh2-enum-algos,http-title")
cyber_service_scan(target="10.0.0.5", ports="443", timing="paranoid")
```

The equivalent nmap commands, for reference and for the operator:

```bash
nmap -sV -sC -p 22,80,443,445 10.0.0.5

# One scan across many hosts with one shared port list
nmap -sV -sC -p 22,80,443,445 10.0.0.0/24 -oA hosts-22-445

# Host is up but does not answer ping: skip host discovery
nmap -Pn -sV -p 22,80,443 10.0.0.5

# No raw sockets available
nmap -sT -sV -p 22,80,443 10.0.0.5
```

Useful global flags: `--open` (only open ports), `--reason` (why the port is in that
state), `-T4` (faster timing), `--min-rate` / `--max-retries` (rate control),
`--host-timeout` (bound a hanging host), `-A` (aggressive: version + OS + traceroute +
default scripts), `--version-all` (exhaustive version probes).

## SMB — 139/tcp, 445/tcp

### Fingerprint the server

```bash
nmap -sV -p 139,445 --script smb-protocols,smb2-capabilities,smb-os-discovery,smb2-time,smb2-security-mode 10.0.0.5
```

```
cyber_service_scan(target="10.0.0.5", ports="139,445",
  nse_scripts="smb-protocols,smb2-capabilities,smb2-time,smb2-security-mode")
```

- `smb-protocols` — SMB1, SMB2, SMB3 dialects the server accepts. **SMB1 enabled is a
  finding on its own.**
- `smb2-capabilities` — SMB2 signing, encryption, compression, dialect, maximum
  transceive size.
- `smb-os-discovery` — OS and version. Depends on `smb-brute`, so it attempts
  authentication as a side effect.
- `smb2-time` — the server clock. Skew against the domain controller breaks Kerberos
  ticket requests; a mismatch here explains a lot of confusing AD failures later.
- `smb2-security-mode` / `smb-security-mode` — signing requirement, SMB1 signing.

### Enumerate shares, users, groups, sessions

```bash
nmap -p 445 --script smb-enum-shares 10.0.0.5
nmap -p 445 --script smb-enum-users 10.0.0.5
nmap -p 445 --script smb-enum-groups 10.0.0.5
nmap -p 445 --script smb-enum-sessions 10.0.0.5
nmap -p 445 --script smb-enum-services 10.0.0.5
nmap -p 445 --script smb-enum-domains 10.0.0.5
nmap -p 445 --script smb-system-info 10.0.0.5
nmap -p 445 --script smb-ls 10.0.0.5
```

```
cyber_service_scan(target="10.0.0.5", ports="445", nse_scripts="smb-enum-shares")
```

Caveats:

- `smb-enum-shares`, `smb-enum-users`, `smb-enum-groups`, `smb-enum-sessions`,
  `smb-enum-domains`, `smb-system-info` and `smb-os-discovery` all declare
  `smb-brute` as a dependency and are tagged `intrusive`. They will try credentials
  (blank, guest, the server name, and the local user list). On a domain-joined box that
  means failed logons; a few dozen attempts can trip a lockout policy.
  `smb-enum-services` is tagged `intrusive` as well but does not depend on
  `smb-brute`, so it does not attempt to log in.
- `smb-enum-shares` is the one to run first. It is the difference between "445 is open"
  and "the finance share is world-readable".
- `smb-ls` lists the content of a share. It declares `smb-enum-shares` as a dependency,
  so nmap runs that first; `--script-args 'smb-ls.shares=...'` points it at a specific
  share. `--script-args` is not exposed by the harness, so use it only in a hand-run
  command.
- `smb-mbenum` (NetBIOS name enumeration) still works over 137/udp and 139/tcp on
  older hosts: `nmap -p 139 --script smb-mbenum 10.0.0.5`.

### Patches and known issues

```bash
nmap -p 445 --script smb-vuln-ms17-010 10.0.0.5      # EternalBlue (MS17-010)
nmap -p 445 --script smb2-vuln-uptime 10.0.0.5        # Samba advisory
nmap -p 445 --script smb-vuln-cve-2017-7494 10.0.0.5  # SambaCry
```

These are `vuln` category: they are vulnerability tests, not enumeration, and they need
vulnerability-testing authorization. `smb-vuln-ms17-010` and `smb2-vuln-uptime` are
tagged `safe`; `smb-vuln-cve-2017-7494` is tagged `intrusive`.

### By hand

```bash
smbclient -L //10.0.0.5 -N                 # list shares anonymously
smbclient //10.0.0.5/SHARE -N -c 'ls'      # list a share anonymously
rpcclient -U '' -N -c 'srvinfo' 10.0.0.5   # server info
rpcclient -U '' -N -c 'enumdomusers' 10.0.0.5
```

Anonymous share access is the headline finding when it works. Report the share, the
permission and the data exposed — not just the fact of access.

## RDP — 3389/tcp

```bash
nmap -sV -p 3389 --script rdp-enum-encryption,rdp-ntlm-info 10.0.0.5
```

```
cyber_service_scan(target="10.0.0.5", ports="3389",
  nse_scripts="rdp-enum-encryption,rdp-ntlm-info")
```

- `rdp-enum-encryption` — the encryption methods the server offers: CredSSP (NLA),
  TLS, and the legacy RC4/MD5 path. **NLA disabled or only legacy encryption offered
  is a finding.** It is also the difference between a credential prompt and an
  unauthenticated session.
- `rdp-ntlm-info` — NTLM information (domain, computer name, NTLMv2 support). A leak
  of the internal domain and NetBIOS name is an information disclosure.

Vulnerability testing, needs authorization:

```bash
nmap -p 3389 --script rdp-vuln-ms12-020 10.0.0.5   # BlueKeep, tagged intrusive
```

By hand:

```bash
xfreerdp /v:10.0.0.5 /cert:ignore +auth-only
```

Also check: is 3389 reachable from where a normal user sits, or only from the internal
network? A jump host is not a control if RDP lands on the desktop.

## SSH — 22/tcp (and 2222, 2200, and friends)

```bash
nmap -sV -p 22 --script ssh-hostkey,ssh2-enum-algos,ssh-auth-methods 10.0.0.5
```

```
cyber_service_scan(target="10.0.0.5", ports="22",
  nse_scripts="ssh-hostkey,ssh2-enum-algos,sshv1")
```

- `ssh-hostkey` — the server host keys and their fingerprints. A key that changed
  between engagements is a serious incident; a weak key type is a finding.
- `ssh2-enum-algos` — the negotiated key exchange, host key, encryption and MAC
  algorithms. Look for `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`,
  `ssh-rsa` (SHA-1 signatures), `arcfour`, `3des-cbc`, `cbc` modes, and the absence of
  `chacha20-poly1305` or `aes*-gcm`. `hmac-sha1` is a MAC weakness finding.
- `ssh-auth-methods` — which authentication methods are offered. `password` means
  password guessing is worth considering, but only with password-audit authorization.
  The script is tagged `intrusive` because it opens a real authentication attempt.
- `sshv1` — checks whether the server still speaks SSH protocol 1. Tagged `safe` and
  `default`; run it whenever SSH is in scope.

Weakness check:

```bash
nmap -p 22 --script ssh2-enum-algos 10.0.0.5
```

By hand:

```bash
ssh -o PreferredAuthentications=none -o StrictHostKeyChecking=no user@10.0.0.5
ssh-keyscan -t rsa,ecdsa,ed25519 10.0.0.5
```

Look for: SSHv1 enabled, `password` auth offered, root login permitted, old OpenSSH
versions, and host keys shorter than 2048 bits.

## SNMP — 161/udp, 162/udp

SNMP is the most productive UDP service to check, because a default community string
leaks the entire device inventory.

Discovery goes through the harness:

```
cyber_portscan(target="10.0.0.5", ports="u:161")
```

Identification does not, because the service scan cannot do UDP. Hand the operator:

```bash
# Does it answer at all, and with which SNMP version?
nmap -sU -p 161 --script snmp-info 10.0.0.5

# System description, uptime, interfaces
nmap -sU -p 161 --script snmp-sysdescr,snmp-processes,snmp-interfaces,snmp-netstat 10.0.0.5

# Windows specifics
nmap -sU -p 161 --script snmp-win32-users,snmp-win32-shares,snmp-win32-software,snmp-win32-services 10.0.0.5
```

- `snmp-info` — enumerates SNMP versions and attempts to read the system OID with a set
  of community strings. Tagged `default`, `version`, `safe`.
- `snmp-sysdescr` — the sysDescr string: hardware model, firmware, serial number, and
  often the exact firmware build. `snmp-processes` — the running process list.
  `snmp-interfaces` — interfaces, IPs and descriptions, which maps the network.
  `snmp-netstat` — the TCP/UDP connection table.
- `snmp-win32-*` — the Windows equivalents and the ones that dump local users and
  shares over SNMP.
- All of these declare `snmp-brute` as a dependency, so they try community strings as a
  side effect. That is a small, fixed list, not a password attack.

Community strings, with authorization for credential testing:

```bash
nmap -sU -p 161 --script snmp-brute --script-args 'snmp-brute.communitiesdb=/usr/share/seclists/Passwords/Default-Credentials/default-snmp-community.txt' 10.0.0.5
```

`snmp-brute` is tagged `brute` and `intrusive`. The community file path is
`snmp-brute.communitiesdb`; the default list is built in.

By hand:

```bash
snmpwalk -v2c -c public 10.0.0.5
snmpwalk -v1 -c private 10.0.0.5 1.3.6.1.2.1.1.1.0
snmpget -v2c -c public 10.0.0.5 1.3.6.1.2.1.1.5.0
```

Look for: `public` or `private` accepted, a v1/v2c community on an internet-facing
host, and SNMPv3 not enforced. Any of those is a reportable finding — an SNMP write
community is worse, because it allows configuration changes.

## MQTT — 1883/tcp, 8883/tcp (TLS), 9001 (WebSocket)

```bash
nmap -sV -p 1883,8883,9001 --script mqtt-subscribe 10.0.0.5
```

```
cyber_service_scan(target="10.0.0.5", ports="1883,8883,9001", nse_scripts="mqtt-subscribe")
```

`mqtt-subscribe` connects to the broker, subscribes and prints the message traffic it
receives. It is tagged `safe`, `discovery`, `version`.

By default it subscribes to `$SYS/#` and `#`, so it picks up the broker's own system
topics — version, uptime, connected clients, subscriptions, retained messages, and
throughput.

Script arguments (hand-run only, the harness does not pass `--script-args`):

| Argument | Meaning |
|---|---|
| `mqtt-subscribe.username` | Broker username |
| `mqtt-subscribe.password` | Broker password (requires a username) |
| `mqtt-subscribe.topic` | Topic filter(s) to subscribe to instead of the defaults |
| `mqtt-subscribe.client-id` | Client identifier to present |
| `mqtt-subscribe.protocol-level` | MQTT protocol level to request |
| `mqtt-subscribe.protocol-name` | Protocol name to request |
| `mqtt-subscribe.listen-msgs` | Number of messages to collect |
| `mqtt-subscribe.listen-time` | How long to listen |

```bash
nmap -p 1883 --script mqtt-subscribe --script-args 'mqtt-subscribe.username=admin,mqtt-subscribe.password=admin,mqtt-subscribe.listen-time=30' 10.0.0.5
```

Look for: a broker with no authentication that lets anyone subscribe, `$SYS` topics
exposed on a public broker, retained messages containing credentials, and topics that
reveal physical processes or patient data. MQTT brokers are frequently deployed with no
TLS and no authentication.

## Web and HTTP — 80, 8080, 8000, 8443, 8888, 3000

Web testing belongs to the web-testing phase, but the service scan should still
fingerprint the server so the next phase starts from facts.

```bash
nmap -sV -p 80,443,8080,8443 --script http-title,http-server-header,http-methods,http-headers 10.0.0.5
```

```
cyber_service_scan(target="10.0.0.5", ports="80,443,8080,8443",
  nse_scripts="http-title,http-server-header,http-methods,http-headers")
```

- `http-title` — the page title. Often the fastest way to identify an admin panel or a
  custom application.
- `http-server-header` — the `Server` header and the framework.
- `http-methods` — the allowed methods. `PUT` and `DELETE` allowed on a web root are
  a finding on their own.
- `http-headers` — the full response header set: cookies without `Secure` or
  `HttpOnly`, a missing `Strict-Transport-Security`, an internal hostname in a header.
- `http-php-version`, `http-generator`, `http-comments-displayer` — technology
  disclosure in the body.
- `http-vhosts` — virtual host discovery, when a name-based vhost hides the real site.
- `http-robots.txt` — the paths the site tries to keep out of the way of.

TLS on the same ports:

```bash
nmap -sV -p 443 --script ssl-cert,ssl-enum-ciphers,ssl-known-key,ssl-date 10.0.0.5
```

```
cyber_service_scan(target="10.0.0.5", ports="443", nse_scripts="ssl-cert,ssl-date")
```

- `ssl-cert` — the certificate: subject, SANs, issuer, validity window, and whether it
  is self-signed. An expired certificate or a certificate for the wrong name is a
  finding; the SAN list is a good host-discovery source.
- `ssl-enum-ciphers` — the accepted ciphersuites and their ratings. `3des`, `rc4`,
  `NULL` and export ciphers are findings. The script is tagged `intrusive` because it
  opens many connections.
- `ssl-known-key` — checks the server key against a database of compromised keys.
  Tagged `vuln`.
- `ssl-date` — the certificate validity window versus the target's clock, and it
  confirms whether the certificate matches the hostname.

## Mail — 25 (SMTP), 110 (POP3), 143 (IMAP)

```bash
nmap -sV -p 25,110,143,587,993,995 --script smtp-commands,smtp-ntlm-info,pop3-capabilities,imap-capabilities 10.0.0.5
```

```
cyber_service_scan(target="10.0.0.5", ports="25,110,143,587,993,995",
  nse_scripts="smtp-commands,smtp-ntlm-info,pop3-capabilities,imap-capabilities")
```

- `smtp-commands` — the supported verbs. `AUTH` with `PLAIN` or `LOGIN` means
  unencrypted credentials can be sent; `VRFY` and `EXPN` mean users can be enumerated.
- `smtp-ntlm-info`, `pop3-ntlm-info`, `imap-ntlm-info` — the NTLM domain and hostname
  leak.
- `pop3-capabilities`, `imap-capabilities` — the supported authentication mechanisms
  and whether TLS is offered.

Relay and user enumeration need authorization:

```bash
nmap -p 25 --script smtp-open-relay 10.0.0.5   # discovery + intrusive + external
nmap -p 25 --script smtp-enum-users 10.0.0.5   # auth + intrusive + external
```

An open relay is a critical finding and must be confirmed from an external vantage
point before it goes in the report.

## Databases — 1433 (MSSQL), 3306 (MySQL), 5432 (PostgreSQL), 27017 (MongoDB), 6379 (Redis)

```bash
# SQL Server
nmap -sV -p 1433 --script ms-sql-info 10.0.0.5

# MySQL
nmap -sV -p 3306 --script mysql-info,mysql-databases,mysql-variables 10.0.0.5

# MongoDB
nmap -sV -p 27017 --script mongodb-info,mongodb-databases 10.0.0.5

# Redis
nmap -sV -p 6379 --script redis-info 10.0.0.5
```

```
cyber_service_scan(target="10.0.0.5", ports="1433,3306,27017,6379",
  nse_scripts="ms-sql-info,mysql-info,mongodb-info,redis-info")
```

- `ms-sql-info` — instance name, version, edition, TCP port, named pipes.
  `ms-sql-empty-password` checks for the `sa` account with an empty password;
  `ms-sql-tables` lists tables with the default credentials.
- `mysql-info` — version, capabilities and the authentication plugin. `mysql-empty-password`
  checks for a root account with no password, which is still common on default installs.
  `mysql-databases` and `mysql-users` are tagged `intrusive`/`auth`.
- `mongodb-info` — version, authentication enabled or not, and the databases present.
  An unauthenticated MongoDB is a critical finding.
- `redis-info` — version, and whether authentication is required. A Redis with no
  password is frequently writable and often reachable from an unexpected network
  segment.

`ms-sql-xp-cmdshell`, `mysql-dump-hashes` and `ms-sql-dump-hashes` extract data or
execute commands. They are exploitation, not enumeration.

## DNS — 53/udp, 53/tcp

```bash
nmap -sU -sT -p 53 --script dns-srv-enum,dns-nsec-enum,dns-nsid,dns-service-discovery 10.0.0.5
nmap -sU -p 53 --script dns-zone-transfer --script-args 'dns-zone-transfer.domain=example.com' 10.0.0.5
```

- `dns-zone-transfer` — an AXFR that succeeds dumps the whole zone. This is one of the
  highest-value checks in a web assessment and it is a single request. The script is
  tagged `intrusive` because a zone transfer is a heavy query for the server.
  The argument is `dns-zone-transfer.domain`; `dns-zone-transfer.server` and
  `dns-zone-transfer.port` are also accepted. Both arguments need `--script-args`, so
  this one is a hand-run command.
- `dns-recursion` — whether the resolver answers for arbitrary domains. Open recursion
  on a server inside the client network is an abuse risk and a finding.
- `dns-nsec-enum` — enumerates NSEC records that sometimes expose zone names.
- `dns-srv-enum` — the standard service records.
- `dns-service-discovery` — mDNS on the local segment. Use it only on the local
  network; it is noisy.

## NFS and RPC — 111/tcp, 111/udp, 2049/tcp

```bash
nmap -sV -p 111,2049 --script rpcinfo,nfs-showmount,nfs-ls,nfs-statfs 10.0.0.5
```

```
cyber_service_scan(target="10.0.0.5", ports="111,2049",
  nse_scripts="rpcinfo,nfs-showmount,nfs-ls")
```

- `rpcinfo` — the registered RPC programs. An unauthenticated `mountd` and `nfsd` give
  you the export list.
- `nfs-showmount` — the exported shares. `nfs-ls` and `nfs-statfs` list the contents
  and the filesystem size of an export. An export with `no_root_squash` and a writable
  path is a direct root compromise path.

## FTP and Telnet — 21/tcp, 23/tcp

```bash
nmap -sV -p 21 --script ftp-anon,ftp-syst 10.0.0.5
nmap -sV -p 23 --script telnet-encryption,telnet-ntlm-info 10.0.0.5
```

- `ftp-anon` — anonymous login. The script reports the login result and lists the
  directory. `ftp-anon.maxlist` bounds the listing.
- `ftp-syst` — the server's system string, which often leaks the distribution and
  version.
- `telnet-encryption` — whether telnet is offered with any encryption. Plain telnet
  carries credentials in clear text; that is the finding.

## VNC — 5900-5905/tcp

```bash
nmap -sV -p 5900-5905 --script vnc-info,vnc-title 10.0.0.5
```

- `vnc-info` — the protocol version and the security types. A VNC server offering
  "None" authentication needs no password at all.
- `vnc-title` — the desktop name, which often contains the host or user name.
  Both scripts are tagged `intrusive` because they open a real session.

## Other services worth a line each

```bash
nmap -sU -p 69 --script tftp-version,tftp-enum 10.0.0.5     # TFTP, no auth by design
nmap -sU -p 123 --script ntp-info 10.0.0.5                   # NTP monlist / drift
nmap -sV -p 389,636 --script ldap-rootdse,ldap-search 10.0.0.5  # AD naming context
nmap -sV -p 5672 --script amqp-info 10.0.0.5                 # RabbitMQ
nmap -sV -p 1080 --script socks-open-proxy 10.0.0.5          # open SOCKS proxy
nmap -sV -p 13,7 --script daytime 10.0.0.5                   # daytime, banner info
```

- `tftp-enum` lists files served over TFTP; TFTP has no authentication at all, so a
  device with a configuration file on it is fully exposed.
- `ntp-monlist` (tagged `intrusive`) asks for the monitoring list, which on old ntpd
  is a known amplification vector.
- `ldap-rootdse` reveals the domain naming context, the domain controller flags and the
  schema. `ldap-search` needs a base DN argument.
- `ldap-brute` and `smtp-open-relay` are `external` category: they send traffic
  outside the target. They need explicit authorization.

## Script selection by category

| Category | Scripts used here | Authorization needed |
|---|---|---|
| `safe` | `ssh-hostkey`, `ssh2-enum-algos`, `sshv1`, `smb-protocols`, `smb2-capabilities`, `smb2-time`, `smb2-security-mode`, `snmp-info`, `snmp-sysdescr`, `snmp-processes`, `snmp-interfaces`, `snmp-netstat`, `mqtt-subscribe`, `ssl-cert`, `ssl-date`, `http-title`, `http-server-header`, `http-methods`, `smtp-commands`, `pop3-capabilities`, `imap-capabilities`, `mysql-info`, `ms-sql-info`, `mongodb-info`, `redis-info`, `nfs-ls`, `ldap-rootdse`, `dns-recursion`, `dns-srv-enum`, `tftp-version`, `ntp-info`, `amqp-info`, `banner` | None beyond enumeration |
| `discovery` | `smb-enum-shares`, `smb-enum-users`, `smb-enum-groups`, `smb-enum-domains`, `smb-enum-sessions`, `smb-enum-services`, `smb-system-info`, `smb-ls`, `smb-mbenum`, `snmp-win32-*`, `ftp-anon`, `http-title`, `vnc-info`, `dns-zone-transfer`, `dns-nsec-enum`, `banner` | Enumeration authorization; check the brute dependencies first |
| `auth` | `ssh-auth-methods`, `mysql-users`, `smtp-enum-users`, `smb-enum-users` | Credential testing |
| `brute` | `smb-brute`, `snmp-brute`, `ssh-brute`, `ftp-brute`, `redis-brute`, `smtp-brute`, `mysql-brute`, `mongodb-brute`, `ms-sql-brute`, `vnc-brute`, `pop3-brute`, `imap-brute`, `ldap-brute` | Password auditing, and a lockout risk the client accepted |
| `vuln` | `smb-vuln-ms17-010`, `smb2-vuln-uptime`, `smb-vuln-cve-2017-7494`, `rdp-vuln-ms12-020`, `ssl-known-key`, `ssl-heartbleed`, `ssl-poodle`, `ssl-ccs-injection`, `smtp-vuln-cve2010-4344`, `smtp-vuln-cve2011-1720`, `smtp-vuln-cve2011-1764` | Vulnerability testing |
| `intrusive` | `smb-enum-*`, `ssl-enum-ciphers`, `ssh-auth-methods`, `smtp-open-relay`, `vnc-title`, `dns-zone-transfer`, `ntp-monlist`, `tftp-enum`, `rdp-vuln-ms12-020` | Explicit, per-service authorization |
| `external` | `smtp-open-relay`, `smtp-enum-users`, `ldap-brute`, `whois-ip`, `dns-random-txid` | Traffic leaves the target; needs explicit authorization |

## Script arguments reference

| Script | Argument | Effect |
|---|---|---|
| `banner` | `banner.ports` | Ports to grab; `common` restricts to text protocols |
| `banner` | `banner.timeout` | Seconds to wait for the banner (default 5) |
| `smb-brute` | `smblimit` | Maximum number of usernames to try |
| `smb-brute` | `smblockout` | Continue after the first account lockout |
| `smb-ls` | `smb-ls.shares` | Share to list |
| `snmp-brute` | `snmp-brute.communitiesdb` | Wordlist of community strings |
| `mqtt-subscribe` | `mqtt-subscribe.username` / `.password` | Broker credentials |
| `mqtt-subscribe` | `mqtt-subscribe.topic` | Topic filter(s) to subscribe to |
| `mqtt-subscribe` | `mqtt-subscribe.listen-time` / `.listen-msgs` | Collection window and count |
| `dns-zone-transfer` | `dns-zone-transfer.domain` | Zone to request |
| `dns-zone-transfer` | `dns-zone-transfer.server` / `.port` | Server and port to query |
| `http-enum` | `http-enum.basepath` | Base path to prepend |
| `http-enum` | `http-enum.category` | Fingerprint category, e.g. `attacks` |
| `ftp-anon` | `ftp-anon.maxlist` | Maximum number of files to list |
| `mongodb-info` | `mongodb-info.db` | Database to query (default `admin`) |
| `ssh-auth-methods` | `ssh.user` | Username to test the methods with |
| `ssl-known-key` | `ssl-known-key.fingerprintfile` | Alternative key fingerprint database |
| `tftp-version` | `tftp-version.socket` | Use a listening socket for error messages |

## Reporting notes

- Quote the banner exactly in the finding evidence, but keep credentials, tokens and
  private keys out of the transcript and out of the finding body. Point at the artifact
  file under `.cyberpi/artifacts/` instead.
- For a version finding, the evidence is: service, product, exact version, port, and
  the CVE or advisory that applies, with the CVE database lookup as the source.
- A scan that found nothing is a result too. Record what was scanned (target, port
  range, protocol) and what the state was, so the client knows the coverage.
