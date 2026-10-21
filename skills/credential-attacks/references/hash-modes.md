# Hash modes and cracking reference

Reference for the `credential-attacks` skill: the hashcat mode numbers, the
John the Ripper format names for the same algorithms, the wordlists and rule
sets that ship with Kali, and the attack modes that decide how the run is
shaped.

The mode numbers below are the current upstream ones (hashcat 7.x, which is
what Kali rolling ships as `hashcat-data` 7.1.2). A mode number never changes
meaning once it ships, so the only version risk is a mode that does not exist
yet in the older build on the box - `hashcat --example-hashes` lists what the
installed build supports.

---

## 1. Identifying a hash

Ask the tool, do not guess:

```
cyber_hash_id  hash: 5f4dcc3b5aa765d61d8327deb882cf99
cyber_hash_id  path: /path/to/hashes.txt
```

Two offline helpers are useful when a second opinion is needed:

```bash
hash-identifier /path/to/hash.txt      # Kali package: hash-identifier
name-that-hash /path/to/hash.txt        # Kali package: name-that-hash
```

hashcat itself can identify a file and show an example hash for any mode:

```bash
hashcat --identify /path/to/hashes.txt
hashcat --example-hashes                # every supported mode with an example
hashcat -hh                            # the full mode list, one line each
```

**A self-describing prefix settles the question faster than any tool:**

| Prefix | Algorithm | hashcat mode |
|---|---|---|
| `$1$` | md5crypt | 500 |
| `$2y$` / `$2a$` / `$2b$` | bcrypt | 3200 |
| `$5$` | sha256crypt | 7400 |
| `$6$` | sha512crypt | 1800 |
| `$apr1$` | Apache md5 | 1600 |
| `$P$` | phpass (WordPress, phpBB3) | 400 |
| `$y$` | yescrypt | 36100 |
| `$argon2` / `$argon2id$` | Argon2 | 34000 |
| `$pbkdf2-sha256$` | PBKDF2-HMAC-SHA256 | 40024 |
| `{SSHA}` | LDAP salted SHA-1 | 111 |
| `{SSHA256}` | LDAP salted SHA-256 | 1411 |
| `$office$*2013*` | MS Office 2013 | 9600 |
| `$pdf$` | PDF | 10400 - 10700 |
| `$keepass$` | KeePass KDBX | 29700 |
| `$zip2$` / `PKZIP` | WinZip / PKZIP | 17200 |
| `\$HEX[]` | hashcat hex-encoded input | depends on the mode |

**Keep the salt with the hash.** A salted hash needs its salt to be cracked;
separating them guarantees a failure. The identifier usually returns
`hash:salt` or `user:hash:salt`, and the tool call takes the whole line.

---

## 2. Common hashcat modes

### Unix / Linux

| Mode | Algorithm | Notes |
|---|---|---|
| 500 | md5crypt, MD5 (Unix), Cisco-IOS `$1$` | `$1$` prefix |
| 1500 | descrypt, DES (Unix), traditional DES | 13-character, 8-character password |
| 1600 | Apache `$apr1$` MD5 | |
| 1700 | SHA2-512 | raw digest, no salt |
| 1800 | sha512crypt `$6$`, SHA512 (Unix) | `$6$` prefix |
| 3200 | bcrypt `$2*$`, Blowfish (Unix) | `$2y$` prefix; deliberately slow |
| 7400 | sha256crypt `$5$`, SHA256 (Unix) | `$5$` prefix |
| 8900 | scrypt | |
| 12400 | BSDi crypt, extended DES | |
| 19000 / 19100 / 19200 | QNX `/etc/shadow` MD5 / SHA256 / SHA512 | |

### Windows / Active Directory

| Mode | Algorithm | Notes |
|---|---|---|
| 1000 | NTLM | From a `SAM` hive; 32 hex characters |
| 1100 | Domain Cached Credentials (DCC), MS Cache | `hash:username` |
| 2100 | Domain Cached Credentials 2 (DCC2), MS Cache 2 | `hash:username` |
| 5500 | NetNTLMv1 / NetNTLMv1+ESS | `challenge:response:username` |
| 5600 | NetNTLMv2 | `challenge:response:username` |
| 14400 | sha1(CX) | Office / Windows domain format |
| 29000 | sha1($salt.sha1(utf16le($username).':'.utf16le($pass))) | |

### Kerberos

| Mode | Algorithm | Notes |
|---|---|---|
| 13100 | Kerberos 5, etype 23, TGS-REP | `etype:hash` |
| 18200 | Kerberos 5, etype 23, AS-REP | AS-REP roastable |
| 19600 | Kerberos 5, etype 17, TGS-REP | RC4 tickets |
| 19700 | Kerberos 5, etype 18, TGS-REP | |
| 7500 | Kerberos 5, etype 23, AS-REQ pre-auth | |

### Databases and application servers

| Mode | Algorithm | Notes |
|---|---|---|
| 300 | MySQL 4.1 / MySQL 5 | |
| 11200 | MySQL CRAM (SHA1) | `challenge:response` |
| 11100 | PostgreSQL CRAM (MD5) | `challenge:response` |
| 40055 | PostgreSQL SCRAM-SHA-256 | |
| 12 | PostgreSQL | |
| 112 | Oracle S: Type (Oracle 11+) | |
| 3100 | Oracle H: Type (Oracle 7+) | |
| 131 / 132 | MSSQL (2000) / MSSQL (2005) | |
| 112 | Oracle S: Type (Oracle 11+) | |

### Web applications and CMS

| Mode | Algorithm | Notes |
|---|---|---|
| 0 | MD5 | raw digest |
| 100 | SHA1 | raw digest |
| 400 | phpass | WordPress, phpBB3, vBulletin, Joomla |
| 2811 | MyBB 1.2+, IPB2+ | |
| 40020 | Drupal 7 | 7.x and later only |
| 40022 | Django (PBKDF2-SHA256) | 7.x and later only |
| 124 | Django (SHA-1) | |

### Network appliances and appliances

| Mode | Algorithm | Notes |
|---|---|---|
| 7000 | FortiGate (FortiOS) | |
| 2400 | Cisco-PIX MD5 | |
| 2410 | Cisco-ASA MD5 | |
| 5700 | Cisco-IOS type 4 (SHA256) | |
| 9300 | Cisco-IOS `$9$` (scrypt) | |
| 7300 | IPMI2 RAKP HMAC-SHA1 | BMC credentials |
| 8500 | RACF | z/OS |
| 8100 | Citrix NetScaler (SHA1) | |
| 8600 / 8700 / 9100 | Lotus Notes/Domino 5 / 6 / 8 | |

### Office documents, archives and key stores

| Mode | Algorithm | Notes |
|---|---|---|
| 9400 | MS Office 2007 | |
| 9500 | MS Office 2010 | |
| 9600 | MS Office 2013 | |
| 9700 | MS Office <= 2003 `$0`/`$1`, MD5 + RC4 | |
| 9800 | MS Office <= 2003 `$3`/`$4`, SHA1 + RC4 | |
| 10400 - 10420 | PDF 1.1 - 1.3 (Acrobat 2 - 4) | |
| 10500 | PDF 1.4 - 1.6 (Acrobat 5 - 8) | |
| 10600 | PDF 1.7 Level 3 (Acrobat 9) | |
| 10700 | PDF 1.7 Level 8 (Acrobat 10 - 11) | |
| 25400 | PDF 1.4 - 1.6, user and owner password | |
| 11600 | 7-Zip | |
| 12500 | RAR3-hp | |
| 13000 | RAR5 | |
| 13600 | WinZip | |
| 17200 / 17220 | PKZIP (Compressed), multi-file | |
| 13400 | KeePass (KDBX v2/v3) | |
| 29700 | KeePass (KDBX v2/v3), keyfile only | |
| 16500 | JWT | |
| 16900 | Ansible Vault | |
| 22100 | BitLocker | |
| 15900 | DPAPI masterkey file v2 | |

### Modern KDFs (7.x only, absent from 6.2.x builds)

| Mode | Algorithm |
|---|---|
| 34000 | Argon2 |
| 34100 | LUKS v2 argon2 + SHA-256 + AES |
| 34300 | KeePass Argon2 (KDBX v4) |
| 35500 | WordPress bcrypt(hmac-sha384($pass)) |
| 36100 | yescrypt |
| 36300 | scryptcrypt, scrypt (Unix) |
| 36800 | OpenSSH private keys (bcrypt-pbkdf) |

If the installed hashcat rejects a mode, it predates that mode. Check
`hashcat --example-hashes` for the build's list before assuming a crack
failed.

---

## 3. John the Ripper format names

John uses names, not numbers. The equivalent format for a hashcat mode is
found with `john --list=formats` (or `john --list=format-details` for the
full description of one). The names below are the current upstream labels.

| Algorithm | John format name |
|---|---|
| MD5 (raw) | `Raw-MD5` |
| SHA1 (raw) | `Raw-SHA1` |
| SHA256 (raw) | `Raw-SHA256` |
| SHA512 (raw) | `Raw-SHA512` |
| MD4 (raw) | `Raw-MD4` |
| md5crypt | `md5crypt` |
| md5crypt, long form | `md5crypt-long` |
| sha256crypt | `sha256crypt` |
| sha512crypt | `sha512crypt` |
| sha1crypt | `sha1crypt` |
| descrypt (traditional DES) | `descrypt` |
| BSDi crypt | `bsdicrypt` |
| bcrypt | `bcrypt` |
| scrypt | `scrypt` |
| Argon2 | `argon2` (`Argon2` in newer builds) |
| NTLM | `NT` |
| LM | `LM` |
| NetNTLMv1 (ESS) | `netntlm` |
| NetNTLMv1 (plain) | `netntlm-naive` |
| NetNTLMv2 | `netntlmv2` |
| NetLM | `netlm` |
| NetLMv2 | `netlmv2` |
| Half LM | `nethalflm` |
| MS Cache | `mscash` |
| MS Cache 2 | `mscash2` |
| phpass | `phpass` |
| Django | `Django` |
| Django (scrypt) | `django-scrypt` |
| Kerberos TGS-REP | `krb5tgs` |
| Kerberos AS-REP | `krb5asrep` |
| MS Office | `Office` |
| MS Office <= 2003 | `oldoffice` |
| PDF | `PDF` |
| PKZIP | `PKZIP` |
| ZIP | `ZIP` |
| 7-Zip | `7z` |
| KeePass | `KeePass` |
| Ansible Vault | `ansible` |
| Bitwarden | `Bitwarden` |
| LastPass (CLI) | `lpcli` |
| LastPass (sniffed session) | `LastPass` |
| Salted SHA-1 | `Salted-SHA1` |
| XSHA / XSHA512 | `xsha` / `xsha512` |
| PBKDF2-HMAC-SHA256 | `PBKDF2-HMAC-SHA256` |
| MySQL 4.1/5 | `mysql-sha1` |
| MySQL 3.23 | `mysql` |
| MSSQL 2000 / 2005 / 2012 | `mssql` / `mssql05` / `mssql12` |
| MongoDB | `MongoDB` |
| ODF | `ODF` |
| Android Backup | `AndroidBackup` |
| net-sha1 | `net-sha1` |
| OpenBSD SoftRAID | `OpenBSD-SoftRAID` |
| Generic `$dynamic_*$` | `dynamic` |

John's `dynamic` format is the reason to keep John around when hashcat
cannot express the algorithm: it takes a `$dynamic_<id>$` expression and
evaluates it directly, so a custom construction can be cracked without
writing a hashcat plugin.

---

## 4. Wordlists and rule sets on Kali

| Path | Contents |
|---|---|
| `/usr/share/wordlists/rockyou.txt.gz` | The `rockyou` corpus, gzipped. The default first wordlist for a straight attack |
| `/usr/share/seclists/Passwords/Common-Credentials/` | `10k-most-common.txt`, `500-worst-passwords.txt`, `Pwdb_top-1000.txt` up to `Pwdb_top-10000000.txt`, per-year most-used lists |
| `/usr/share/seclists/Passwords/Default-Credentials/` | Per-vendor defaults: `ssh-betterdefaultpasslist.txt`, `mysql-betterdefaultpasslist.txt`, `postgres-betterdefaultpasslist.txt`, `mssql-betterdefaultpasslist.txt`, `tomcat-betterdefaultpasslist.txt`, `vnc-betterdefaultpasslist.txt`, `windows-betterdefaultpasslist.txt`, `default-passwords.txt`, plus a `Routers/` set |
| `/usr/share/seclists/Usernames/` | `cirt-default-usernames.txt`, `top-usernames-shortlist.txt`, `sap-default-usernames.txt`, `xato-net-10-million-usernames.txt` |
| `/usr/share/hashcat/rules/` | hashcat rule sets: `best66.rule`, `dive.rule`, `leetspeak.rule`, `rockyou-30000.rule`, `combinator.rule`, `toggles1-5.rule` |

`rockyou.txt.gz` is gzipped: hashcat reads it directly, but other tools need
it expanded (`gzip -dk /usr/share/wordlists/rockyou.txt.gz`) - and do that
once, into the engagement directory, not in place in `/usr/share`.

Rule set choices, in the order they are worth trying:

1. `best66.rule` - the general-purpose mutation set. Try it first.
2. `dive.rule` - deeper mutations, slower, resolves more.
3. `rockyou-30000.rule` - applies to `rockyou` specifically.
4. `leetspeak.rule` - when the password looks like a deliberate substitution.
5. `combinator.rule` - combines two words, for the `Word+Year` shape.

---

## 5. Attack modes

| `-a` | Mode | Use it for |
|---|---|---|
| 0 | Straight | Wordlist, optionally with `-r` rules. The default and the right first choice |
| 1 | Combination | Two wordlists concatenated |
| 3 | Brute-force | A mask (`?l?l?d?d`). Only after the wordlist and rules fail |
| 4 | PCFG | Password-based cracking grammar; needs the `-a 4` rulesets installed |
| 6 | Hybrid wordlist + mask | Wordlist inside a mask - `?d?w?d?d` |
| 7 | Hybrid mask + wordlist | The other hybrid direction |
| 9 | Association | Cracks a hash against a username taken from the hash list |
| 12 | Hybrid, two wordlists | A mask that places one wordlist inside another |

The current build (7.x) also has attack modes 5 (table) and 8 (generic).
The 6.2.x builds shipped on older Kali images number them differently - mode
4 was "permutation" and there was no generic mode - so read the mode list
printed by `hashcat -hh` on the box rather than trusting the table above
blindly.

### Masks

| Token | Character set |
|---|---|
| `?l` | lowercase `a-z` |
| `?u` | uppercase `A-Z` |
| `?d` | digits `0-9` |
| `?h` | hex lowercase `0-9a-f` |
| `?H` | hex uppercase `0-9A-F` |
| `?s` | special characters |
| `?a` | all of the above |
| `?w` | the word from the wordlist (hybrid modes) |

Check the size of a mask before running it - `hashcat --keyspace` prints the
keyspace, and a mask that turns out to be 10^14 candidates is a multi-day
run:

```bash
hashcat --keyspace '?u?l?l?l?l?l?d?d?d'
```

A mask built from the observed password shape is far more productive than a
generic one: `?u?l?l?l?l?l?d?d?d?d` for a capitalised word plus four digits
is a keyspace of 26 x 26^4 x 10^4, which a GPU resolves in minutes.

---

## 6. Rules, potfile and sessions

- The potfile records every cracked hash and its plaintext. hashcat skips
  pairs already in it, so repeated runs get cheaper. It lives in the
  hashcat profile directory - `~/.local/share/hashcat/hashcat.potfile` on
  current builds, `~/.hashcat/hashcat.potfile` on older ones.
- `hashcat --show` lists what the potfile already holds, for the hashes in a
  file. Run it before a long cracking session: the answer may already exist.
- `hashcat --left` lists the hashes that are still uncracked.
- `hashcat --restore` resumes an interrupted session; `--session <name>`
  names it, and `--runtime <seconds>` bounds a run.
- `--outfile` writes the cracked pairs to a file, which is where the result
  belongs. The plaintext goes into the artifact, not into the transcript.

## 7. Choosing the right tool for the job

| Situation | Tool |
|---|---|
| A hash from an AD or Windows system | `cyber_hash_crack` with hashcat |
| A hash that needs a custom construction | John the Ripper's `dynamic` format |
| A PDF, Office, KeePass or archive password | `cyber_hash_crack` with the matching mode |
| A Kerberos ticket | `cyber_hash_crack` with the etype mode |
| A hash of unknown type | `cyber_hash_id` first, always |
| A live service with a credential list | `cyber_password_audit` |
| A key or password in the client's own files | `cyber_secret_scan` |

## 8. Do not

- Do not report "strong password" from a failed crack. It may be the wrong
  mode, a missing salt, or a wordlist that does not contain the pattern.
- Do not print a cracked password into the transcript, the finding body, or
  the report. Summarise the class of the credential and point at the
  artifact.
- Do not run an unbounded brute force. Check `--keyspace` first, set a
  `--runtime`, and record what was left unattacked.
- Do not spray a live service before reading its lockout policy and
  calculating the attempts-per-account budget.
- Do not reuse a recovered credential against another host without the
  operator's approval.
