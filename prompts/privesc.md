---
description: Enumerate the local privilege escalation surface and validate the findings
argument-hint: "[focus]"
---
Enumerate the privilege escalation surface of ${1:-this machine} and validate the findings.

## Arguments

- Focus: $1
- Extra instructions: $@

This is a local assessment. Everything stays on the machine CyberPi runs on, unless the operator names another target in the extra instructions.

## Steps

1. Establish the current context: the current user, its groups, the sudo privileges, and the kernel and distribution version. Then read the local configuration directly: `/etc/sudoers`, `/etc/sudoers.d/`, `/etc/crontab` and `/etc/cron.*`, the systemd timers, the setuid and setgid binaries, and the file capabilities on the filesystem. There is no CyberPi tool for this, so use the harness's own file and shell access. `sudo -n -l` is safe here because it only reads the policy.
2. `cyber_secret_scan` - scan the working directory and the local checkout for leaked secrets: API keys, private keys, cloud credentials, connection strings and passwords committed into configuration. Point it at the path you want with `path`, and use `since_commit` to keep the run to what changed recently. This is the fastest way to turn "the application runs here" into a foothold.
3. `cyber_hash_id` - identify the format of any password hashes you found, so the strength assessment later is meaningful. Pass the hashes in `hashes`.
4. `cyber_hash_crack` - attempt to recover the weak ones against the bundled wordlists, with the hashes in `hashes` and the wordlist in `wordlist`. Always set `time_limit` so the run stays bounded. Report the recovered account and the source file, never the plaintext in the transcript.
5. `cyber_password_audit` - only for services that listen locally and are named in the engagement scope. Pass the local host in `target` and the service in `service`.
6. `cyber_record_finding` - record every validated escalation path as a finding: the misconfiguration, the exact file or path, the preconditions it needs, the impact, and the reproduction.

## Rules

- Stay local by default. Do not attack a remote host just because its address appears in a config file.
- Never print a recovered password, token, private key or cookie. Name the account, the source file and the artifact path, and leave the secret in the artifact.
- Do not actually perform the escalation. Validate it with evidence such as file permissions, the policy text or a benign read of a root-only file, and describe the step that would work. A path is a finding only when you can show that its precondition holds.
- Mark everything else as unverified and say what evidence is missing.
