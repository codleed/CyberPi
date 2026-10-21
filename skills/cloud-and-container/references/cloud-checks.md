# Cloud and container check reference

Item-by-item check lists for the `cloud-and-container` skill. Each line is a
question with a definite answer you can obtain from the environment. Work the
list; do not paraphrase it from memory.

**Reading rules**

- A "no" in this document is a finding only when the answer comes from the
  live system, not from assumption.
- Where the check is a configuration review, note the resource that carries
  the misconfiguration, not just the check that failed.
- The severity table at the end maps answers to ratings; use it instead of
  inventing a rating per finding.

---

## 1. Identity and boundary

- [ ] Which account / subscription / project is the harness operating in?
- [ ] Which principal, and via which role-assumption chain?
- [ ] Is the credential a user, an assumed role, an instance profile, a
      workload identity, or a Kubernetes service account?
- [ ] What is the credential's issue date, expiry, and last rotation?
- [ ] Is the client identity (user, federation, OIDC provider) in the scope
      document, and does the scope list the tenant identifier, not just the
      console hostname?
- [ ] Which endpoints are actually reachable from the harness position
      (internet, peering, transit, VPN)?

## 2. IAM and role trust

### 2.1 Policy content

- [ ] `Action: "*"` on any principal that is not a break-glass account.
- [ ] `Resource: "*"` on any action that touches data (read, write, decrypt).
- [ ] Action-level wildcards that hide a dangerous verb, e.g. `s3:*`,
      `iam:*`, `kms:*`, `ec2:*`, `sts:*`.
- [ ] `iam:PassRole` with a wildcard resource, especially combined with a
      compute service.
- [ ] `NotAction` blocks that silently widen the policy.
- [ ] Conditions that are always true (`StringEquals` on an empty condition,
      `Bool` on `aws:MultiFactorAuthPresent` with a wildcard principal).
- [ ] Permissions boundary or SCP that does not actually reduce the
      effective permissions of the role.

### 2.2 Privilege escalation chains

Check whether the principal can reach a higher-privileged principal through
one of these. Each is a separate finding; name the chain in the description.

| Chain | Actions needed |
|---|---|
| Create and set a policy version | `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`, `iam:GetPolicyVersion` |
| Attach a policy to a user or role | `iam:AttachUserPolicy`, `iam:AttachRolePolicy`, `iam:AttachGroupPolicy` |
| Write inline policy | `iam:PutUserPolicy`, `iam:PutRolePolicy`, `iam:PutGroupPolicy` |
| Mint a key for another user | `iam:CreateAccessKey` (plus `iam:CreateLoginProfile`) |
| Assume a more privileged role | `sts:AssumeRole` (plus trust) |
| Pass a role to compute | `iam:PassRole` + `lambda:CreateFunction`/`UpdateFunctionCode` or `ecs:RunTask` or `ec2:RunInstances` or `cloudformation:CreateStack` |
| Command execution on a host | `ssm:SendCommand`, `ssm:StartSession`, `ec2:GetConsoleOutput` |
| Update a Lambda deployment | `lambda:UpdateFunctionCode` on a function the principal can also invoke |
| Decrypt everything | `kms:Decrypt` on a customer-managed key, or `kms:ScheduleKeyDeletion` |
| Read secrets | `secretsmanager:GetSecretValue`, `ssm:GetParameter` (decrypt) |

### 2.3 Trust policies

- [ ] `Principal: "*"` in a trust policy.
- [ ] Trust of `*` with `sts:ExternalId` (usable once the external id leaks).
- [ ] Trust of a third-party provider account without `sts:SourceIdentity` or
      an IP/VPCCondition restriction.
- [ ] Trust conditions that key on `aws:SourceArn` or `aws:SourceAccount` that
      an attacker could impersonate.
- [ ] Federation trust with an overly broad SAML audience or an OIDC
      `sub`/`aud` condition that is not pinned.
- [ ] Service principals with write permissions (`lambda.amazonaws.com` with
      `*`, `ec2.amazonaws.com` with `iam:*`).

### 2.4 Credential hygiene

- [ ] Root account enabled, or root access keys present.
- [ ] MFA not enforced for human principals with console access.
- [ ] Access keys older than the rotation policy, or keys on principals that
      should never hold long-lived keys.
- [ ] Duplicate keys across accounts (a key reused in two roles multiplies
      the blast radius).
- [ ] Service account keys (legacy) instead of short-lived workload
      identity.
- [ ] Unknown principals — list the principals that have used the account
      recently (`CloudTrail`) and flag any that nobody recognizes.

## 3. Storage exposure

### 3.1 Object storage (S3 and equivalents)

- [ ] Public access block: all four settings enabled, at bucket and account
      level.
- [ ] Bucket policy with `Principal: "*"` — including `"AWS": "*"` and
      `"Service": "*"`.
- [ ] Object ACLs granting `AllUsers` or `AuthenticatedUsers`.
- [ ] Website hosting enabled on a bucket that also holds data.
- [ ] Cross-account grants to accounts the client has not named.
- [ ] Object lock and versioning — is there a recovery path after an
      accidental delete or a ransomware-style overwrite?
- [ ] Server-side encryption, and whether the key is customer-managed with a
      policy that is not `Principal: "*"`.
- [ ] Lifecycle rules that replicate to a bucket with weaker controls.
- [ ] Access points, object lambda and access grants that bypass the bucket
      policy.
- [ ] Deprecated `aws:SourceIp` conditions that still trust a CIDR the
      client has since reallocated.

### 3.2 Block and file storage

- [ ] EBS/AMI snapshots: encrypted, not shared with other accounts.
- [ ] EFS/FSx export policies allowing `0.0.0.0/0` or `::/0`.
- [ ] Backup vaults: cross-account restore permissions, public recovery
      points.
- [ ] Azure storage accounts: public network access set to "Enabled",
      container public access, shared access signature URIs in the code
      base, storage firewall bypass with `networkAcls.defaultAction` allow.
- [ ] GCP buckets: `allUsers`/`allAuthenticatedUsers` binding, uniform
      bucket-level access disabled, retention policy unset.

### 3.3 Databases and caches

- [ ] `PubliclyAccessible` on RDS/Aurora instances, plus a security group
      open to the world.
- [ ] Snapshot or backup sharing outside the account.
- [ ] Encryption at rest, and the key policy.
- [ ] Automated backups retained longer than the data requires.
- [ ] Connection strings and passwords in the IaC, the CI, or the container
      image.

### 3.4 Verifying exposure

Listing the bucket and reading one benign object is normal proof. Bulk
download is not — and it is also the fastest way to turn a finding into an
incident. Confirm readability, record the object count and the ACL, and stop.

## 4. Network and management plane

- [ ] Security groups and network ACLs with `0.0.0.0/0` or `::/0` on admin
      or data ports (22, 23, 3389, 3306, 5432, 1433, 27017, 6379, 9200,
      6443, 2375, 8080).
- [ ] IPv6 rules reviewed separately — an open `::/0` is a distinct finding
      from the IPv4 one.
- [ ] Management ports exposed through a load balancer or an ingress.
- [ ] Private endpoints and VPC endpoints that should have replaced a public
      one.
- [ ] Peering and transit gateway routes that cross an account boundary.
- [ ] CloudFront or CDN in front of an origin with no origin access control.
- [ ] IMDS reachable (`169.254.169.254`) from a network that was not meant
      to reach it — `hop limit 1` mitigations present?
- [ ] IMDSv2 required, or IMDSv1 still accepted.

Port list for `cyber_service_scan` when hunting management planes. Pass the
relevant rows as a comma-separated `ports` list (`"6443,8443,8080,8001"`) or
as a range (`"1-1024"`), and add `nse_scripts` when you need the service and
version behind the port:

| Service | Ports |
|---|---|
| Kubernetes API server | 6443, 8443, 8080, 8001 |
| kubelet | 10250, 10255 |
| etcd | 2379, 2380 |
| Kubernetes dashboard | 8443 |
| Docker API | 2375, 2376 |
| containerd / CRI | 10250, 9898 |
| Consul | 8500, 8501, 8502, 8503 |
| Vault | 8200, 8201 |
| Argo CD | 8080, 443 |
| Harbor | 443, 8080 |
| Rancher | 443 |
| GitLab | 22, 80, 443, 8929 |
| SonarQube | 9000 |
| Jenkins | 8080, 50000 |
| Databases | 3306, 5432, 1433, 27017, 6379, 9200, 9042, 8529 |
| Remote access | 22, 23, 3389, 5900 |

## 5. Kubernetes

### 5.1 API server exposure

- [ ] API server reachable from outside the cluster network.
- [ ] Insecure port 8080 disabled.
- [ ] Anonymous authentication disabled, and `--anonymous-auth=false`.
- [ ] RBAC authorization enabled (`--authorization-mode=Node,RBAC`).
- [ ] Audit logging on and shipped somewhere the cluster operator cannot
      edit.
- [ ] etcd encrypted at rest and reachable only over TLS.

### 5.2 Service accounts and RBAC

- [ ] Every workload runs with a dedicated service account, not `default`.
- [ ] `automountServiceAccountToken: false` where the API is not needed.
- [ ] `kubectl auth can-i --list` for the token in hand: check for `*` verbs on
      `*` resources, `create pods`, `create pods/exec`, `get secrets`,
      `list pods`, `impersonate`, `escalate`, `bind`.
- [ ] `cluster-admin` or wildcard bindings (`cluster-admin` via
      `system:masters`, `*/*` roles).
- [ ] `escalate` and `bind` verbs on roles — these are escalation by
      themselves.
- [ ] Secrets readable across namespaces by low-privilege identities.
- [ ] Pod exec and `pods/attach` allowed for the reviewed identity.

### 5.3 Pod and node configuration

- [ ] `privileged: true` pods, `hostNetwork`, `hostPID`, `hostIPC`.
- [ ] `hostPath` volumes that mount the host root or `/var/lib/kubelet`.
- [ ] `allowPrivilegeEscalation` not disabled, `runAsUser: 0`.
- [ ] Pod Security Admission in `restricted` mode, and namespace labels
      enforcing it.
- [ ] Missing resource limits (a DoS and a noisy-neighbour risk).
- [ ] Image pull policy `Always` with mutable tags, and no image signature
      verification.
- [ ] Secret values in plain `Secret` objects rather than an external
      secret manager (and no etcd encryption at rest).
- [ ] Service account tokens with long, unbounded expiry.

### 5.4 Node and kubelet

- [ ] Kubelet 10250 anonymous or certificate-authenticated access.
- [ ] Kubelet read-only 10255 exposed.
- [ ] Node authorizer / NodeRestriction enabled.
- [ ] Container runtime socket exposed on the node.

## 6. Container escape primitives

Check the effective capability set against this list. The effective set
(`CapEff`) is what matters; `CapBnd` is the ceiling.

| Capability | Consequence |
|---|---|
| `CAP_SYS_ADMIN` | Mount, namespace manipulation, cgroup v1 `release_agent` escape, legacy container breakout |
| `CAP_SYS_MODULE` | Load a kernel module — direct root on the host |
| `CAP_SYS_PTRACE` | Read and write other processes' memory, inject into them |
| `CAP_DAC_READ_SEARCH` | Read any file, bypassing file permissions |
| `CAP_DAC_OVERRIDE` | Bypass read and write permission checks |
| `CAP_FOWNER` | Bypass ownership checks (chown to self, then write) |
| `CAP_CHOWN` | Change file ownership |
| `CAP_SETUID`, `CAP_SETGID` | Change the effective user, drop to root |
| `CAP_SETPCAP` | Grant capabilities the bounding set does not otherwise allow |
| `CAP_NET_ADMIN` | Reconfigure interfaces, routes, and the netfilter rules of the host namespace |
| `CAP_NET_RAW` | Raw sockets, packet sniffing, ARP spoofing |
| `CAP_BPF` | Load eBPF programs — kernel-level control |
| `CAP_PERFMON` | Read kernel and process performance counters, including kernel memory |
| `CAP_SYSLOG` | Read the kernel ring buffer, including host messages |
| `CAP_CHECKPOINT_RESTORE` | Read and write process memory, including kernel pointers |
| `CAP_MKNOD` | Create device nodes, reaching host block devices |
| `CAP_SYS_RAWIO` | Raw I/O on the host's devices |
| `CAP_SYS_BOOT` | Reboot or halt the host |
| `CAP_SYS_TIME` | Change the system clock, defeat time-based controls |
| `CAP_AUDIT_CONTROL`, `CAP_AUDIT_WRITE` | Tamper with the audit trail |

Escape routes, in the order they are worth testing:

1. **Docker socket** — `/var/run/docker.sock` is full control of the daemon:
   mount the host root, start a privileged container. Equivalent: the
   containerd socket (`/run/containerd/containerd.sock`) and the CRI socket.
2. **Host filesystem** — a read-write bind mount of `/`, `/etc`, `/root`,
   `/var/lib/kubelet`, or `/proc/1/root`.
3. **cgroup v1 `release_agent`** — with a writable `/sys/fs/cgroup`, write to
   `release_agent`; the command runs as root on the host when the cgroup is
   removed. `notify_on_release` must be set. cgroup v2 closes this path.
4. **Kernel interfaces** — writable `/proc/sysrq-trigger`, writable
   `/proc/sys/kernel/core_pattern` (point it at a script you control), a
   readable `/dev/mem`, a writable `/dev/kmsg`.
5. **Kernel exploit** — `uname -a` and correlate the version with known
   container escapes (`dirty pipe` CVE-2022-0847, `runc` and `containerd`
   CVEs, overlayfs and `nsfs` issues). Use the CVE tooling to look the
   version up rather than guessing.
6. **Namespace confusion** — shared PID namespace (`ps` shows host
   processes), shared network namespace (host management interfaces
   reachable), shared IPC.
7. **Metadata service** — `169.254.169.254` reachable from the pod yields
   the instance role, and with it the cloud account. This is the most common
   real-world escape and it needs no exploit.
8. **Cluster API** — the pod's service account token reaching a permissive
   API server, and from there `pods/exec` into a privileged pod or
   `create pods` with a `hostPath` mount.
9. **Device access** — `/dev/sd*`, `/dev/mapper/*`, `/dev/kvm` present
   through the container's `/dev`.

### 6.1 Escape verification, safely

Confirm the primitive without executing the exploit:

- the socket exists and is writable → `ls -l` and a `test -w` check;
- the mount is read-write → the mount options in `/proc/self/mountinfo`;
- the capability is present → `capsh --print` and `CapEff` in
  `/proc/self/status`;
- the cgroup is writable → `test -w` on `release_agent` and the value of
  `notify_on_release`.

Report the primitive and the safe verification. Executing the escape is a
separate, explicit instruction from the operator.

## 7. Image and registry review

### 7.1 Image configuration

- [ ] `User` is not root (or root is required and the risks are accepted).
- [ ] `ENTRYPOINT`/`CMD` — a shell as the entrypoint means the container
      starts with a root shell.
- [ ] `ADD`/`COPY` of `.aws/credentials`, `.ssh/`, `.dockerconfig.json`,
      `.kube/config`, `.npmrc`, `.pypirc`, `*.pem`, `*.key`.
- [ ] Build-time `ARG` and `ENV` values that were never unset — `docker
      history` shows them, and the value stays in the layer.
- [ ] A copy of `.git/` in the image (full history, including deleted
      secrets).
- [ ] Package manager caches and build tooling left in the final layer.
- [ ] `apt`/`apk`/`yum` sources pointing at an internal mirror (information
      leak, and a supply-chain pivot).
- [ ] Exposed ports and health checks that bind `0.0.0.0`.
- [ ] Base image: distribution, version, and whether it is still supported.
- [ ] Known vulnerable packages (`trivy image`, `grype`, `dive`).
- [ ] The image's own CVEs, correlated through the CVE tooling.

### 7.2 Registry

- [ ] Repository policy: who can push, who can pull, is `*` allowed.
- [ ] Publicly accessible repository (ECR, GCR, ACR, Docker Hub, GHCR).
- [ ] Tag mutability: mutable production tags defeat provenance.
- [ ] Image scanning on push, and results that are acted on.
- [ ] Image signing and verification (cosign, Notary) in the deployment
      path.
- [ ] Retention and lifecycle rules for old images holding vulnerable
      versions.
- [ ] Cross-account pull grants to unknown accounts.
- [ ] A registry credential in an image, an env var or a mounted secret — a
      push credential is a write primitive on production.
- [ ] Build pipeline: does the CI push to a registry the runtime can pull
      from, and can a user inject a layer?

## 8. Severity guidance

| Situation | Severity |
|---|---|
| Demonstrated host, cluster or cloud account control from a container | Critical |
| Account-wide write or admin privilege proven (`iam:*`, `Action: "*"`) | Critical |
| Read access to production secrets, customer data or PII proven | Critical or High |
| Public bucket containing sensitive data | Critical (data) / High (readable but unverified) |
| Escape primitive present but not exercised | High |
| Over-permissive role allowing privilege escalation by one action | High |
| Management plane exposed to the internet (API server, etcd, kubelet) | High |
| Unrestricted `PassRole` plus a compute service | High |
| Public bucket with no sensitive content identified | Medium |
| Open security group on an administrative port | Medium |
| Service account with wildcard RBAC on a non-sensitive namespace | Medium |
| Long-lived credentials in an image or repository | Medium |
| Missing `no-new-privileges`, unnecessary capabilities, AppArmor not
  enforcing | Low |
| Untagged or unpinned images, scanning not enabled | Low or Info |

Adjust with the blast radius: a wildcard policy in a sandbox account is
Medium, the same policy in production is Critical.

## 9. Command cheat sheet

Read-only inspection. Every command here is safe to run; none of them changes
the target.

### Cloud identity and inventory

```bash
aws sts get-caller-identity
aws configure list-profiles
aws iam list-users
aws iam list-roles
aws iam list-access-keys
aws iam get-role --role-name <role>
aws iam list-attached-role-policies --role-name <role>
aws iam get-role-policy --role-name <role> --policy-name <policy>
aws iam get-account-password-policy
aws s3api list-buckets
aws s3api get-public-access-block --bucket <bucket>
aws s3api get-bucket-policy --bucket <bucket>
aws s3api get-bucket-acl --bucket <bucket>
aws ec2 describe-security-groups
aws rds describe-db-instances
aws kms list-keys
```

Use `cyber_cloud_enum` for the same queries so the results are journalled and
cached; the commands are here to show what the enumeration covers.

### Kubernetes

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
kubectl auth can-i --list
kubectl get secrets -A
kubectl get pods -A -o wide
kubectl get clusterrolebindings -o wide
kubectl get psa,events
```

### Container inspection

```bash
cat /proc/1/cgroup
cat /proc/self/status
capsh --print
cat /proc/self/attr/current
cat /proc/self/mountinfo
ls -l /var/run/docker.sock /run/containerd/containerd.sock
test -w /sys/fs/cgroup/cgroup.release_agent && echo writable
ip addr
ip route
curl -s --max-time 2 -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/service-accounts/
```

The metadata request is read-only and proves reachability. Do not request
credentials unless the operator asked for them.

### Image review

```bash
docker image inspect <image>
docker history --no-trunc <image>
docker image save <image> -o /tmp/image.tar
trivy image <image>
dive <image>
```

### Secret hunting

```bash
trufflehog filesystem <path> --json
trufflehog git file://<repo-path> --json
```

Use `cyber_secret_scan` for both so the output lands in the engagement
artifacts and the transcript stays clean.
