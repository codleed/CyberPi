---
name: cloud-and-container
description: Assess cloud tenants, container platforms and Kubernetes. Use when enumerating cloud identities and resources, reviewing IAM policies, role trust and storage exposure, hunting public buckets and over-permissive roles, checking container escape paths from inside a running container, reviewing container images and registries, or testing Kubernetes API access and RBAC.
compatibility: Kali Linux with awscli, nmap, trufflehog and chisel installed.
---

# Cloud and container assessment

Two tracks that share one method: enumerate what exists, then read what the
existing permissions actually allow.

- **Track A — cloud review workflow.** The cloud tenant is a large attack
  surface reachable with the credentials already on the box. Enumerate
  identities, enumerate resources, review IAM, review storage, review network
  exposure, hunt secrets, pivot into planes that are not directly routable.
- **Track B — container escape checklist.** From inside a container, decide
  whether the container is a jail or a doorway. Capabilities, mounted host
  paths, kernel interfaces, runtime sockets and the Kubernetes API are the
  ways out; the checklist names each one and how to prove it.

Read `references/cloud-checks.md` for the item-by-item check lists, the
severity guidance and the command cheat sheet. Do the work from there rather
than improvising checks.

## Rules that apply to both tracks

1. **Read-only until the operator says otherwise.** Enumeration, reading and
   validation are in scope by default. Creating, modifying or deleting a cloud
   resource, and writing to a bucket, are not — ask first, even when the
   finding is obvious.
2. **Every network action is scope-checked.** The toolkit refuses targets that
   are not in `.cyberpi/scope.json`. A refusal is not a bug: it means the
   tenant identifier, API hostname or CIDR has to be added by the operator.
   Add cloud API endpoints (`sts.<region>.amazonaws.com`,
   `*.eks.<region>.amazonaws.com`, `*.management.azure.com`, the VPC endpoint
   DNS names) and cluster CIDRs to the scope before the scan, and note the
   absence of a scope as a finding-adjacent risk in the report.
3. **Never print credential material.** Cloud keys, session tokens, kubeconfig
   bearer tokens and SSH keys go to the artifact file, not into the transcript.
   `cyber_secret_scan` already does this — report the artifact path and the
   count of findings per type, never the secret values.
4. **Verify the identity before the privilege.** The first question in a cloud
   assessment is "which account am I in", not "what can I reach". An
   enumeration that runs against the wrong tenant is not a finding.

## The tools

| Tool | Technique | Requires | Use it for |
|---|---|---|---|
| `cyber_cloud_enum` | `cloud-enumeration` | `aws` | Identities, IAM, resources and storage in the cloud account |
| `cyber_service_scan` | `service-enumeration` | `nmap` | Management-plane and container-platform ports on a scoped host |
| `cyber_secret_scan` | `password-audit` | `trufflehog` | Secrets in repos, config, cloud credential files and manifests |
| `cyber_pivot` | `pivot` | `chisel` | Reaching internal management endpoints through an authorized pivot host |

The tool schemas published in the current session are authoritative for
parameter names. The table below states the intent of each call; map it onto
whatever the schema declares.

| Intent | Call |
|---|---|
| Who am I, and which account/tenant am I in | `cyber_cloud_enum` on the caller-identity / current-account view |
| List identities (users, roles, service principals, keys) | `cyber_cloud_enum` on the IAM identity view |
| List resources of one service (S3, EC2, RDS, Lambda, EKS, KMS, …) | `cyber_cloud_enum` on that service's list/describe view, optionally pinned to a region |
| List buckets and their exposure flags | `cyber_cloud_enum` on the storage view |
| Reach an internal API server, kubelet, etcd or registry | `cyber_pivot` through an authorized host that routes to it |
| Enumerate exposed management ports on a host | `cyber_service_scan` with `target` = the host and `ports` = the management port list |
| Identify the service behind a management port | `cyber_service_scan` with `target`, `ports` and `nse_scripts` (for example `http-title,safe`) |
| Find hardcoded keys, tokens and passwords in files | `cyber_secret_scan` on the path to scan |
| Prove a finding | `cyber_record_finding` with the evidence and the artifact path |

`cyber_service_scan` needs raw privileges for a SYN scan — CyberPi has to run
as `sudo` on Kali for it to work. If it comes back with open ports and no
service detail, check the privileges before trusting the result.

---

## Track A — Cloud review workflow

Work the steps in order. Each step produces the inputs for the next one.

### Step 1 — Fix the boundary

Identify the tenant and the identity before touching anything.

- Environment: `AWS_PROFILE`, `AWS_REGION`, `AWS_DEFAULT_REGION`,
  `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `GOOGLE_CLOUD_PROJECT`,
  `GOOGLE_APPLICATION_CREDENTIALS`, `KUBECONFIG`, `KUBE_TOKEN`.
- On disk: `~/.aws/credentials`, `~/.aws/config`, `~/.azure/`,
  `~/.config/gcloud/`, `~/.kube/config`, `/var/run/secrets/kubernetes.io/serviceaccount/`.
- Record: account id, subscription id, project id, cluster API server URL,
  source of each credential (who issued it, when).

If the credential is a role assumption chain, follow it: the role chain is
usually where the real privilege boundary is.

### Step 2 — Enumerate identities

Use `cyber_cloud_enum` on the IAM view and capture, for every principal:

- the principal type, ARN/ID, creation date and last-used date;
- access keys: count, age, last rotated, MFA status;
- attached and inline policies, and the permissions they grant;
- role trust policies: which principals may assume the role, and under which
  conditions (external id, source IP, MFA, source VPC);
- whether the root account or a service-account-equivalent is enabled.

Never output a key. The enumeration returns key metadata, and the summary
should carry identifiers, not secrets.

### Step 3 — Enumerate resources

Use `cyber_cloud_enum` per service, in this order — services earlier in the
list expose the most:

1. Identity: IAM, organizations, SSO, access analyzer, STS.
2. Storage: S3 and object storage, EFS, EBS snapshots, backup vaults.
3. Compute: EC2 instances, launch templates, Lambda functions and versions,
   ECS/EKS clusters, Auto Scaling groups.
4. Data: RDS/Aurora instances and snapshots, DynamoDB tables, Redshift,
   ElastiCache, KMS keys.
5. Network: VPCs, subnets, security groups, route tables, load balancers,
   CloudFront distributions, API Gateway, NAT gateways.
6. Messaging and delivery: SNS, SQS, EventBridge, SES.

For every resource record: identifier, region, owner account, encryption
state, whether it is publicly reachable, and the security group or ACL that
governs it.

### Step 4 — Review IAM

This is where the real findings live. For each policy, evaluate the items in
`references/cloud-checks.md` under "IAM and role trust":

- `Action: "*"` or `Resource: "*"` on a non-trivial principal;
- a single action with a wildcard resource (`iam:PassRole` on `*`,
  `s3:GetObject` on `*`, `kms:Decrypt` on `*`);
- privilege-escalation chains — `iam:CreatePolicyVersion` +
  `iam:SetDefaultPolicyVersion`, `iam:AttachUserPolicy`/`AttachRolePolicy`,
  `iam:PutUserPolicy`, `iam:PassRole` + a compute service that executes code
  (`lambda:CreateFunction`/`UpdateFunctionCode`, `ecs:RunTask`,
  `ec2:RunInstances`), `iam:CreateAccessKey` for another user,
  `sts:AssumeRole` for a more privileged role, `ssm:SendCommand`;
- trust policies that are open to any account or any principal, or that
  trust a third-party provider without a condition;
- service principals granted broad write permissions;
- permissions boundaries and SCPs that do not actually constrain the role;
- long-lived access keys on humans, and keys on principals that should be
  role-only.

Score each as a separate finding with the shortest escalation chain you can
demonstrate. A wildcard policy is a finding; "this wildcard lets me read
another team's production bucket" is a finding that survives a review meeting.

### Step 5 — Review storage exposure

For every bucket, container and share, use `cyber_cloud_enum` on the storage
view and check:

- public access block enabled on all four settings (block public ACLs, block
  public policy, ignore public ACLs, restrict public buckets);
- bucket policy `Principal: "*"` — including `"AWS": "*"` and service
  principals;
- object ACLs and object-level public grants;
- versioning and object lock (does a mistake have a recovery path);
- encryption at rest with a customer-managed key, and the key policy;
- cross-account grants and whether the other account is known to the client;
- lifecycle rules that copy objects to a less-protected bucket;
- Azure: storage account public access level, container public access, SAS
  URIs, and storage account firewall rules;
- GCP: bucket IAM bindings, `allUsers`/`allAuthenticatedUsers`, uniform
  bucket-level access;
- RDS: `PubliclyAccessible`, security group source, and snapshot sharing;
- ECR: repository policy, image scanning, tag mutability, and whether
  cross-account pull is allowed.

Then look for the data itself: object listing through a misconfigured bucket is
a confirmed exposure, not a theoretical one — but only download what the
operator authorized. Listing and reading a single benign object to prove
readability is normal; bulk exfiltration is not.

### Step 6 — Review network and management-plane exposure

Use `cyber_service_scan` against the scoped hosts, with the management port
set that matters for the platform:

| Platform | Ports |
|---|---|
| Kubernetes API | 6443, 8443, 8080 (insecure), 8001 |
| kubelet | 10250, 10255 (read-only) |
| etcd | 2379, 2380 |
| Dashboard | 8443 |
| Docker API | 2375, 2376 |
| containerd / CRI | 10250, 9898 |
| Consul | 8500, 8501, 8502, 8503 |
| Vault | 8200, 8201 |
| Rancher | 443 |
| GitLab | 22, 8929, 80, 443 |
| Databases | 5432, 3306, 1433, 27017, 6379, 9200, 2379 |
| RDP / SMB | 3389, 445 |

For the containers, clouds and databases found in step 3, verify that the
source of the scan is allowed by the security group — a management port
reachable from `0.0.0.0/0` is a finding on its own.

Also check security groups and firewall rules directly: `0.0.0.0/0` on 22,
3389, 3306, 5432, 27017, 6379, 9200, 6443 or 2375 is a finding; IPv6 `::/0`
on the same is a separate finding, because it is routinely forgotten.

### Step 7 — Hunt secrets

Use `cyber_secret_scan` on:

- the engagement working tree and any cloned repositories;
- cloud credential directories: `~/.aws`, `~/.azure`, `~/.config/gcloud`,
  `~/.kube`;
- IaC and deployment material: Terraform state (`terraform.tfstate` holds
  secrets in plaintext), `*.tfvars`, Helm values, Kubernetes manifests,
  Docker Compose files, CI configuration;
- build output, `.env` files, Terraform variables, and `*.pem`/`*.key`;
- inside a container: `/proc/1/environ`, `/proc/self/environ`, and the
  filesystem of the running workload.

Report the artifact path and a per-type count. Never paste a detected value
into the transcript, into a finding's `evidence` field, or into the report
body — reference the artifact and let the client open it.

### Step 8 — Pivot to what is not directly routable

Some management planes are reachable only from inside the network: a private
API server, an internal registry, a peering-only endpoint, a bastion. Use
`cyber_pivot` (chisel) to build the tunnel through an authorized host that
can reach them, then repeat steps 2, 5 and 6 against the internal targets.

Rules: the pivot host must itself be in scope, the tunnel endpoints must be
in scope, and the pivot is journalled. Do not pivot just to reach a host you
were not authorized to test — the scope check applies to the tunnel endpoint
as well.

### Step 9 — Record and report

For each confirmed issue, call `cyber_record_finding`:

- a title that names the problem and the asset, not a category;
- the target as the concrete resource identifier;
- severity per the guidance in `references/cloud-checks.md`;
- evidence as the command, the summary and the artifact path — never a secret;
- reproduction as the exact steps, so the client can re-run them.

Keep "control weakness" and "demonstrated impact" apart. A permissive policy
nobody can use is a weakness; a permissive policy that read a production
database is a critical finding, and the difference is the evidence.

---

## Track B — Container escape checklist

Run this from inside the container. Everything here is read-only inspection
of the local filesystem and the local kernel — no network action except the
targeted checks in steps 6 and 7.

The goal is one verdict: **can this container reach the host, the cluster, or
the cloud account?** A single yes is an escape path; the finding is the
shortest path, not the longest list.

### 1. Confirm the container boundary

- `/.dockerenv`, `/run/.containerenv` — container runtime detected.
- `/proc/1/cgroup` — the runtime and, on cgroup v1, the host hierarchy.
- `/proc/self/mountinfo` — the real mount table, including bind mounts.
- `ps aux` — if you can see processes you did not start, the PID namespace is
  shared with the host.
- `/proc/1/cmdline` — the container's entrypoint; sometimes the host's init
  when the PID namespace is shared.

### 2. Check the privilege surface

- `id`, `cat /proc/self/status` — `Uid`, `Gid`, `CapEff`, `CapBnd`,
  `CapPrm`, `NoNewPrivs`, `Seccomp`.
- `capsh --print` (from `libcap2-bin`) — decoded capability sets.
- `cat /proc/self/attr/current` and `/sys/kernel/security/apparmor/profiles` —
  the AppArmor profile in force.
- `ls -l /sys/fs/cgroup` and `cat /sys/fs/cgroup/cgroup.controllers` — cgroup
  v1 or v2. The version decides which escape technique applies.

### 3. Look for dangerous capabilities

`CAP_SYS_ADMIN` is the one that matters: with it, a container can mount, mount
namespaces are trivial to manipulate, and on cgroup v1 it enables the
`release_agent` escape. `CAP_SYS_MODULE` loads a kernel module outright.
`CAP_SYS_PTRACE` allows reading another process's memory and injecting into
it. `CAP_DAC_READ_SEARCH` reads any file. `CAP_NET_ADMIN` reconfigures the
network stack. `CAP_SETUID`/`CAP_SETGID`/`CAP_FOWNER`/`CAP_CHOWN` widen file
ownership. `CAP_MKNOD` creates device nodes. `CAP_SYS_RAWIO` and
`CAP_BPF` reach the raw kernel. `CAP_PERFMON` and `CAP_CHECKPOINT_RESTORE`
are commonly over-granted and enable kernel memory reads. `CAP_NET_RAW`
enables raw sockets and packet sniffing inside the container.

List the ones actually present, and match the effective set against the
capability list in `references/cloud-checks.md`.

### 4. Enumerate mounted host paths

From `/proc/self/mountinfo`, look for anything mounted from the host:

| Path | Why it matters |
|---|---|
| `/var/run/docker.sock`, `/run/docker.sock` | Full control of the Docker daemon — the classic escape |
| `/run/containerd/containerd.sock`, `/run/k3s/containerd/containerd.sock` | containerd control, equivalent impact |
| `/host`, `/mnt/host`, `/rootfs` | The host filesystem mounted directly |
| `/proc/1/root` | The host root through the init process |
| `/var/lib/kubelet`, `/etc/kubernetes` | Cluster secrets and kubelet credentials |
| `/var/run/secrets/kubernetes.io/serviceaccount` | The pod's service account token |
| `/sys/fs/cgroup` writable | cgroup v1 escape via `release_agent` |
| `/proc/sysrq-trigger`, `/proc/sys/kernel/*` writable | Kernel-level write primitives |
| `/dev` | Device nodes — `/dev/sd*`, `/dev/mem`, `/dev/kmem`, `/dev/kmsg` |

Distinguish read-only bind mounts from read-write. A read-only `/var/lib/kubelet`
is information; a writable `/etc` on the host is the escape.

### 5. Test the cgroup and kernel escape paths

- cgroup v1: if `/sys/fs/cgroup` is writable, the `release_agent` trick applies
  — writing to `release_agent` executes a command as root on the host when the
  cgroup is removed. Confirm writability and the presence of
  `notify_on_release` before calling it.
- cgroup v2: the classic path is closed; a kernel exploit is the remaining
  route. Record `uname -a` and check it against known kernel escapes.
- `/proc/sysrq-trigger` writable, `/proc/sys/kernel/core_pattern` writable,
  `/dev/mem` readable: each is a privilege boundary failure on its own.
- Kernel version: note it and correlate it with known container escapes
  (`dirty pipe` CVE-2022-0847, `runc` and `containerd` CVEs, `overlayfs`
  issues). Use the CVE tooling to check the version rather than guessing.

### 6. Check network reach

- Is the container on the host network namespace? Compare `ip addr` with the
  node's addresses and check for the host's management addresses.
- Link-local metadata: `169.254.169.254` (AWS/Azure IMDS, GCP metadata
  `metadata.google.internal`). If reachable, the instance role and its
  credentials are one request away — that is the escape, and it is the most
  common one in practice.
- Cluster access: the API server from inside the pod, the kubelet on
  10250, and any NodePort service in the 30000-32767 range.
- Internal control planes reachable from the pod network: Consul, Vault,
  ArgoCD, Harbor, a database.

### 7. Check Kubernetes access

If a service account token is mounted, the API server is the next stop:

- the token at `/var/run/secrets/kubernetes.io/serviceaccount/token`, the
  namespace in `.../namespace`, and the CA in `.../ca.crt`;
- what the identity may do: `kubectl auth can-i --list`, and the specific
  verbs that matter — `create pods`, `exec`, `get secrets`, `list pods`,
  `create pods/exec`, `impersonate`;
- whether the token is bound to a role, whether automount is on, and how long
  the token lives;
- whether `kubectl get secrets -A`, `kubectl get pods -A` and pod exec into
  other workloads are permitted — pod exec into a privileged pod is an
  immediate escape;
- `hostPath` volumes and privileged pods in the cluster, and whether the pod
  can create one.

`cyber_service_scan` is the way to confirm the cluster's management ports from
the outside; the token check is the way to confirm what the pod can do.

### 8. Inventory credentials in the container

- Environment: `/proc/1/environ`, `/proc/self/environ` — cloud keys, database
  passwords, API tokens, kubeconfig paths.
- Filesystem: `~/.aws/credentials`, `~/.aws/config`, `~/.kube/config`,
  `~/.docker/config.json`, `/root/.ssh/`, `/run/secrets/`, mounted secrets,
  `/etc/environment`, cloud-init user-data.
- Use `cyber_secret_scan` on the filesystem paths to keep the values out of
  the transcript, and `cyber_pivot` only when the credentials are needed to
  reach an authorized next host.

### 9. Judge and record

State the escape path in one sentence, in this form:

> From the `<workload>` container, `<primitive>` gives `<host / cluster / cloud
> account>` access, demonstrated by `<what was done>`.

Then record it with `cyber_record_finding`, and separate:

- **Escaped** — you proved host, cluster or account control. Severity critical
  or high depending on the scope of the account reached.
- **Escape path present, not exercised** — the primitive is there (writable
  cgroup, docker socket, `CAP_SYS_ADMIN`) but you did not execute it. Severity
  high, and say plainly in the description that it was not executed.
- **Hardening gap** — missing `no-new-privileges`, AppArmor/SELinux not
  enforcing, capabilities that are unnecessary. Severity low or medium, and
  give the exact `securityContext` or `--cap-drop` that closes it.

Never execute a destructive escape (writing `release_agent`, mounting the host
root, running a privileged container) unless the operator explicitly asks for
proof. The primitive plus a safe read-only verification is a complete finding.

### 10. Image and registry review

From a host that can pull the image:

- configuration: `docker image inspect` — user (root?), entrypoint, exposed
  ports, volumes, env, labels, and `ADD`/`COPY` of credential files;
- history: `docker history` — build-time `ARG`/`ENV` values, `curl`/`wget`
  layers, package managers that leave credentials, the `.git` directory
  copied into the image;
- content: `trivy image`, `grype`, or `dive` for layers, packages and known
  vulnerabilities;
- the image's own vulnerability set, correlated with the CVE tooling;
- registry: ECR/GCR/ACR repository policies, public repositories, tag
  mutability, scanning and signing enabled, cross-account pull, retention and
  lifecycle rules;
- any `.dockerconfig.json` in the image or in a mounted secret — a registry
  password that grants push is equivalent to a write primitive on production.

From inside the running container, the same image is visible as
`/etc/os-release`, the kernel it shares with the host, and the secrets baked
into the layers.

---

## Reporting

- `cyber_record_finding` for each confirmed issue, with the asset identifier
  as the target and the artifact path as evidence.
- `cyber_journal` to review what was actually attempted, including the
  actions the scope refused.
- `cyber_surface` for the resource and host inventory built along the way.
- `cyber_report` at the end of the engagement.

## Reference

- `references/cloud-checks.md` — item-by-item check lists for IAM, storage,
  network, Kubernetes, container escape and image/registry review, with
  severity guidance and a command cheat sheet.
