# Tunnel configuration snippets

Reference for the `pivoting-and-tunneling` skill. Every snippet targets Kali
Linux. Replace `PIVOT`, `ATTACKER`, `INTERNAL` and `TARGET` with the real
values for the engagement.

---

## cyber_pivot

`cyber_pivot` is the harness-managed way to run a tunnel. It spawns the
process detached, keeps the state in `.cyberpi/pivot/` and journals the
action. The commands it runs are listed below so that the same tunnel can be
reproduced by hand when the tool does not cover the case.

| Action | Command it runs |
|---|---|
| `start-chisel-server` | `chisel server --port <listen_port> --reverse --socks5` |
| `start-chisel-client` | `chisel client <target> R:<socks_port>:socks` |
| `socks-proxy` | `chisel client <target> 127.0.0.1:<socks_port>:socks` |
| `start-proxychains` | `chisel client <target> 127.0.0.1:<socks_port>:socks` |
| `port-forward` | `chisel client <target> 127.0.0.1:<listen_port>:<remote_host>:<remote_port>` |
| `start-ligolo-proxy` | `ligolo-proxy -selfcert -laddr 0.0.0.0:<listen_port>` |

Defaults: chisel port 8080, SOCKS port 1080, ligolo port 11601. Older
ligolo-ng releases use `-l <port>` instead of `-laddr 0.0.0.0:<port>`; the
tool detects this from `ligolo-proxy -h` and prints the usage line it used.

Files it writes:

```
.cyberpi/pivot/<tunnel>.json    tunnel state: command, pid, ports, paths
.cyberpi/pivot/<tunnel>.pid     pid of the background process
.cyberpi/pivot/<tunnel>.log     stdout and stderr of the process
.cyberpi/notes/proxychains-<tunnel>.conf   proxychains configuration
```

The tunnel name is the action plus the pivot host, for example
`chisel-client-pivot-10-0-0-5`. `kill_existing: true` stops the tunnel the
tool started earlier for the same action and target, which is the clean way
to replace one.

---

## chisel

Chisel has two roles. The **client** initiates the tunnel; the **server**
accepts it. The port specifications decide which machine listens and which
machine opens the connection to the destination.

### The attacker can reach the pivot

The pivot runs the server, the attacker runs the client and gets a local
SOCKS5 proxy.

```bash
# Pivot
chisel server --port 8080 --host 0.0.0.0
# Attacker
chisel client PIVOT:8080 127.0.0.1:1080:socks
```

The destination is reached from the pivot, which is the side with the route
into the internal network.

### The pivot can reach the attacker

The attacker runs the server, the pivot runs the client with a remote SOCKS5
proxy. The proxy appears on the attacker on the port named by the `R:` spec.

```bash
# Attacker
chisel server --port 8080 --reverse --socks5 --host 0.0.0.0
# Pivot
chisel client ATTACKER:8080 R:1080:socks
```

### Server flags

| Flag | Effect |
|---|---|
| `--port` | Port the chisel server listens on (the client connects to it) |
| `--host` | Interface to bind, `0.0.0.0` for all |
| `--socks5` | Accept `socks` remotes from the client |
| `--reverse` | Invert the direction of the tunnel (see below) |
| `--auth user:pass` | Require a shared secret, e.g. `cyberpi:<random>` |
| `--obfs` | Obfuscate the handshake so the traffic does not look like chisel |
| `--heartbeat` | Keepalive interval in seconds, e.g. `--heartbeat 30` |
| `--max-retry-count` | Reconnect attempts, `-1` for unlimited |

Chisel traffic is plain HTTP with a `CONNECT`-like method, so it passes
through most HTTP egress filters. `--obfs` makes it look like noise.

### Client port specifications

```bash
# Local SOCKS5 proxy on the client, port 1080
chisel client PIVOT:8080 127.0.0.1:1080:socks

# Remote SOCKS5 proxy on the server, port 1080
chisel client PIVOT:8080 R:1080:socks

# Local forward: listen on 127.0.0.1:8081, deliver to INTERNAL:80
chisel client PIVOT:8080 127.0.0.1:8081:INTERNAL:80

# Remote forward: the chisel server listens on 8081 and reaches INTERNAL:80
chisel client PIVOT:8080 R:8081:INTERNAL:80

# Two forwards in one session
chisel client PIVOT:8080 127.0.0.1:1080:socks 127.0.0.1:8081:INTERNAL:80
```

| Form | Meaning |
|---|---|
| `LOCAL:HOST:PORT` | Listener on the chisel client, destination reached through the server |
| `R:HOST:PORT` | Listener on the chisel server, destination reached through the client |
| `127.0.0.1:1080:socks` | SOCKS5 proxy on the chisel client, on port 1080 |
| `R:1080:socks` | SOCKS5 proxy on the chisel server, on port 1080 |
| `socks` as the host | SOCKS5 proxy instead of a plain forward |

The short form `1080:socks` is accepted as well; the explicit
`127.0.0.1:1080:socks` form is what the harness uses.

### Reverse mode

`--reverse` flips the direction of the tunnel: the chisel server acts as the
client, so the side with the route to the destination opens the connection
to it.

```bash
# Attacker
chisel server --reverse --port 8080 --host 0.0.0.0
# Pivot
chisel client ATTACKER:8080 R:1080:socks
```

The listener can land on either machine depending on the topology. Confirm
with `ss -tlnp` on both ends, then test with
`curl --socks5-hostname 127.0.0.1:1080 http://INTERNAL/`. `chisel --help` on
the installed version is the authority for the exact behaviour.

### Running the client persistently

A chisel client that exits kills the tunnel.

```bash
tmux new -d -s chisel 'chisel client PIVOT:8080 127.0.0.1:1080:socks'
tmux attach -t chisel
```

Or with `nohup`:

```bash
nohup chisel client PIVOT:8080 127.0.0.1:1080:socks > chisel.log 2>&1 &
echo $! > chisel.pid
```

### Hardening the server

```bash
chisel server --port 8443 --host 0.0.0.0 --auth cyberpi:"$(openssl rand -hex 16)" --obfs --heartbeat 30
```

Keep the secret out of the shell history and out of the transcript. Store it
in the engagement notes as a pointer, not as a value.

---

## SSH

### Dynamic (SOCKS5) forwarding

```bash
ssh -N -D 1080 -f \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=4 \
  user@PIVOT
```

### Local forward

```bash
ssh -N -L 127.0.0.1:8081:INTERNAL:80 -f \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=30 \
  user@PIVOT
```

### Remote forward

```bash
ssh -N -R 8081:INTERNAL:80 -f \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=30 \
  user@PIVOT
```

### Chaining through a jump host

```bash
# One hop: the SOCKS proxy exits on PIVOT
ssh -N -D 1080 -f -J user@HOP1 user@PIVOT

# Two hops: the SOCKS proxy exits on PIVOT, reached through HOP1
ssh -N -D 1081 -f -J user@HOP1,user@HOP2 user@PIVOT
```

### SOCKS chaining: one proxy through another

```bash
# First proxy: attacker -> HOP1
ssh -N -D 1080 -f user@HOP1
# Second proxy: exits on PIVOT, reached through the first
ssh -N -D 1081 -f -o ProxyCommand="nc -X 5 -x 127.0.0.1:1080 %h %p" user@PIVOT
```

`nc -X 5` is a SOCKS5 client; `-X 4` for SOCKS4. OpenBSD netcat supports
both. `ncat` uses `--proxy 127.0.0.1:1080 --proxy-type socks5`.

### ssh client config

`~/.ssh/config`:

```sshconfig
Host pivot
    HostName PIVOT
    User user
    IdentityFile ~/.ssh/engagement_pivot
    ServerAliveInterval 30
    ServerAliveCountMax 4
    ExitOnForwardFailure yes
    LocalForward 8081 INTERNAL:80
    DynamicForward 1080
```

Then `ssh -fN pivot` brings up both forwards.

### Control sockets

A control socket gives a clean teardown instead of hunting for the PID.

```bash
ssh -M -S ~/.ssh/cyberpi-%r@%h:%p -fN -D 1080 user@PIVOT
# ssh expands the tokens, so the teardown uses the expanded path
ssh -S ~/.ssh/cyberpi-user@PIVOT:22 -O exit user@PIVOT
```

---

## proxychains4

### Configuration file

`/etc/proxychains4.conf` (system) or `~/.proxychains/proxychains.conf`
(user). The user file wins when it exists.

```ini
# strict_chain: every proxy in the list must be up, or nothing is proxied.
strict_chain
# proxy_dns: resolve names through the proxy, so internal DNS is used.
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 1080
```

| Option | Effect |
|---|---|
| `strict_chain` | All proxies must be reachable, otherwise the call fails |
| `dynamic_chain` | Fall back to the next proxy when one is down (quietly) |
| `proxy_dns` | Resolve names through the proxy (remote DNS) |
| `proxy_dns_old` | Older remote resolver, occasionally needed for odd resolvers |
| `remote_dns_subnet` | Subnet used for the fake DNS addresses |

### The generated configuration

`cyber_pivot` writes its own configuration for the tunnel it just started:

```
.cyberpi/notes/proxychains-<tunnel>.conf
```

It contains the `[ProxyList]` entry for the SOCKS endpoint of that tunnel and
the command to use it:

```bash
proxychains4 -f .cyberpi/notes/proxychains-<tunnel>.conf <command>
```

### Usage

```bash
proxychains4 curl http://INTERNAL/
proxychains4 nmap -sT -p 80,443 INTERNAL
proxychains4 -f ~/.proxychains/proxychains.conf nmap -sT INTERNAL
```

Limitations, in order of importance:

- proxychains redirects through `LD_PRELOAD`. Only dynamically linked
  binaries are affected. nmap and curl are; naabu and httpx (Go, statically
  linked) are not. Check with `file "$(which naabu)"`.
- Only TCP is proxied. UDP scanning does not work through proxychains.
- A SYN scan uses raw sockets and bypasses the redirect entirely. Use `-sT`.
- SOCKS4 has no DNS support, so `proxy_dns` does nothing for it.

### Native proxy support, without proxychains

Preferred for the tools that have it:

```bash
curl --socks5-hostname 127.0.0.1:1080 http://INTERNAL/
curl --proxy socks5h://127.0.0.1:1080 http://INTERNAL/
nmap -sT -p 80,443 --proxies socks5://127.0.0.1:1080 INTERNAL
sqlmap --proxy socks5://127.0.0.1:1080 -u http://INTERNAL/
```

`socks5h://` and `--socks5-hostname` resolve the name through the proxy.
`socks5://` and `--socks5` resolve locally.

---

## ligolo-ng

Not part of the CyberPi default toolchain. Install it on Kali with
`sudo apt install -y ligolo-ng`, or download the release archive for the
architecture, verify the checksum, and install the binaries by hand:

```bash
sudo install -m 0755 ligolo-proxy /usr/local/bin/ligoloproxy
sudo install -m 0755 ligolo-agent /usr/local/bin/ligolo
```

### TUN mode (layer 3, the usual case)

```bash
# Attacker (root: the proxy creates the tun interface)
sudo ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# Pivot (no root required in TUN mode)
ligolo -c ATTACKER:11601

# Attacker, once the agent is connected
sudo ip route add 10.0.0.0/24 dev ligolo
sudo sysctl -w net.ipv4.ip_forward=1
```

Older ligolo-ng releases take `-l 11601` instead of `-laddr 0.0.0.0:11601`,
and some name the agent flag `--client` instead of `-c`. `ligolo-proxy -h`
and `ligolo -h` show what the installed version understands, and
`cyber_pivot` prints the exact usage line it used for the proxy.

`-selfcert` makes the proxy generate its own certificate. For a long
engagement, pin a certificate instead of accepting any.

### Ethernet mode (layer 2)

For ARP-level access to a segment. The agent must run as root on the pivot
and the attacker bridges the interface.

```bash
# Pivot
sudo ligolo -c ATTACKER:11601
# Attacker
sudo ligoloproxy -interface ligolo -ethernet
```

### NAT for tunnelled traffic

When the attacker must reach hosts that route back through the tunnel, the
attacker needs to masquerade the traffic.

```bash
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -d 10.0.0.0/24 -j MASQUERADE
sudo sysctl -w net.ipv4.ip_forward=1
```

### Checking the interface

```bash
ip -brief addr show ligolo
ip route show dev ligolo
```

---

## socat

```bash
# Pivot: expose an internal service
socat TCP-LISTEN:8080,fork,reuseaddr TCP:INTERNAL:80

# Attacker: bridge a local port to the pivot's listener
socat TCP-LISTEN:8081,fork,reuseaddr TCP:PIVOT:8080

# Bridge through a SOCKS5 proxy
socat TCP-LISTEN:8081,fork,reuseaddr SOCKS5:127.0.0.1:1080
```

socat cannot terminate a SOCKS5 server. For a proxy, use chisel or
`ssh -D`.

---

## Environment for manual work

Export the proxy for the shells you run by hand. CyberPi spawns its
scanners with the environment of the pi process, so exporting before
starting the harness affects them too, but only for tools that read the
variable themselves (httpx accepts `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY`).

```bash
export ALL_PROXY=socks5h://127.0.0.1:1080
export HTTP_PROXY=socks5h://127.0.0.1:1080
export HTTPS_PROXY=socks5h://127.0.0.1:1080
export no_proxy=127.0.0.1,localhost
```

---

## Engagement notes template

Record the tunnel in `.cyberpi/notes/` so the report explains the traffic.
Harness tool calls are journalled automatically; tunnels started by hand are
not.

```markdown
# Pivot 1 — chisel SOCKS5
- Pivot host: PIVOT (compromised via INTERNAL-01, creds from AD-02)
- Tunnel: chisel server on PIVOT:8080, client on the attacker, SOCKS5 on 127.0.0.1:1080
- Started by: cyber_pivot action=start-chisel-client target=PIVOT
- Purpose: reach the 10.0.0.0/24 segment
- Scope: 10.0.0.0/24 authorized in .cyberpi/scope.json
- Started: 2025-03-14T09:12:00Z, stopped: 2025-03-14T17:40:00Z
- Tools used through it: cyber_portscan, cyber_service_scan, cyber_http_probe
- Local forwards: 127.0.0.1:8081 -> INTERNAL:80
```
