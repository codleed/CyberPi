/**
 * Infrastructure tools: network pivoting / tunnelling and cloud enumeration.
 *
 * Both tools need more than "run one command and print stdout": the pivot tool
 * owns long-lived processes (config file, detached launch, PID bookkeeping,
 * stop), and the cloud tool has to redact credentials before anything reaches
 * the transcript. Both therefore use the `execute` path of the toolkit and
 * share its scope check, technique gate, binary check and journal entries.
 */

import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { Type } from "@earendil-works/pi-ai";
import type { ToolDefinition } from "@earendil-works/pi-coding-agent";
import { engagementPaths, ensureDir } from "../lib/config.ts";
import { formatCommand, run, runMany, which, type RunPlan } from "../lib/exec.ts";
import { appendJournal, writeArtifact } from "../lib/journal.ts";
import { defineCyberTool, parseJson, type CyberToolOutcome } from "../lib/toolkit.ts";

const DEFAULT_CHISEL_PORT = 8080;
const DEFAULT_SOCKS_PORT = 1080;
const DEFAULT_LIGOLO_PORT = 11601;
const FOREGROUND_TIMEOUT_MS = 900_000;
const MAX_BUCKETS_INSPECTED = 20;

/* -------------------------------------------------------------------------- */
/* cyber_pivot                                                                */
/* -------------------------------------------------------------------------- */

type PivotAction =
	| "start-chisel-server"
	| "start-chisel-client"
	| "start-ligolo-proxy"
	| "start-proxychains"
	| "socks-proxy"
	| "port-forward";

interface PivotParams {
	action: PivotAction;
	target?: string;
	listen_port?: number;
	remote_host?: string;
	remote_port?: number;
	socks_port?: number;
	background?: boolean;
	kill_existing?: boolean;
}

interface PivotDetails {
	tunnel: string;
	action: PivotAction;
	command: string;
	binary: string;
	pid?: number;
	listenPort?: number;
	socksPort?: number;
	configPath: string;
	pidPath?: string;
	logPath: string;
	proxychainsPath?: string;
	stopped?: { pid?: number; reason?: string; stopped: boolean };
}

interface PivotPlan {
	binary: string;
	args: string[];
	command: string;
	listenPort?: number;
	socksPort?: number;
	/** Address the tunnel listens on, for the summary. */
	listenAddress?: string;
	/** Where the SOCKS5 endpoint of this tunnel lives. */
	socksEndpoint?: { host: string; port: number };
	usage: string[];
	/** Extra lines appended to the summary (fingerprint, warnings). */
	notes: string[];
}

interface TunnelState {
	name: string;
	action: PivotAction;
	binary: string;
	command: string;
	startedAt: string;
	pid?: number;
	listenPort?: number;
	socksPort?: number;
	configPath: string;
	pidPath: string;
	logPath: string;
	proxychainsPath?: string;
}

function splitList(value: string | undefined): string[] {
	if (!value) return [];
	return value
		.split(",")
		.map((item) => item.trim())
		.filter((item) => item.length > 0);
}

function slug(value: string): string {
	return value.replace(/[^a-zA-Z0-9.]+/g, "-").replace(/^-+|-+$/g, "");
}

/** Stable name of a tunnel: the action plus the pivot host it points at. */
function tunnelName(action: PivotAction, target: string | undefined): string {
	const base = slug(action.replace(/^start-/, ""));
	const host = target ? slug(target.split(":")[0] ?? "") : "";
	return host ? `${base}-${host}` : base;
}

/** Split "host", "host:port" or "[v6]:port" into its parts. */
function splitHostPort(raw: string, defaultPort: number): { host: string; port: number } {
	const trimmed = raw.trim();
	if (trimmed.startsWith("[")) {
		const end = trimmed.indexOf("]");
		if (end !== -1) {
			const host = trimmed.slice(1, end);
			const rest = trimmed.slice(end + 1);
			const port = rest.startsWith(":") ? Number(rest.slice(1)) : defaultPort;
			return { host, port: Number.isInteger(port) && port > 0 ? port : defaultPort };
		}
	}
	const colon = trimmed.lastIndexOf(":");
	if (colon > 0 && trimmed.indexOf(":") === colon) {
		const port = Number(trimmed.slice(colon + 1));
		if (Number.isInteger(port) && port > 0 && port <= 65535) {
			return { host: trimmed.slice(0, colon), port };
		}
	}
	return { host: trimmed, port: defaultPort };
}

/** Render a host for use in a chisel server specification. */
function hostForCommand(host: string): string {
	return host.includes(":") ? `[${host}]` : host;
}

function isAlive(pid: number): boolean {
	try {
		process.kill(pid, 0);
		return true;
	} catch (error) {
		return (error as NodeJS.ErrnoException).code === "EPERM";
	}
}

/**
 * True when the process is the one we started.
 *
 * PIDs are recycled, so a stale PID file must never be able to kill an
 * unrelated process. /proc is authoritative on Linux; when it is not readable
 * the check is skipped and the operator is told.
 */
function processMatches(pid: number, binary: string): { matches: boolean; known: boolean } {
	let cmdline: string;
	try {
		cmdline = fs.readFileSync(`/proc/${pid}/cmdline`, "utf8");
	} catch {
		return { matches: true, known: false };
	}
	const parts = cmdline.split("\0").filter(Boolean);
	if (parts.length === 0) return { matches: false, known: true };
	const name = binary.split("/").pop() ?? binary;
	return { matches: parts.some((part) => part.includes(name)), known: true };
}

function pivotDir(cwd: string): string {
	const dir = path.join(engagementPaths(cwd).dir, "pivot");
	ensureDir(dir);
	return dir;
}

function readPidFile(pidPath: string): number | undefined {
	if (!fs.existsSync(pidPath)) return undefined;
	const raw = fs.readFileSync(pidPath, "utf8").trim();
	const pid = Number.parseInt(raw, 10);
	return Number.isInteger(pid) && pid > 0 ? pid : undefined;
}

function readTunnelState(configPath: string): TunnelState | undefined {
	if (!fs.existsSync(configPath)) return undefined;
	const parsed = parseJson<TunnelState>(fs.readFileSync(configPath, "utf8"));
	return parsed;
}

/** Stop a tunnel this tool started earlier. */
function stopTunnel(dir: string, name: string): { stopped: boolean; pid?: number; reason?: string } {
	const pidPath = path.join(dir, `${name}.pid`);
	const state = readTunnelState(path.join(dir, `${name}.json`));
	const pid = readPidFile(pidPath);
	if (!pid) {
		if (fs.existsSync(pidPath)) fs.rmSync(pidPath, { force: true });
		return { stopped: false, reason: "no PID file for this tunnel" };
	}
	if (!isAlive(pid)) {
		fs.rmSync(pidPath, { force: true });
		return { stopped: false, pid, reason: `process ${pid} is no longer running` };
	}
	const binary = state?.binary ?? "chisel";
	const check = processMatches(pid, binary);
	if (!check.matches) {
		return {
			stopped: false,
			pid,
			reason: `PID ${pid} is alive but does not look like ${binary}; refusing to kill it`,
		};
	}
	try {
		process.kill(pid, "SIGTERM");
	} catch (error) {
		return { stopped: false, pid, reason: `could not signal PID ${pid}: ${(error as Error).message}` };
	}
	const deadline = Date.now() + 4000;
	while (Date.now() < deadline) {
		if (!isAlive(pid)) break;
		sleep(100);
	}
	if (isAlive(pid)) {
		try {
			process.kill(pid, "SIGKILL");
		} catch {
			// The process died between the check and the signal.
		}
	}
	fs.rmSync(pidPath, { force: true });
	return { stopped: true, pid };
}

function sleep(ms: number): void {
	const shared = new Int32Array(new SharedArrayBuffer(4));
	Atomics.wait(shared, 0, 0, ms);
}

interface LaunchResult {
	pid?: number;
	code?: number | null;
	stdout: string;
	stderr: string;
	error?: string;
}

/**
 * Start the tunnel process.
 *
 * Background tunnels are started through nohup in their own session so they
 * survive the harness and the terminal; foreground tunnels run attached and
 * are stopped when they exit or when the timeout elapses.
 */
function launchBackground(
	binary: string,
	args: string[],
	options: { cwd: string; logPath: string },
): Promise<LaunchResult> {
	return new Promise<LaunchResult>((resolve) => {
		const fd = fs.openSync(options.logPath, "a");
		let child: ChildProcess;
		try {
			child = spawn("nohup", [binary, ...args], {
				cwd: options.cwd,
				env: process.env,
				detached: true,
				stdio: ["ignore", fd, fd],
			});
		} catch (error) {
			fs.closeSync(fd);
			resolve({ stdout: "", stderr: "", error: (error as Error).message });
			return;
		}
		fs.closeSync(fd);
		child.unref();
		let settled = false;
		child.on("error", (error: Error) => {
			if (settled) return;
			settled = true;
			resolve({ pid: undefined, stdout: "", stderr: "", error: error.message });
		});
		setTimeout(() => {
			if (settled) return;
			settled = true;
			resolve({ pid: child.pid, stdout: "", stderr: "" });
		}, 500);
	});
}

function launchForeground(
	binary: string,
	args: string[],
	options: { cwd: string; timeoutMs: number },
): Promise<LaunchResult> {
	return new Promise<LaunchResult>((resolve) => {
		let child: ChildProcess;
		try {
			child = spawn(binary, args, {
				cwd: options.cwd,
				env: process.env,
				detached: false,
				stdio: ["ignore", "pipe", "pipe"],
			});
		} catch (error) {
			resolve({ stdout: "", stderr: "", error: (error as Error).message });
			return;
		}

		const stdoutChunks: Buffer[] = [];
		const stderrChunks: Buffer[] = [];
		let settled = false;
		const timer = setTimeout(() => {
			child.kill("SIGKILL");
		}, options.timeoutMs);
		child.stdout?.on("data", (chunk: Buffer) => stdoutChunks.push(chunk));
		child.stderr?.on("data", (chunk: Buffer) => stderrChunks.push(chunk));
		child.on("error", (error: Error) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolve({ stdout: "", stderr: "", error: error.message });
		});
		child.on("close", (code) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolve({
				pid: child.pid,
				code,
				stdout: Buffer.concat(stdoutChunks).toString("utf8"),
				stderr: Buffer.concat(stderrChunks).toString("utf8"),
			});
		});
	});
}

function launchProcess(
	binary: string,
	args: string[],
	options: { cwd: string; background: boolean; logPath: string; timeoutMs: number },
): Promise<LaunchResult> {
	return options.background
		? launchBackground(binary, args, { cwd: options.cwd, logPath: options.logPath })
		: launchForeground(binary, args, { cwd: options.cwd, timeoutMs: options.timeoutMs });
}

/** Extract the server fingerprint chisel prints on startup, when present. */
function fingerprintFromLog(logPath: string): string | undefined {
	try {
		if (!fs.existsSync(logPath)) return undefined;
		const content = fs.readFileSync(logPath, "utf8");
		const match = /fingerprint[:\s]+([A-Za-z0-9+/=]{20,})/i.exec(content);
		return match ? match[1] : undefined;
	} catch {
		return undefined;
	}
}

function logTail(logPath: string, maxLines = 12): string[] {
	try {
		if (!fs.existsSync(logPath)) return [];
		return fs
			.readFileSync(logPath, "utf8")
			.split("\n")
			.map((line) => line.trim())
			.filter((line) => line.length > 0)
			.slice(-maxLines);
	} catch {
		return [];
	}
}

interface LigoloFlags {
	/** `laddr` in ligolo-ng >= 0.5, plain `l` in older releases. */
	listenStyle: "laddr" | "l";
	supportsLocalTunnels: boolean;
}

/** Detect which flags the installed ligolo-proxy understands. */
async function detectLigoloFlags(binary: string): Promise<LigoloFlags> {
	const result = await run(binary, ["-h"], { timeoutMs: 15_000 });
	const help = `${result.stdout}\n${result.stderr}`;
	if (help.includes("-laddr")) {
		return { listenStyle: "laddr", supportsLocalTunnels: /(^|\s)-L(\s|$)/.test(help) };
	}
	if (/(^|\s)-l(\s|$)/.test(help)) {
		return { listenStyle: "l", supportsLocalTunnels: /(^|\s)-L(\s|$)/.test(help) };
	}
	return { listenStyle: "laddr", supportsLocalTunnels: false };
}

/** Build the command for the requested pivot action. */
async function buildPivotPlan(params: PivotParams): Promise<{ plan?: PivotPlan; error?: string }> {
	const background = params.background ?? true;
	const socksPort = params.socks_port ?? DEFAULT_SOCKS_PORT;
	const listenPort = params.listen_port;
	const target = params.target?.trim();

	switch (params.action) {
		case "start-chisel-server": {
			const port = listenPort ?? DEFAULT_CHISEL_PORT;
			const args = ["server", "--port", String(port), "--reverse", "--socks5"];
			return {
				plan: {
					binary: "chisel",
					args,
					command: formatCommand("chisel", args),
					listenPort: port,
					listenAddress: "0.0.0.0",
					socksPort,
					socksEndpoint: { host: "127.0.0.1", port: socksPort },
					usage: [
						`Run the client on the target: chisel client <this-host>:${port} R:${socksPort}:socks`,
						`Or a local forward: chisel client <this-host>:${port} 127.0.0.1:${port}:<internal-host>:<internal-port>`,
						`The SOCKS5 proxy appears on this host at 127.0.0.1:${socksPort} once a reverse client connects`,
					],
					notes: ["The server binds 0.0.0.0 and accepts reverse and SOCKS remotes (--reverse --socks5)."],
				},
			};
		}
		case "start-chisel-client": {
			if (!target) {
				return { error: "action start-chisel-client needs a target: the host running the chisel server." };
			}
			const server = splitHostPort(target, DEFAULT_CHISEL_PORT);
			const serverSpec = `${hostForCommand(server.host)}:${server.port}`;
			if (params.remote_port !== undefined) {
				const remoteHost = params.remote_host?.trim() || "127.0.0.1";
				const localPort = listenPort ?? DEFAULT_CHISEL_PORT;
				const remote = `127.0.0.1:${localPort}:${remoteHost}:${params.remote_port}`;
				const args = ["client", serverSpec, remote];
				return {
					plan: {
						binary: "chisel",
						args,
						command: formatCommand("chisel", args),
						listenPort: localPort,
						listenAddress: "127.0.0.1",
						usage: [
							`Reach the forwarded service: nc 127.0.0.1 ${localPort}`,
							`Or: curl http://127.0.0.1:${localPort}/`,
						],
						notes: [
							`Forward: 127.0.0.1:${localPort} -> ${remoteHost}:${params.remote_port} (resolved on the chisel server)`,
						],
					},
				};
			}
			const remote = `R:${socksPort}:socks`;
			const args = ["client", serverSpec, remote];
			return {
				plan: {
					binary: "chisel",
					args,
					command: formatCommand("chisel", args),
					listenPort: server.port,
					listenAddress: server.host,
					socksPort,
					socksEndpoint: { host: server.host, port: socksPort },
					usage: [
						`The reverse SOCKS5 proxy opens on the chisel server at ${server.host}:${socksPort}`,
						`Use it from that host: proxychains4 -f <config> <command>`,
					],
					notes: ["The chisel server must run with --reverse for R: remotes to be accepted."],
				},
			};
		}
		case "socks-proxy":
		case "start-proxychains": {
			if (!target) {
				return { error: `action ${params.action} needs a target: the host running the chisel server.` };
			}
			const server = splitHostPort(target, DEFAULT_CHISEL_PORT);
			const serverSpec = `${hostForCommand(server.host)}:${server.port}`;
			const remote = `127.0.0.1:${socksPort}:socks`;
			const args = ["client", serverSpec, remote];
			return {
				plan: {
					binary: "chisel",
					args,
					command: formatCommand("chisel", args),
					listenPort: socksPort,
					listenAddress: "127.0.0.1",
					socksPort,
					socksEndpoint: { host: "127.0.0.1", port: socksPort },
					usage: [
						`curl --socks5-hostname 127.0.0.1:${socksPort} http://<internal-host>/`,
						`proxychains4 -f <proxychains config> <command>`,
					],
					notes: [
						"The SOCKS5 listener runs on this host; traffic exits through the chisel server.",
						"The chisel server must run with --socks5 for socks remotes to be accepted.",
					],
				},
			};
		}
		case "port-forward": {
			if (!target) {
				return { error: "action port-forward needs a target: the host running the chisel server." };
			}
			if (params.remote_port === undefined) {
				return { error: "action port-forward needs remote_port: the port to reach through the tunnel." };
			}
			const server = splitHostPort(target, DEFAULT_CHISEL_PORT);
			const serverSpec = `${hostForCommand(server.host)}:${server.port}`;
			const remoteHost = params.remote_host?.trim() || "127.0.0.1";
			const localPort = listenPort ?? DEFAULT_CHISEL_PORT;
			const remote = `127.0.0.1:${localPort}:${remoteHost}:${params.remote_port}`;
			const args = ["client", serverSpec, remote];
			return {
				plan: {
					binary: "chisel",
					args,
					command: formatCommand("chisel", args),
					listenPort: localPort,
					listenAddress: "127.0.0.1",
					usage: [
						`nc 127.0.0.1 ${localPort}`,
						`curl http://127.0.0.1:${localPort}/`,
					],
					notes: [
						`Forward: 127.0.0.1:${localPort} -> ${remoteHost}:${params.remote_port} (resolved on the chisel server)`,
					],
				},
			};
		}
		case "start-ligolo-proxy": {
			const binary = "ligolo-proxy";
			if (!which(binary)) {
				return {
					error:
						"ligolo-proxy is not installed. Install ligolo-ng on Kali with: sudo apt install -y ligolo-ng",
				};
			}
			const port = listenPort ?? DEFAULT_LIGOLO_PORT;
			const flags = await detectLigoloFlags(binary);
			const args = ["-selfcert"];
			if (flags.listenStyle === "laddr") {
				args.push("-laddr", `0.0.0.0:${port}`);
			} else {
				args.push("-l", String(port));
			}
			if (params.socks_port !== undefined && flags.supportsLocalTunnels) {
				args.push("-L", `127.0.0.1:${params.socks_port}:1080`);
			}
			const usageLine = formatCommand(binary, args);
			return {
				plan: {
					binary,
					args,
					command: usageLine,
					listenPort: port,
					listenAddress: "0.0.0.0",
					usage: [
						`usage: ${usageLine}`,
						`Run the agent on the target: ligolo -c ${hostForCommand("this-host")}:${port}`,
						"ligolo-proxy creates a tun interface, so it has to run as root on this host.",
					],
					notes: [
						`ligolo-proxy usage: ${usageLine}`,
						"ligolo-ng tunnels IP traffic, not TCP ports: use the tun interface instead of proxychains.",
					],
				},
			};
		}
		default:
			return { error: `unknown action: ${String(params.action)}` };
	}
}

/** Write the proxychains4 configuration for a SOCKS5 endpoint. */
function writeProxychainsConfig(notesDir: string, name: string, endpoint: { host: string; port: number }): string {
	ensureDir(notesDir);
	const file = path.join(notesDir, `proxychains-${name}.conf`);
	const content = [
		"# CyberPi pivot - proxychains4 configuration",
		`# tunnel: ${name}`,
		`# generated: ${new Date().toISOString()}`,
		`# usage: proxychains4 -f ${file} <command>`,
		"[ProxyList]",
		`socks5 ${endpoint.host} ${endpoint.port}`,
		"",
	].join("\n");
	fs.writeFileSync(file, content, "utf8");
	return file;
}

const pivotTool = defineCyberTool({
	name: "cyber_pivot",
	label: "Network pivot",
	description:
		"Set up and control a network pivot. Starts a chisel or ligolo-ng tunnel, keeps the process " +
		"(config file, PID file and log inside .cyberpi/pivot) and reports how to use it. " +
		"Actions: start-chisel-server (tunnel entry point), start-chisel-client (reverse SOCKS5 or " +
		"local forward through a pivot host), start-ligolo-proxy (ligolo-ng tun interface), " +
		"start-proxychains (local SOCKS5 plus a proxychains4 configuration), socks-proxy (local " +
		"SOCKS5 through the pivot) and port-forward (raw TCP forward). The pivot host is checked " +
		"against the engagement scope.",
	promptSnippet: "cyber_pivot: start or control a chisel/ligolo pivot tunnel",
	technique: "pivot",
	requires: ["chisel"],
	installHint: "Install chisel on Kali with: sudo apt install -y chisel",
	target: (params) => params.target ?? params.remote_host,
	parameters: Type.Object({
		action: Type.Enum(
			[
				"start-chisel-server",
				"start-chisel-client",
				"start-ligolo-proxy",
				"start-proxychains",
				"socks-proxy",
				"port-forward",
			],
			{
				description:
					"start-chisel-server: run the chisel entry point on this host. start-chisel-client: " +
					"connect to a chisel server and open a reverse SOCKS5 (default) or a local forward " +
					"(when remote_port is given). start-ligolo-proxy: run the ligolo-ng proxy. " +
					"start-proxychains: local SOCKS5 through the pivot plus a proxychains4 configuration " +
					"in the engagement notes. socks-proxy: local SOCKS5 through the pivot. " +
					"port-forward: raw TCP forward to remote_host:remote_port.",
			},
		),
		target: Type.Optional(
			Type.String({
				description:
					"Pivot host, required for the client actions. May carry the port of the pivot " +
					"service (host:port); the default port is 8080.",
			}),
		),
		listen_port: Type.Optional(
			Type.Number({
				description:
					"Port the tunnel listens on. chisel server: the HTTP port (default 8080). " +
					"chisel client forward: the local port (default 8080). ligolo-proxy: the proxy " +
					"port (default 11601).",
			}),
		),
		remote_host: Type.Optional(
			Type.String({
				description:
					"Host reached through the tunnel. Resolved on the pivot host, not locally. " +
					"Defaults to 127.0.0.1 (the pivot host itself).",
			}),
		),
		remote_port: Type.Optional(
			Type.Number({ description: "Port reached through the tunnel. Required for port-forward." }),
		),
		socks_port: Type.Optional(Type.Number({ description: "SOCKS5 port (default 1080)." })),
		background: Type.Optional(
			Type.Boolean({
				default: true,
				description:
					"Run the tunnel detached in the background (default) or attached in the foreground, " +
					"which ends the tunnel when the command returns.",
			}),
		),
		kill_existing: Type.Optional(
			Type.Boolean({
				description:
					"Stop a tunnel this tool started earlier for the same action and target before " +
					"starting the new one.",
			}),
		),
	}),
	execute: async (params, ctx): Promise<CyberToolOutcome<PivotDetails>> => {
		const cwd = ctx.cwd;
		const paths = engagementPaths(cwd);
		const dir = pivotDir(cwd);
		const name = tunnelName(params.action, params.target);
		const background = params.background ?? true;

		const built = await buildPivotPlan(params);
		if (!built.plan) {
			return {
				summary: built.error ?? "the pivot could not be configured",
				isError: true,
				details: {
					tunnel: name,
					action: params.action,
					command: "",
					binary: "",
					configPath: path.join(dir, `${name}.json`),
					pidPath: path.join(dir, `${name}.pid`),
					logPath: path.join(dir, `${name}.log`),
				},
			};
		}
		const plan = built.plan;

		let stopped: { pid?: number; reason?: string; stopped: boolean } | undefined;
		if (params.kill_existing) {
			const result = stopTunnel(dir, name);
			stopped = { stopped: result.stopped, pid: result.pid, reason: result.reason };
		}

		const configPath = path.join(dir, `${name}.json`);
		const pidPath = path.join(dir, `${name}.pid`);
		const logPath = path.join(dir, `${name}.log`);
		ensureDir(paths.notes);

		let proxychainsPath: string | undefined;
		if (plan.socksEndpoint) {
			proxychainsPath = writeProxychainsConfig(paths.notes, name, plan.socksEndpoint);
		}

		const launch = await launchProcess(plan.binary, plan.args, {
			cwd,
			background,
			logPath,
			timeoutMs: FOREGROUND_TIMEOUT_MS,
		});

		if (launch.error) {
			return {
				summary: `Could not start ${plan.binary}: ${launch.error}`,
				isError: true,
				details: {
					tunnel: name,
					action: params.action,
					command: plan.command,
					binary: plan.binary,
					configPath,
					pidPath,
					logPath,
					proxychainsPath,
					stopped,
				},
			};
		}

		const pid = launch.pid;
		const state: TunnelState = {
			name,
			action: params.action,
			binary: plan.binary,
			command: plan.command,
			startedAt: new Date().toISOString(),
			pid,
			listenPort: plan.listenPort,
			socksPort: plan.socksPort,
			configPath,
			pidPath,
			logPath,
			proxychainsPath,
		};
		fs.writeFileSync(configPath, `${JSON.stringify(state, null, 2)}\n`, "utf8");
		if (pid !== undefined && background) {
			fs.writeFileSync(pidPath, `${pid}\n`, "utf8");
		}

		appendJournal(cwd, {
			ts: new Date().toISOString(),
			tool: "cyber_pivot",
			action: params.action,
			target: params.target ?? params.remote_host,
			command: plan.command,
			summary: `tunnel ${name}${pid ? ` (pid ${pid})` : ""}`,
			severity: "info",
			artifact: configPath,
		});

		const lines: string[] = [];
		lines.push(`Command:   ${plan.command}`);
		lines.push(`Tunnel:    ${name}`);
		lines.push(`Config:    ${configPath}`);
		lines.push(`PID file:  ${pidPath}${pid ? ` (pid ${pid})` : ""}`);
		lines.push(`Log:       ${logPath}`);
		if (plan.listenPort !== undefined) {
			const address = plan.listenAddress ?? "127.0.0.1";
			lines.push(`Listening: ${address}:${plan.listenPort}`);
		}
		if (plan.socksEndpoint) {
			lines.push(`SOCKS5:    ${plan.socksEndpoint.host}:${plan.socksEndpoint.port}`);
		}
		if (stopped) {
			lines.push(
				stopped.stopped
					? `Stopped:   previous tunnel (pid ${stopped.pid})`
					: `Stopped:   nothing to stop (${stopped.reason ?? "unknown"})`,
			);
		}

		const fingerprint = fingerprintFromLog(logPath);
		if (fingerprint) {
			lines.push(`Fingerprint: ${fingerprint}`);
		}

		lines.push("");
		lines.push("Usage:");
		for (const usage of plan.usage) {
			lines.push(`  ${usage}`);
		}

		if (proxychainsPath) {
			const snippet = fs
				.readFileSync(proxychainsPath, "utf8")
				.split("\n")
				.map((line) => line.trim())
				.filter((line) => line.length > 0 && !line.startsWith("#"));
			lines.push("");
			lines.push(`proxychains4 config (${proxychainsPath}):`);
			for (const line of snippet) {
				lines.push(`  ${line}`);
			}
			lines.push(`  proxychains4 -f ${proxychainsPath} <command>`);
		}

		for (const note of plan.notes) {
			lines.push("");
			lines.push(note);
		}

		let failed = false;
		if (background) {
			if (pid === undefined || !isAlive(pid)) {
				failed = true;
				const tail = logTail(logPath);
				lines.push("");
				lines.push("The tunnel process exited immediately. Log output:");
				for (const line of tail) {
					lines.push(`  ${line}`);
				}
			} else {
				lines.push("");
				lines.push(`Stop it:   kill ${pid}   (or re-run with kill_existing=true)`);
			}
		} else {
			lines.push("");
			lines.push(
				`Foreground tunnel exited with code ${launch.code ?? "unknown"}. Stop it with Ctrl-C while it runs.`,
			);
			if ((launch.code ?? 0) !== 0) {
				failed = true;
				const tail = logTail(logPath);
				for (const line of tail) {
					lines.push(`  ${line}`);
				}
			}
		}

		const summary = failed
			? `Pivot ${name} did not stay up (${plan.command})`
			: `Pivot ${name} started: ${plan.command}${pid ? ` (pid ${pid})` : ""}`;

		return {
			summary,
			output: lines.join("\n"),
			isError: failed,
			severity: failed ? "medium" : "info",
			details: {
				tunnel: name,
				action: params.action,
				command: plan.command,
				binary: plan.binary,
				pid,
				listenPort: plan.listenPort,
				socksPort: plan.socksPort,
				configPath,
				pidPath,
				logPath,
				proxychainsPath,
				stopped,
			},
		};
	},
});

/* -------------------------------------------------------------------------- */
/* cyber_cloud_enum                                                           */
/* -------------------------------------------------------------------------- */

type CloudProvider = "aws" | "gcp" | "azure";

const PROVIDER_BINARY: Record<CloudProvider, string> = {
	aws: "aws",
	gcp: "gcloud",
	azure: "az",
};

const PROVIDER_INSTALL: Record<CloudProvider, string> = {
	aws: "sudo apt install -y awscli",
	gcp: "sudo apt install -y google-cloud-cli",
	azure: "sudo apt install -y azure-cli",
};

const PROVIDER_CHECKS: Record<CloudProvider, string[]> = {
	aws: ["identity", "iam", "storage", "compute"],
	gcp: ["identity", "projects", "storage", "compute"],
	azure: ["identity", "storage", "compute"],
};

const DEFAULT_CHECKS = ["identity", "storage"];

interface ExposedResource {
	kind: "storage" | "compute" | "account";
	name: string;
	id?: string;
	region?: string;
	exposure: string;
	severity: "low" | "medium" | "high";
}

interface CloudDetails {
	provider: CloudProvider;
	checks: string[];
	identity: string[];
	accounts: string[];
	resources: ExposedResource[];
	artifact?: string;
	redactedFields: string[];
	errors: string[];
}

interface CloudCommandSpec {
	check: string;
	bin: string;
	args: string[];
}

interface CommandOutcome {
	check: string;
	command: string;
	exitCode: number | null;
	durationMs: number;
	stdout: string;
	stderr: string;
}

const SECRET_KEY_PATTERN =
	/(access[_-]?key|secret|password|passwd|token|credential|private[_-]?key|api[_-]?key|session[_-]?key)/i;

const SECRET_TEXT_PATTERN =
	/((?:"|')?(?:access_token|refresh_token|id_token|rapt_token|client_secret|password|secret_access_key|secret_key|private_key)(?:"|')?\s*[:=]\s*)("?)([^"\s,}]+)/gi;

function redactText(text: string): string {
	return text.replace(SECRET_TEXT_PATTERN, (_match, prefix: string, quote: string) => `${prefix}${quote}[redacted]`);
}

function redactValue(value: unknown, keys: Set<string>): unknown {
	if (Array.isArray(value)) {
		return value.map((item) => redactValue(item, keys));
	}
	if (value !== null && typeof value === "object") {
		const result: Record<string, unknown> = {};
		for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
			if (SECRET_KEY_PATTERN.test(key)) {
				keys.add(key);
				result[key] = "[redacted]";
			} else {
				result[key] = redactValue(item, keys);
			}
		}
		return result;
	}
	return value;
}

function asArray<T>(value: unknown): T[] {
	return Array.isArray(value) ? (value as T[]) : [];
}

function asRecord(value: unknown): Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: {};
}

interface AwsIdentity {
	UserId?: string;
	Account?: string;
	Arn?: string;
}

interface AwsUser {
	UserName?: string;
	UserId?: string;
	Arn?: string;
	CreateDate?: string;
}

interface AwsInstance {
	InstanceId?: string;
	PublicIpAddress?: string;
	PrivateIpAddress?: string;
	InstanceType?: string;
	State?: { Name?: string };
	Placement?: { AvailabilityZone?: string };
}

interface AwsPublicAccessBlock {
	PublicAccessBlockConfiguration?: {
		BlockPublicAcls?: boolean;
		IgnorePublicAcls?: boolean;
		BlockPublicPolicy?: boolean;
		RestrictPublicBuckets?: boolean;
	};
}

interface AwsBucketPolicyStatus {
	PolicyStatus?: { IsPublic?: boolean };
}

interface GcpAuthAccount {
	account?: string;
	status?: string;
	expiration?: string;
	id?: string;
}

interface GcpProject {
	projectId?: string;
	name?: string;
	projectNumber?: string;
	lifecycleState?: string;
}

interface GcpBucket {
	name?: string;
	location?: string;
	storageClass?: string;
	iamConfiguration?: { uniformBucketLevelAccess?: { enabled?: boolean } };
}

interface GcpIamPolicy {
	bindings?: Array<{ role?: string; members?: string[] }>;
}

interface GcpInstance {
	name?: string;
	id?: string;
	zone?: string;
	status?: string;
	networkInterfaces?: Array<{ accessConfigs?: Array<{ natIP?: string }> }>;
}

interface AzureSubscription {
	id?: string;
	name?: string;
	state?: string;
	tenantId?: string;
	isDefault?: boolean;
	user?: { name?: string; type?: string };
}

interface AzureStorageAccount {
	name?: string;
	id?: string;
	location?: string;
	type?: string;
	properties?: {
		allowBlobPublicAccess?: boolean;
		publicNetworkAccess?: string;
		minimumTlsVersion?: string;
	};
}

interface AzureVm {
	name?: string;
	id?: string;
	location?: string;
	provisioningState?: string;
}

interface AzureIpAddress {
	virtualMachine?: { name?: string; id?: string };
	virtualMachineNetworkInterface?: { ipAddresses?: Array<{ ipAddress?: string; ipAddressType?: string }> };
}

/** Build the CLI invocations for the requested checks. */
function buildCloudCommands(provider: CloudProvider, params: CloudParams, checks: string[]): CloudCommandSpec[] {
	const profile = params.profile?.trim();
	const specs: CloudCommandSpec[] = [];
	if (provider === "aws") {
		const profileArgs = profile ? ["--profile", profile] : [];
		if (checks.includes("identity")) {
			specs.push({ check: "identity", bin: "aws", args: ["sts", "get-caller-identity", "--output", "json", ...profileArgs] });
		}
		if (checks.includes("iam")) {
			specs.push({ check: "iam", bin: "aws", args: ["iam", "list-users", "--output", "json", ...profileArgs] });
		}
		if (checks.includes("storage")) {
			specs.push({ check: "storage", bin: "aws", args: ["s3", "ls", ...profileArgs] });
		}
		if (checks.includes("compute")) {
			const regions = splitList(params.regions);
			if (regions.length === 0) {
				specs.push({
					check: "compute",
					bin: "aws",
					args: ["ec2", "describe-instances", "--output", "json", ...profileArgs],
				});
			} else {
				for (const region of regions) {
					specs.push({
						check: "compute",
						bin: "aws",
						args: ["ec2", "describe-instances", "--output", "json", "--region", region, ...profileArgs],
					});
				}
			}
		}
		return specs;
	}
	if (provider === "gcp") {
		const profileArgs = profile ? ["--configuration", profile] : [];
		if (checks.includes("identity")) {
			specs.push({ check: "identity", bin: "gcloud", args: [...profileArgs, "auth", "list", "--format=json"] });
		}
		if (checks.includes("projects")) {
			specs.push({ check: "projects", bin: "gcloud", args: [...profileArgs, "projects", "list", "--format=json"] });
		}
		if (checks.includes("storage")) {
			specs.push({
				check: "storage",
				bin: "gcloud",
				args: [...profileArgs, "storage", "buckets", "list", "--format=json"],
			});
		}
		if (checks.includes("compute")) {
			specs.push({
				check: "compute",
				bin: "gcloud",
				args: [...profileArgs, "compute", "instances", "list", "--format=json"],
			});
		}
		return specs;
	}
	const subscriptionArgs = profile ? ["--subscription", profile] : [];
	if (checks.includes("identity")) {
		specs.push({ check: "identity", bin: "az", args: ["account", "list", "--output", "json", ...subscriptionArgs] });
	}
	if (checks.includes("storage")) {
		specs.push({
			check: "storage",
			bin: "az",
			args: ["storage", "account", "list", "--output", "json", ...subscriptionArgs],
		});
	}
	if (checks.includes("compute")) {
		specs.push({ check: "compute", bin: "az", args: ["vm", "list", "--output", "json", ...subscriptionArgs] });
		specs.push({
			check: "compute-ip",
			bin: "az",
			args: ["vm", "list-ip-addresses", "--output", "json", ...subscriptionArgs],
		});
	}
	return specs;
}

async function runCloudPhase(specs: CloudCommandSpec[], cwd: string): Promise<CommandOutcome[]> {
	if (specs.length === 0) return [];
	const plans: RunPlan[] = specs.map((spec) => ({
		bin: spec.bin,
		args: spec.args,
		cwd,
		label: spec.check,
	}));
	const results = await runMany(plans, { cwd, timeoutMs: 120_000 });
	return results.map((result, index) => {
		const spec = specs[index];
		const outcome: CommandOutcome = {
			check: spec.check,
			command: result.cmd,
			exitCode: result.code,
			durationMs: result.durationMs,
			stdout: result.stdout,
			stderr: result.stderr,
		};
		appendJournal(cwd, {
			ts: new Date().toISOString(),
			tool: "cyber_cloud_enum",
			action: spec.check,
			command: result.cmd,
			exitCode: result.code,
			durationMs: result.durationMs,
			summary: result.timedOut ? "command timed out" : `exit ${result.code}`,
			severity: "info",
		});
		return outcome;
	});
}

/** Parse the bucket names out of `aws s3 ls` output. */
function parseAwsBucketList(stdout: string): string[] {
	const buckets: string[] = [];
	for (const line of stdout.split("\n")) {
		const match = /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s*$/.exec(line.trim());
		if (match) buckets.push(match[1]);
	}
	return buckets;
}

function publicAccessBlockState(stdout: string): { configured: boolean; effective: boolean } {
	const parsed = parseJson<AwsPublicAccessBlock>(stdout);
	const config = parsed?.PublicAccessBlockConfiguration;
	if (!config) return { configured: false, effective: false };
	const effective =
		config.BlockPublicAcls === true &&
		config.IgnorePublicAcls === true &&
		config.BlockPublicPolicy === true &&
		config.RestrictPublicBuckets === true;
	return { configured: true, effective };
}

function policyIsPublic(stdout: string): boolean | undefined {
	const parsed = parseJson<AwsBucketPolicyStatus>(stdout);
	if (!parsed?.PolicyStatus || typeof parsed.PolicyStatus.IsPublic !== "boolean") return undefined;
	return parsed.PolicyStatus.IsPublic;
}

function gcpPolicyMembers(parsed: unknown): string[] {
	const policy = asRecord(parsed) as GcpIamPolicy;
	const members: string[] = [];
	for (const binding of asArray<{ role?: string; members?: string[] }>(policy.bindings)) {
		for (const member of binding.members ?? []) {
			if (member === "allUsers" || member === "allAuthenticatedUsers") members.push(`${member} (${binding.role ?? "unknown role"})`);
		}
	}
	return members;
}

interface CloudAnalysis {
	identity: string[];
	accounts: string[];
	resources: ExposedResource[];
	errors: string[];
}

function analyzeAws(outcomes: CommandOutcome[], params: CloudParams, followUps: CommandOutcome[]): CloudAnalysis {
	const analysis: CloudAnalysis = { identity: [], accounts: [], resources: [], errors: [] };
	const accountFilter = splitList(params.account_ids);

	for (const outcome of outcomes) {
		if (outcome.exitCode !== 0) {
			analysis.errors.push(`${outcome.check}: ${outcome.command} exited ${outcome.exitCode}: ${outcome.stderr.trim() || "no output"}`);
		}
	}

	for (const outcome of outcomes.filter((item) => item.check === "identity")) {
		const identity = parseJson<AwsIdentity>(outcome.stdout);
		if (!identity) continue;
		if (identity.Account) analysis.accounts.push(identity.Account);
		analysis.identity.push(`Account ${identity.Account ?? "unknown"}`);
		if (identity.Arn) analysis.identity.push(`ARN ${identity.Arn}`);
		if (identity.UserId) analysis.identity.push(`UserId ${identity.UserId}`);
		if (accountFilter.length > 0 && identity.Account && !accountFilter.includes(identity.Account)) {
			analysis.errors.push(
				`The active credentials belong to account ${identity.Account}, which is not in the requested account list (${accountFilter.join(", ")}).`,
			);
		}
	}

	for (const outcome of outcomes.filter((item) => item.check === "iam")) {
		const users = asArray<AwsUser>((parseJson<{ Users?: AwsUser[] }>(outcome.stdout) ?? {}).Users);
		for (const user of users) {
			analysis.identity.push(`IAM user ${user.UserName ?? "unknown"}${user.Arn ? ` (${user.Arn})` : ""}`);
		}
	}

	for (const outcome of outcomes.filter((item) => item.check === "storage")) {
		const buckets = parseAwsBucketList(outcome.stdout);
		for (const bucket of buckets) {
			const block = followUps.find((item) => item.command.includes(`--bucket ${bucket} `) && item.command.includes("get-public-access-block"));
			const policy = followUps.find((item) => item.command.includes(`--bucket ${bucket} `) && item.command.includes("get-bucket-policy-status"));
			const state = block ? publicAccessBlockState(block.stdout) : { configured: false, effective: false };
			const isPublic = policy ? policyIsPublic(policy.stdout) : undefined;
			if (isPublic === true) {
				analysis.resources.push({
					kind: "storage",
					name: bucket,
					exposure: "bucket policy grants public access",
					severity: "high",
				});
			} else if (!state.effective) {
				analysis.resources.push({
					kind: "storage",
					name: bucket,
					exposure: state.configured
						? "public access block is not fully enabled"
						: "no public access block configured, the bucket may be publicly reachable",
					severity: "medium",
				});
			}
		}
	}

	for (const outcome of outcomes.filter((item) => item.check === "compute")) {
		const reservations = asArray<{ Instances?: AwsInstance[] }>(
			(parseJson<{ Reservations?: Array<{ Instances?: AwsInstance[] }> }>(outcome.stdout) ?? {}).Reservations,
		);
		for (const reservation of reservations) {
			for (const instance of asArray<AwsInstance>(reservation.Instances)) {
				if (!instance.PublicIpAddress) continue;
				analysis.resources.push({
					kind: "compute",
					name: instance.InstanceId ?? "unknown instance",
					region: instance.Placement?.AvailabilityZone,
					exposure: `public IP ${instance.PublicIpAddress} (${instance.State?.Name ?? "unknown state"})`,
					severity: "medium",
				});
			}
		}
	}

	return analysis;
}

function analyzeGcp(outcomes: CommandOutcome[], params: CloudParams, followUps: CommandOutcome[]): CloudAnalysis {
	const analysis: CloudAnalysis = { identity: [], accounts: [], resources: [], errors: [] };
	const accountFilter = splitList(params.account_ids);

	for (const outcome of outcomes) {
		if (outcome.exitCode !== 0) {
			analysis.errors.push(`${outcome.check}: ${outcome.command} exited ${outcome.exitCode}: ${outcome.stderr.trim() || "no output"}`);
		}
	}

	for (const outcome of outcomes.filter((item) => item.check === "identity")) {
		for (const account of asArray<GcpAuthAccount>(parseJson<GcpAuthAccount[]>(outcome.stdout))) {
			analysis.identity.push(`Account ${account.account ?? "unknown"} (${account.status ?? "unknown status"})`);
			if (account.expiration) analysis.identity.push(`Credential expires ${account.expiration}`);
		}
	}

	for (const outcome of outcomes.filter((item) => item.check === "projects")) {
		for (const project of asArray<GcpProject>(parseJson<GcpProject[]>(outcome.stdout))) {
			const projectId = project.projectId ?? "";
			if (accountFilter.length > 0 && !accountFilter.includes(projectId)) continue;
			analysis.accounts.push(`${projectId}${project.projectNumber ? ` (number ${project.projectNumber})` : ""}`);
			analysis.identity.push(`Project ${project.name ?? projectId} ${project.lifecycleState ?? ""}`.trim());
		}
	}

	for (const outcome of outcomes.filter((item) => item.check === "storage")) {
		for (const bucket of asArray<GcpBucket>(parseJson<GcpBucket[]>(outcome.stdout))) {
			const name = bucket.name ?? "unknown bucket";
			const policy = followUps.find((item) => item.command.includes(name));
			const publicMembers = policy ? gcpPolicyMembers(parseJson<unknown>(policy.stdout)) : [];
			if (publicMembers.length > 0) {
				analysis.resources.push({
					kind: "storage",
					name,
					region: bucket.location,
					exposure: `public IAM binding: ${publicMembers.join(", ")}`,
					severity: "high",
				});
			} else if (bucket.iamConfiguration?.uniformBucketLevelAccess?.enabled === false) {
				analysis.resources.push({
					kind: "storage",
					name,
					region: bucket.location,
					exposure: "uniform bucket level access is disabled",
					severity: "low",
				});
			}
		}
	}

	for (const outcome of outcomes.filter((item) => item.check === "compute")) {
		for (const instance of asArray<GcpInstance>(parseJson<GcpInstance[]>(outcome.stdout))) {
			const natIps: string[] = [];
			for (const nic of instance.networkInterfaces ?? []) {
				for (const access of nic.accessConfigs ?? []) {
					if (access.natIP) natIps.push(access.natIP);
				}
			}
			if (natIps.length === 0) continue;
			analysis.resources.push({
				kind: "compute",
				name: instance.name ?? instance.id ?? "unknown instance",
				region: instance.zone,
				exposure: `public IP ${natIps.join(", ")} (${instance.status ?? "unknown status"})`,
				severity: "medium",
			});
		}
	}

	return analysis;
}

function analyzeAzure(outcomes: CommandOutcome[], params: CloudParams, followUps: CommandOutcome[]): CloudAnalysis {
	const analysis: CloudAnalysis = { identity: [], accounts: [], resources: [], errors: [] };
	const accountFilter = splitList(params.account_ids);

	for (const outcome of outcomes) {
		if (outcome.exitCode !== 0) {
			analysis.errors.push(`${outcome.check}: ${outcome.command} exited ${outcome.exitCode}: ${outcome.stderr.trim() || "no output"}`);
		}
	}

	for (const outcome of outcomes.filter((item) => item.check === "identity")) {
		for (const subscription of asArray<AzureSubscription>(parseJson<AzureSubscription[]>(outcome.stdout))) {
			const id = subscription.id ?? "";
			if (accountFilter.length > 0 && !accountFilter.includes(id) && !accountFilter.includes(subscription.name ?? "")) {
				continue;
			}
			analysis.accounts.push(`${subscription.name ?? id}${id ? ` (${id})` : ""}`);
			analysis.identity.push(
				`Subscription ${subscription.name ?? "unknown"} state=${subscription.state ?? "unknown"}${subscription.user?.name ? ` user=${subscription.user.name}` : ""}`,
			);
		}
	}

	for (const outcome of outcomes.filter((item) => item.check === "storage")) {
		for (const account of asArray<AzureStorageAccount>(parseJson<AzureStorageAccount[]>(outcome.stdout))) {
			const name = account.name ?? "unknown storage account";
			if (account.properties?.allowBlobPublicAccess === true) {
				analysis.resources.push({
					kind: "storage",
					name,
					id: account.id,
					region: account.location,
					exposure: "allowBlobPublicAccess is enabled",
					severity: "high",
				});
			} else if (account.properties?.publicNetworkAccess === "Enabled") {
				analysis.resources.push({
					kind: "storage",
					name,
					id: account.id,
					region: account.location,
					exposure: "public network access enabled",
					severity: "low",
				});
			}
		}
	}

	const publicIps = new Map<string, string[]>();
	for (const outcome of followUps.filter((item) => item.check === "compute-ip")) {
		for (const entry of asArray<AzureIpAddress>(parseJson<AzureIpAddress[]>(outcome.stdout))) {
			const vmName = entry.virtualMachine?.name ?? "unknown";
			const addresses = (entry.virtualMachineNetworkInterface?.ipAddresses ?? [])
				.filter((address) => address.ipAddressType === "Public" && address.ipAddress)
				.map((address) => address.ipAddress ?? "");
			if (addresses.length === 0) continue;
			publicIps.set(vmName, [...(publicIps.get(vmName) ?? []), ...addresses]);
		}
	}

	for (const outcome of outcomes.filter((item) => item.check === "compute")) {
		for (const vm of asArray<AzureVm>(parseJson<AzureVm[]>(outcome.stdout))) {
			const name = vm.name ?? "unknown vm";
			const addresses = publicIps.get(name);
			if (!addresses || addresses.length === 0) continue;
			analysis.resources.push({
				kind: "compute",
				name,
				id: vm.id,
				region: vm.location,
				exposure: `public IP ${addresses.join(", ")} (${vm.provisioningState ?? "unknown state"})`,
				severity: "medium",
			});
		}
	}

	return analysis;
}

interface CloudParams {
	provider: CloudProvider;
	profile?: string;
	account_ids?: string;
	regions?: string;
	checks?: string;
	output_dir?: string;
}

const cloudTool = defineCyberTool({
	name: "cyber_cloud_enum",
	label: "Cloud enumeration",
	description:
		"Enumerate a cloud account and the resources it exposes. Uses the native CLIs " +
		"(aws sts get-caller-identity / iam list-users / s3 ls / ec2 describe-instances, " +
		"gcloud auth list / projects list / storage buckets list / compute instances list, " +
		"az account list / storage account list / vm list), parses the JSON output and reports " +
		"the identity, the accounts and every publicly exposed resource. Session tokens and " +
		"secret keys are never printed: only the field names and the artifact path are shown.",
	promptSnippet: "cyber_cloud_enum: enumerate cloud accounts and exposed resources",
	technique: "cloud-enumeration",
	requires: ["aws"],
	installHint:
		"Install the cloud CLI on Kali with: sudo apt install -y awscli (AWS), " +
		"sudo apt install -y google-cloud-cli (GCP), sudo apt install -y azure-cli (Azure)",
	parameters: Type.Object({
		provider: Type.Enum(["aws", "gcp", "azure"], {
			description: "Cloud provider to enumerate.",
		}),
		profile: Type.Optional(
			Type.String({
				description:
					"CLI profile to use. AWS: --profile. GCP: --configuration. " +
					"Azure: --subscription.",
			}),
		),
		account_ids: Type.Optional(
			Type.String({
				description:
					"Comma separated account, project or subscription ids to restrict the report to.",
			}),
		),
		regions: Type.Optional(
			Type.String({
				description: "Comma separated regions to enumerate. AWS only; the default region is used when omitted.",
			}),
		),
		checks: Type.Optional(
			Type.String({
				description:
					"Comma separated checks to run. identity, iam (AWS), projects (GCP), storage, compute. " +
					"Default: identity,storage.",
			}),
		),
		output_dir: Type.Optional(
			Type.String({
				description: "Directory to write the full output artifact to. Defaults to .cyberpi/artifacts.",
			}),
		),
	}),
	execute: async (params, ctx): Promise<CyberToolOutcome<CloudDetails>> => {
		const cwd = ctx.cwd;
		const provider = params.provider;
		const binary = PROVIDER_BINARY[provider];
		const install = PROVIDER_INSTALL[provider];

		if (!which(binary)) {
			return {
				summary: `The ${provider} CLI (${binary}) is not installed. Install it on Kali with: ${install}`,
				isError: true,
				details: {
					provider,
					checks: [],
					identity: [],
					accounts: [],
					resources: [],
					redactedFields: [],
					errors: [`${binary} is not installed`],
				},
			};
		}

		const requested = splitList(params.checks);
		const checks = requested.length > 0 ? requested : [...DEFAULT_CHECKS];
		const supported = PROVIDER_CHECKS[provider];
		const unknown = checks.filter((check) => !supported.includes(check));
		if (unknown.length > 0) {
			return {
				summary: `Unknown check(s) for ${provider}: ${unknown.join(", ")}. Supported checks: ${supported.join(", ")}.`,
				isError: true,
				details: {
					provider,
					checks,
					identity: [],
					accounts: [],
					resources: [],
					redactedFields: [],
					errors: [`unknown checks: ${unknown.join(", ")}`],
				},
			};
		}

		const specs = buildCloudCommands(provider, params, checks);
		const outcomes = await runCloudPhase(specs, cwd);

		// Follow-up calls: per-bucket public exposure and per-VM public addresses.
		const followUpSpecs: CloudCommandSpec[] = [];
		const bucketNames: string[] = [];
		for (const outcome of outcomes) {
			if (outcome.exitCode !== 0) continue;
			if (outcome.check === "storage" && provider === "aws") {
				bucketNames.push(...parseAwsBucketList(outcome.stdout));
			}
			if (outcome.check === "storage" && provider === "gcp") {
				for (const bucket of asArray<GcpBucket>(parseJson<GcpBucket[]>(outcome.stdout))) {
					if (bucket.name) bucketNames.push(bucket.name);
				}
			}
		}
		const profileArgs = params.profile?.trim()
			? provider === "aws"
				? ["--profile", params.profile.trim()]
				: provider === "gcp"
					? ["--configuration", params.profile.trim()]
					: ["--subscription", params.profile.trim()]
			: [];
		if (provider === "aws") {
			for (const bucket of bucketNames.slice(0, MAX_BUCKETS_INSPECTED)) {
				followUpSpecs.push({
					check: "storage-access",
					bin: "aws",
					args: ["s3api", "get-public-access-block", "--bucket", bucket, "--output", "json", ...profileArgs],
				});
			}
		}
		if (provider === "gcp") {
			for (const bucket of bucketNames.slice(0, MAX_BUCKETS_INSPECTED)) {
				followUpSpecs.push({
					check: "storage-policy",
					bin: "gcloud",
					args: [...profileArgs, "storage", "buckets", "get-iam-policy", `gs://${bucket}`, "--format=json"],
				});
			}
		}
		const followUps = await runCloudPhase(followUpSpecs, cwd);

		// AWS: confirm the policy status of the buckets that look exposed.
		const policySpecs: CloudCommandSpec[] = [];
		if (provider === "aws") {
			for (const bucket of bucketNames.slice(0, MAX_BUCKETS_INSPECTED)) {
				const block = followUps.find((item) => item.command.includes(`--bucket ${bucket} `));
				if (!block) continue;
				const state = publicAccessBlockState(block.stdout);
				if (state.effective) continue;
				policySpecs.push({
					check: "storage-policy",
					bin: "aws",
					args: ["s3api", "get-bucket-policy-status", "--bucket", bucket, "--output", "json", ...profileArgs],
				});
			}
		}
		const policies = await runCloudPhase(policySpecs, cwd);

		// Redact before anything is written to disk or returned to the model.
		const redactedKeys = new Set<string>();
		const redactOutcome = (outcome: CommandOutcome): CommandOutcome => {
			const parsed = parseJson<unknown>(outcome.stdout);
			if (parsed === undefined) {
				return { ...outcome, stdout: redactText(outcome.stdout), stderr: redactText(outcome.stderr) };
			}
			const redacted = redactValue(parsed, redactedKeys);
			return {
				...outcome,
				stdout: redactText(JSON.stringify(redacted, null, 2)),
				stderr: redactText(outcome.stderr),
			};
		};
		const allOutcomes = [...outcomes, ...followUps, ...policies].map(redactOutcome);
		const redactedFirst = allOutcomes.slice(0, outcomes.length);
		const redactedFollowUps = allOutcomes.slice(outcomes.length, outcomes.length + followUps.length);
		const redactedPolicies = allOutcomes.slice(outcomes.length + followUps.length);

		const analysis =
			provider === "aws"
				? analyzeAws(redactedFirst, params, [...redactedFollowUps, ...redactedPolicies])
				: provider === "gcp"
					? analyzeGcp(redactedFirst, params, redactedFollowUps)
					: analyzeAzure(redactedFirst, params, redactedFollowUps);

		const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
		const artifactName = `cloud-enum-${provider}-${timestamp}.json`;
		const artifactBody = {
			provider,
			generatedAt: new Date().toISOString(),
			profile: params.profile ?? null,
			accountIds: splitList(params.account_ids),
			regions: splitList(params.regions),
			checks,
			redactedFields: [...redactedKeys].sort(),
			identity: analysis.identity,
			accounts: analysis.accounts,
			resources: analysis.resources,
			errors: analysis.errors,
			commands: allOutcomes.map((outcome) => ({
				check: outcome.check,
				command: outcome.command,
				exitCode: outcome.exitCode,
				durationMs: outcome.durationMs,
				stdout: outcome.stdout,
				stderr: outcome.stderr,
			})),
		};
		let artifactPath: string;
		if (params.output_dir?.trim()) {
			const dir = path.resolve(ctx.cwd, params.output_dir.trim());
			ensureDir(dir);
			artifactPath = path.join(dir, artifactName);
			fs.writeFileSync(artifactPath, `${JSON.stringify(artifactBody, null, 2)}\n`, "utf8");
		} else {
			artifactPath = writeArtifact(cwd, artifactName, `${JSON.stringify(artifactBody, null, 2)}\n`);
		}

		const lines: string[] = [];
		lines.push(`Provider: ${provider}`);
		lines.push(`Checks:   ${checks.join(", ")}`);
		if (analysis.identity.length > 0) {
			lines.push("");
			lines.push("Identity:");
			for (const entry of analysis.identity) lines.push(`  ${entry}`);
		}
		if (analysis.accounts.length > 0) {
			lines.push("");
			lines.push("Accounts:");
			for (const entry of analysis.accounts) lines.push(`  ${entry}`);
		}
		lines.push("");
		lines.push(`Exposed resources: ${analysis.resources.length}`);
		for (const resource of analysis.resources) {
			const where = resource.region ? ` [${resource.region}]` : "";
			lines.push(`  [${resource.severity}] ${resource.kind} ${resource.name}${where}: ${resource.exposure}`);
		}
		if (analysis.errors.length > 0) {
			lines.push("");
			lines.push("Errors:");
			for (const error of analysis.errors) lines.push(`  ${error}`);
		}
		lines.push("");
		if (redactedKeys.size > 0) {
			lines.push(`Redacted credential fields: ${[...redactedKeys].sort().join(", ")} (values are not shown)`);
		} else {
			lines.push("Redacted credential fields: none");
		}
		lines.push(`Full output: ${artifactPath}`);

		const severity = analysis.resources.some((resource) => resource.severity === "high")
			? "high"
			: analysis.resources.length > 0
				? "medium"
				: "info";

		return {
			summary: `${provider} enumeration complete: ${analysis.accounts.length} account(s), ${analysis.resources.length} exposed resource(s)`,
			output: lines.join("\n"),
			severity,
			details: {
				provider,
				checks,
				identity: analysis.identity,
				accounts: analysis.accounts,
				resources: analysis.resources,
				artifact: artifactPath,
				redactedFields: [...redactedKeys].sort(),
				errors: analysis.errors,
			},
		};
	},
});

export const infraTools: ToolDefinition[] = [pivotTool, cloudTool];
