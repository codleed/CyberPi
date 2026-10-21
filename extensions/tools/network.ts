/**
 * Network tools: fast port scanning, service enumeration and packet capture.
 *
 * Every tool is a thin wrapper around a Kali binary. The shared toolkit owns
 * the authorization check, the binary check, the timeout, the truncation, the
 * artifact capture and the journal entry, so this file only has to build the
 * right command line and parse the structured output the scanner produces.
 *
 * The plan builder and the summariser of each tool are plain functions so the
 * interesting logic (argument construction, output parsing, surface indexing)
 * can be exercised without a Kali box.
 */

import fs from "node:fs";
import path from "node:path";
import { Type } from "@earendil-works/pi-ai";
import type { ToolDefinition } from "@earendil-works/pi-coding-agent";
import { ensureDir, engagementPaths } from "../lib/config.ts";
import type { RunPlan, RunResult } from "../lib/exec.ts";
import { addHosts, addServices } from "../lib/surface.ts";
import { defineCyberTool, parseJson, parseJsonLines, type CyberToolSummary } from "../lib/toolkit.ts";

const DEFAULT_SCAN_RATE = 1000;
const DEFAULT_CAPTURE_SECONDS = 60;
const PORTSCAN_TIMEOUT_MS = 300_000;
const SERVICE_SCAN_TIMEOUT_MS = 600_000;
const CAPTURE_GRACE_MS = 15_000;
const MAX_SCRIPT_OUTPUT = 500;

/** Characters that may appear in a host name, an IP literal or an interface. */
const SAFE_HOST = /^[A-Za-z0-9._:-]+$/;

/* -------------------------------------------------------------------------- */
/* shared helpers                                                             */
/* -------------------------------------------------------------------------- */

/**
 * Per-call context.
 *
 * The toolkit hands the engagement directory to `build` but not to
 * `summarize`, so the working directory travels with the parameter object.
 * A WeakMap keeps concurrent calls of the same tool from mixing up.
 */
interface ToolContext {
	cwd: string;
	capturePath?: string;
}

const toolContexts = new WeakMap<object, ToolContext>();

function rememberContext(params: object, context: ToolContext): void {
	toolContexts.set(params, context);
}

function recallContext(params: object): ToolContext {
	return toolContexts.get(params) ?? { cwd: process.cwd() };
}

/** Filesystem safe file name stem. */
function slug(text: string): string {
	const cleaned = text.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
	return cleaned.slice(0, 60) || "target";
}

/** Timestamp used to keep artifact names unique. */
function stamp(): string {
	return new Date().toISOString().replace(/[:.]/g, "-");
}

/**
 * The full output of a run.
 *
 * The toolkit keeps stdout truncated in memory but writes the untruncated
 * output to the artifact file, so parsers fall back to the artifact when the
 * in-memory copy was cut short.
 */
export function fullOutput(result: RunResult): string {
	if (!result.truncated) return result.stdout;
	if (result.artifact) {
		try {
			return fs.readFileSync(result.artifact, "utf8");
		} catch {
			return result.stdout;
		}
	}
	return result.stdout;
}

/** Cut a single field down so the transcript stays small. */
function clip(text: string, limit = MAX_SCRIPT_OUTPUT): string {
	const value = text.replace(/\s+/g, " ").trim();
	return value.length > limit ? `${value.slice(0, limit - 1)}…` : value;
}

/* -------------------------------------------------------------------------- */
/* naabu                                                                      */
/* -------------------------------------------------------------------------- */

export interface OpenPort {
	host: string;
	ip: string;
	port: number;
	protocol: string;
}

interface NaabuRecord {
	host?: unknown;
	ip?: unknown;
	port?: unknown;
	protocol?: unknown;
}

function toText(value: unknown): string {
	return typeof value === "string" ? value.trim() : "";
}

/** Parse naabu's JSON output (JSON lines, or a single JSON array). */
export function parseNaabuOutput(text: string): OpenPort[] {
	const records: NaabuRecord[] = [];
	const trimmed = text.trim();
	if (trimmed.startsWith("[")) {
		const parsed = parseJson<NaabuRecord[]>(trimmed);
		if (Array.isArray(parsed)) records.push(...parsed);
	} else {
		records.push(...parseJsonLines<NaabuRecord>(text));
	}

	const ports: OpenPort[] = [];
	const seen = new Set<string>();
	for (const record of records) {
		const port = typeof record.port === "number" ? record.port : Number(record.port);
		if (!Number.isFinite(port) || port <= 0 || port > 65535) continue;
		const ip = toText(record.ip);
		const host = toText(record.host) || ip;
		if (!host) continue;
		const protocol = toText(record.protocol).toLowerCase() || "tcp";
		const key = `${host}:${port}/${protocol}`;
		if (seen.has(key)) continue;
		seen.add(key);
		ports.push({ host, ip, port, protocol });
	}
	return ports;
}

/* -------------------------------------------------------------------------- */
/* nmap XML                                                                   */
/* -------------------------------------------------------------------------- */

interface XmlElement {
	name: string;
	attributes: Record<string, string>;
	children: XmlElement[];
	text: string;
}

function findTagEnd(source: string, start: number): number {
	let quote = "";
	for (let index = start; index < source.length; index++) {
		const char = source[index];
		if (quote) {
			if (char === quote) quote = "";
			continue;
		}
		if (char === '"' || char === "'") {
			quote = char;
			continue;
		}
		if (char === ">") return index;
	}
	return -1;
}

function parseAttributes(body: string): Record<string, string> {
	const attributes: Record<string, string> = {};
	const pattern = /([A-Za-z_][\w.:-]*)\s*=\s*("([^"]*)"|'([^']*)')/g;
	let match = pattern.exec(body);
	while (match !== null) {
		attributes[match[1]] = match[3] ?? match[4] ?? "";
		match = pattern.exec(body);
	}
	return attributes;
}

/**
 * A small XML reader covering the subset nmap produces: elements, attributes,
 * comments, the XML declaration and CDATA. It is deliberately forgiving: a
 * truncated document still yields the elements that were read.
 */
export function parseXml(source: string): XmlElement {
	const document: XmlElement = { name: "#document", attributes: {}, children: [], text: "" };
	const stack: XmlElement[] = [document];
	let index = 0;

	while (index < source.length) {
		const open = source.indexOf("<", index);
		if (open === -1) {
			stack[stack.length - 1].text += source.slice(index);
			break;
		}
		if (open > index) stack[stack.length - 1].text += source.slice(index, open);

		if (source.startsWith("<!--", open)) {
			const end = source.indexOf("-->", open);
			index = end === -1 ? source.length : end + 3;
			continue;
		}
		if (source.startsWith("<?", open)) {
			const end = source.indexOf("?>", open);
			index = end === -1 ? source.length : end + 2;
			continue;
		}
		if (source.startsWith("<![CDATA[", open)) {
			const end = source.indexOf("]]>", open);
			stack[stack.length - 1].text += source.slice(open + 9, end === -1 ? source.length : end);
			index = end === -1 ? source.length : end + 3;
			continue;
		}
		if (source.startsWith("</", open)) {
			const end = source.indexOf(">", open);
			if (end === -1) break;
			const name = source.slice(open + 2, end).trim();
			for (let depth = stack.length - 1; depth > 0; depth--) {
				if (stack[depth].name === name) {
					stack.length = depth;
					break;
				}
			}
			index = end + 1;
			continue;
		}

		const end = findTagEnd(source, open);
		if (end === -1) break;
		const raw = source.slice(open + 1, end);
		const selfClosing = raw.endsWith("/");
		const body = selfClosing ? raw.slice(0, -1) : raw;
		const space = body.search(/\s/);
		const name = (space === -1 ? body : body.slice(0, space)).trim();
		const attributes = space === -1 ? {} : parseAttributes(body.slice(space));
		const element: XmlElement = { name, attributes, children: [], text: "" };
		stack[stack.length - 1].children.push(element);
		if (!selfClosing) stack.push(element);
		index = end + 1;
	}

	return document;
}

/** Every descendant with the given tag name. */
export function findAll(element: XmlElement, name: string): XmlElement[] {
	const found: XmlElement[] = [];
	for (const child of element.children) {
		if (child.name === name) found.push(child);
		found.push(...findAll(child, name));
	}
	return found;
}

/** The first descendant with the given tag name. */
export function findFirst(element: XmlElement, name: string): XmlElement | undefined {
	return findAll(element, name)[0];
}

export interface NmapScript {
	id: string;
	output: string;
}

export interface NmapService {
	host: string;
	ip: string;
	port: number;
	protocol: string;
	state: string;
	reason: string;
	service: string;
	version: string;
	details: Record<string, string>;
	scripts: NmapScript[];
}

export interface NmapHost {
	host: string;
	ip: string;
	scripts: NmapScript[];
}

/** Extract the XML document from an nmap run, discarding scanner chatter. */
export function extractXml(text: string): string {
	const start = text.indexOf("<nmaprun");
	if (start === -1) return "";
	const end = text.lastIndexOf("</nmaprun>");
	if (end === -1) return "";
	return text.slice(start, end + "</nmaprun>".length);
}

function readScripts(container: XmlElement | undefined): NmapScript[] {
	if (!container) return [];
	return findAll(container, "script").map((script) => ({
		id: script.attributes.id ?? "script",
		output: clip(script.attributes.output ?? script.text ?? ""),
	}));
}

/** Parse nmap's `-oX` document into hosts and open services. */
export function parseNmapXml(xml: string): { hosts: NmapHost[]; services: NmapService[] } {
	const hosts: NmapHost[] = [];
	const services: NmapService[] = [];
	const document = parseXml(xml);
	const run = findFirst(document, "nmaprun");
	if (!run) return { hosts, services };

	for (const host of findAll(run, "host")) {
		const address = findFirst(host, "address");
		const ip = address?.attributes.addr ?? "";
		const hostname = findFirst(host, "hostname");
		const name = hostname?.attributes.name ?? ip;
		if (!name) continue;

		hosts.push({ host: name, ip, scripts: readScripts(findFirst(host, "hostscript")) });

		const ports = findFirst(host, "ports");
		if (!ports) continue;
		for (const port of findAll(ports, "port")) {
			const state = findFirst(port, "state");
			const stateName = state?.attributes.state ?? "unknown";
			if (!stateName.startsWith("open")) continue;

			const service = findFirst(port, "service");
			const product = service?.attributes.product ?? "";
			const version = service?.attributes.version ?? "";
			const details: Record<string, string> = {};
			for (const [key, value] of Object.entries(service?.attributes ?? {})) {
				if (key === "name" || key === "product" || key === "version") continue;
				if (value) details[key] = value;
			}
			if (state?.attributes.reason) details.reason = state.attributes.reason;
			if (state?.attributes.reason_ttl) details.reasonTtl = state.attributes.reason_ttl;

			services.push({
				host: name,
				ip,
				port: Number(port.attributes.portid ?? 0),
				protocol: port.attributes.protocol ?? "tcp",
				state: stateName,
				reason: state?.attributes.reason ?? "",
				service: service?.attributes.name ?? "",
				version: [product, version].filter((part) => part.length > 0).join(" "),
				details,
				scripts: readScripts(port),
			});
		}
	}

	return { hosts, services };
}

/* -------------------------------------------------------------------------- */
/* pcap                                                                       */
/* -------------------------------------------------------------------------- */

const PCAP_MAGIC_LE = [0xa1b2c3d4, 0xa1b23c4d];
const PCAP_MAGIC_BE = [0xd4c3b2a1, 0x4d3cb2a1];
const PCAPNG_MAGIC = 0x0a0d0d0a;

/** Count the packets stored in a capture file. */
export function countPcapPackets(file: string): number | undefined {
	let buffer: Buffer;
	try {
		buffer = fs.readFileSync(file);
	} catch {
		return undefined;
	}
	if (buffer.length < 24) return undefined;

	const magic = buffer.readUInt32LE(0);
	if (magic === PCAPNG_MAGIC) {
		let offset = 0;
		let count = 0;
		while (offset + 12 <= buffer.length) {
			const type = buffer.readUInt32LE(offset);
			const length = buffer.readUInt32LE(offset + 4);
			if (length < 12 || offset + length > buffer.length) break;
			if (type === 6) count++;
			offset += length;
		}
		return count;
	}

	const littleEndian = PCAP_MAGIC_LE.includes(magic);
	const bigEndian = PCAP_MAGIC_BE.includes(magic);
	if (!littleEndian && !bigEndian) return undefined;

	let offset = 24;
	let count = 0;
	while (offset + 16 <= buffer.length) {
		const captured = littleEndian ? buffer.readUInt32LE(offset + 8) : buffer.readUInt32BE(offset + 8);
		if (captured > buffer.length) break;
		offset += 16 + captured;
		count++;
	}
	return count;
}

/** Parse the packet counter tcpdump prints when it exits. */
export function parseTcpdumpCount(text: string): number | undefined {
	const match = /(\d+)\s+packets\s+captured/i.exec(text);
	if (!match) return undefined;
	const value = Number(match[1]);
	return Number.isFinite(value) ? value : undefined;
}

/* -------------------------------------------------------------------------- */
/* cyber_portscan                                                             */
/* -------------------------------------------------------------------------- */

export interface PortscanParams {
	target: string;
	ports?: string;
	rate?: number;
	top_ports?: number;
}

export interface PortscanDetails {
	target: string;
	openPorts: OpenPort[];
	count: number;
	artifact?: string;
}

/** Build the naabu command line. */
export function buildPortscanPlan(params: PortscanParams): RunPlan {
	const rate = params.rate ?? DEFAULT_SCAN_RATE;
	const args = ["-host", params.target, "-json", "-silent", "-rate", String(rate)];
	if (params.ports) {
		args.push("-p", params.ports);
	} else if (params.top_ports !== undefined) {
		args.push("-top-ports", String(params.top_ports));
	}
	return {
		bin: "naabu",
		args,
		label: `portscan-${slug(params.target)}-${stamp()}`,
		target: params.target,
	};
}

/** Parse a naabu run, index the open ports and summarise them. */
export function summarizePortscan(
	results: RunResult[],
	params: PortscanParams,
	cwd: string,
): CyberToolSummary<PortscanDetails> {
	const result = results[0];
	const ports = parseNaabuOutput(result ? fullOutput(result) : "");
	const artifact = result?.artifact;

	const addresses = new Map<string, string[]>();
	for (const port of ports) {
		if (!port.ip) continue;
		const known = addresses.get(port.host) ?? [];
		if (!known.includes(port.ip)) known.push(port.ip);
		addresses.set(port.host, known);
	}
	if (addresses.size > 0) {
		addHosts(
			cwd,
			[...addresses.entries()].map(([host, list]) => ({ host, addresses: list, source: "naabu" })),
		);
	}
	if (ports.length > 0) {
		addServices(
			cwd,
			ports.map((port) => ({
				host: port.host,
				port: port.port,
				protocol: port.protocol,
				source: "naabu",
			})),
		);
	}

	const summary =
		ports.length === 0
			? `naabu found no open ports on ${params.target}`
			: `naabu found ${ports.length} open port${ports.length === 1 ? "" : "s"} on ${params.target}`;
	const body = ports.map((port) => {
		const address = port.ip && port.ip !== port.host ? ` (ip ${port.ip})` : "";
		return `${port.host}:${port.port}/${port.protocol}${address}`;
	});

	return {
		summary,
		output: body.length > 0 ? [`open ports (${body.length}):`, ...body].join("\n") : "",
		details: { target: params.target, openPorts: ports, count: ports.length, artifact },
		severity: "info",
		isError: result !== undefined && result.code !== 0 && ports.length === 0,
	};
}

const portscanTool = defineCyberTool({
	name: "cyber_portscan",
	label: "Port scan",
	description:
		"Fast SYN port scan of an authorized target with naabu. Returns every open port and records it in the engagement surface index.",
	promptSnippet: "cyber_portscan: fast SYN port scan of a scoped target with naabu",
	promptGuidelines: [
		"Use cyber_portscan first to find open ports, then cyber_service_scan to identify the services behind them.",
	],
	technique: "port-scan",
	requires: ["naabu"],
	installHint: "Install naabu on Kali with: sudo apt install -y naabu",
	timeoutMs: PORTSCAN_TIMEOUT_MS,
	cacheTtlMs: 600_000,
	parameters: Type.Object({
		target: Type.String({ description: "Host, IP address or CIDR range to scan" }),
		ports: Type.Optional(Type.String({ description: "Port list, e.g. 1-1024 or 80,443,8080" })),
		rate: Type.Optional(Type.Number({ description: "Packets per second", default: DEFAULT_SCAN_RATE })),
		top_ports: Type.Optional(Type.Number({ description: "Scan only the N most common ports" })),
	}),
	build: (params, ctx) => {
		rememberContext(params as unknown as object, { cwd: ctx.cwd });
		return buildPortscanPlan(params);
	},
	summarize: (results, params) =>
		summarizePortscan(results, params, recallContext(params as unknown as object).cwd),
});

/* -------------------------------------------------------------------------- */
/* cyber_service_scan                                                         */
/* -------------------------------------------------------------------------- */

export interface ServiceScanParams {
	target: string;
	ports?: string;
	nse_scripts?: string;
	timing?: "paranoid" | "normal" | "aggressive";
	version_only?: boolean;
}

export interface ServiceScanDetails {
	target: string;
	services: NmapService[];
	count: number;
	artifact?: string;
}

/** Build the nmap command line. */
export function buildServiceScanPlan(params: ServiceScanParams): RunPlan {
	const timing = params.timing ?? "normal";
	const template = timing === "paranoid" ? "0" : timing === "aggressive" ? "4" : "3";
	const args = ["-sV", "-Pn", `-T${template}`, "-oX", "-"];
	if (params.ports) args.push("-p", params.ports);
	if (params.version_only) {
		args.push("--version-light");
	} else if (params.nse_scripts) {
		args.push("--script", params.nse_scripts);
	}
	args.push(params.target);
	return {
		bin: "nmap",
		args,
		label: `nmap-${slug(params.target)}-${stamp()}`,
		target: params.target,
	};
}

/** Parse an nmap run, index the services and summarise them. */
export function summarizeServiceScan(
	results: RunResult[],
	params: ServiceScanParams,
	cwd: string,
): CyberToolSummary<ServiceScanDetails> {
	const result = results[0];
	const xml = extractXml(result ? fullOutput(result) : "");
	const { hosts, services } = parseNmapXml(xml);
	const artifact = result?.artifact;

	const hostEntries = hosts
		.filter((host) => host.host.length > 0)
		.map((host) => {
			const entry: { host: string; addresses?: string[]; source: string } = {
				host: host.host,
				source: "nmap",
			};
			if (host.ip) entry.addresses = [host.ip];
			return entry;
		});
	if (hostEntries.length > 0) addHosts(cwd, hostEntries);

	if (services.length > 0) {
		addServices(
			cwd,
			services.map((service) => {
				const entry: {
					host: string;
					port: number;
					protocol: string;
					service?: string;
					version?: string;
					details?: Record<string, string>;
					source: string;
				} = {
					host: service.host,
					port: service.port,
					protocol: service.protocol,
					source: "nmap",
				};
				if (service.service) entry.service = service.service;
				if (service.version) entry.version = service.version;
				if (Object.keys(service.details).length > 0) entry.details = service.details;
				return entry;
			}),
		);
	}

	const body: string[] = [];
	if (services.length > 0) body.push(`open services (${services.length}):`);
	for (const service of services) {
		const title = service.service || "unknown";
		const version = service.version ? ` — ${service.version}` : "";
		body.push(`${service.port}/${service.protocol} open ${title}${version}`);
		for (const script of service.scripts) {
			body.push(`  nse ${script.id}: ${script.output}`);
		}
	}
	for (const host of hosts) {
		for (const script of host.scripts) {
			body.push(`  nse ${script.id} (host): ${script.output}`);
		}
	}
	if (params.version_only && params.nse_scripts) {
		body.push("note: NSE scripts were skipped because version_only was set.");
	}
	if (body.length === 0 && result && result.stderr.trim().length > 0) {
		body.push(result.stderr.trim());
	}

	const summary =
		services.length === 0
			? `nmap found no open services on ${params.target}`
			: `nmap found ${services.length} open service${services.length === 1 ? "" : "s"} on ${params.target}`;

	return {
		summary,
		output: body.join("\n"),
		details: { target: params.target, services, count: services.length, artifact },
		severity: "info",
		isError: result !== undefined && result.code !== 0 && services.length === 0,
	};
}

const serviceScanTool = defineCyberTool({
	name: "cyber_service_scan",
	label: "Service scan",
	description:
		"Service and version detection on an authorized target with nmap. Reports every open port with its service, product version and NSE script output.",
	promptSnippet: "cyber_service_scan: nmap service and version detection on a scoped target",
	promptGuidelines: [
		"cyber_service_scan needs raw privileges for a SYN scan; run CyberPi with sudo on Kali.",
	],
	technique: "service-enumeration",
	requires: ["nmap"],
	installHint: "Install nmap on Kali with: sudo apt install -y nmap",
	timeoutMs: SERVICE_SCAN_TIMEOUT_MS,
	cacheTtlMs: 900_000,
	parameters: Type.Object({
		target: Type.String({ description: "Host, IP address or CIDR range to scan" }),
		ports: Type.Optional(Type.String({ description: "Port list, e.g. 80,443,8080 or 1-1024" })),
		nse_scripts: Type.Optional(Type.String({ description: "NSE scripts to run, e.g. http-title,safe" })),
		timing: Type.Optional(
			Type.Union([Type.Literal("paranoid"), Type.Literal("normal"), Type.Literal("aggressive")], {
				default: "normal",
			}),
		),
		version_only: Type.Optional(Type.Boolean({ description: "Detect versions only, without NSE scripts" })),
	}),
	build: (params, ctx) => {
		rememberContext(params as unknown as object, { cwd: ctx.cwd });
		return buildServiceScanPlan(params);
	},
	summarize: (results, params) =>
		summarizeServiceScan(results, params, recallContext(params as unknown as object).cwd),
});

/* -------------------------------------------------------------------------- */
/* cyber_capture                                                               */
/* -------------------------------------------------------------------------- */

export interface CaptureParams {
	target?: string;
	port?: number;
	duration_seconds?: number;
	interface?: string;
}

export interface CaptureDetails {
	path: string;
	packets: number;
	durationSeconds: number;
	interface?: string;
	filter: string;
	tcpdumpCount?: number;
}

/** Build the tcpdump filter expression for the requested host and port. */
export function buildCaptureFilter(params: CaptureParams): string {
	const parts: string[] = [];
	if (params.target) parts.push(`host ${params.target}`);
	if (params.port !== undefined) parts.push(`port ${params.port}`);
	return parts.join(" and ");
}

/** Build the tcpdump command line, writing the capture into the engagement. */
export function buildCapturePlan(params: CaptureParams, cwd: string): { plan: RunPlan; capturePath: string } {
	const paths = engagementPaths(cwd);
	ensureDir(paths.artifacts);
	const duration = params.duration_seconds ?? DEFAULT_CAPTURE_SECONDS;
	if (!Number.isFinite(duration) || duration <= 0) {
		throw new Error("duration_seconds must be a positive number of seconds.");
	}
	if (params.interface !== undefined && !SAFE_HOST.test(params.interface)) {
		throw new Error(`invalid interface name: ${params.interface}`);
	}
	if (params.target !== undefined && !SAFE_HOST.test(params.target)) {
		throw new Error(`invalid capture target: ${params.target}`);
	}
	if (params.port !== undefined && (!Number.isInteger(params.port) || params.port <= 0 || params.port > 65535)) {
		throw new Error(`invalid port: ${params.port}`);
	}

	const name = `capture-${slug(params.target ?? params.interface ?? "any")}-${stamp()}`;
	const capturePath = path.join(paths.artifacts, `${name}.pcap`);
	const args = ["-U", "-w", capturePath];
	if (params.interface) args.push("-i", params.interface);
	const filter = buildCaptureFilter(params);
	if (filter.length > 0) args.push(filter);

	return {
		capturePath,
		plan: {
			bin: "tcpdump",
			args,
			label: name,
			target: params.target,
			timeoutMs: Math.round(duration * 1000) + CAPTURE_GRACE_MS,
		},
	};
}

/** Summarise a capture run, counting packets from tcpdump or from the file. */
export function summarizeCapture(
	results: RunResult[],
	params: CaptureParams,
	capturePath: string,
): CyberToolSummary<CaptureDetails> {
	const result = results[0];
	const duration = params.duration_seconds ?? DEFAULT_CAPTURE_SECONDS;
	const filter = buildCaptureFilter(params);

	const tcpdumpCount = result ? parseTcpdumpCount(`${result.stdout}\n${result.stderr}`) : undefined;
	const fileCount = capturePath ? countPcapPackets(capturePath) : undefined;
	const packets = tcpdumpCount ?? fileCount ?? 0;

	const body = [
		`capture file: ${capturePath}`,
		`packets captured: ${packets}`,
		`duration: ${duration}s`,
		`interface: ${params.interface ?? "default"}`,
		`filter: ${filter || "none"}`,
	];
	if (tcpdumpCount === undefined && fileCount !== undefined) {
		body.push("packet count read from the capture file (tcpdump was stopped by the timeout).");
	}

	return {
		summary: `tcpdump captured ${packets} packet${packets === 1 ? "" : "s"} into ${capturePath}`,
		output: body.join("\n"),
		details: {
			path: capturePath,
			packets,
			durationSeconds: duration,
			interface: params.interface,
			filter,
			tcpdumpCount,
		},
		severity: "info",
		isError: result !== undefined && result.code !== 0 && packets === 0,
	};
}

const captureTool = defineCyberTool({
	name: "cyber_capture",
	label: "Packet capture",
	description:
		"Capture network traffic with tcpdump into a pcap file inside the engagement artifacts directory, optionally filtered by host and port.",
	promptSnippet: "cyber_capture: capture packets with tcpdump into a pcap artifact",
	promptGuidelines: [
		"cyber_capture needs raw privileges for the interface; run CyberPi with sudo on Kali.",
	],
	technique: "recon",
	requires: ["tcpdump"],
	installHint: "Install tcpdump on Kali with: sudo apt install -y tcpdump",
	parameters: Type.Object({
		target: Type.Optional(Type.String({ description: "Only capture traffic of this host or IP" })),
		port: Type.Optional(Type.Number({ description: "Only capture traffic on this port" })),
		duration_seconds: Type.Optional(
			Type.Number({ description: "How long to capture, in seconds", default: DEFAULT_CAPTURE_SECONDS }),
		),
		interface: Type.Optional(Type.String({ description: "Interface to capture on, e.g. eth0" })),
	}),
	build: (params, ctx) => {
		const { plan, capturePath } = buildCapturePlan(params, ctx.cwd);
		rememberContext(params as unknown as object, { cwd: ctx.cwd, capturePath });
		return plan;
	},
	summarize: (results, params) => {
		const context = recallContext(params as unknown as object);
		return summarizeCapture(results, params, context.capturePath ?? "");
	},
});

export const networkTools: ToolDefinition[] = [portscanTool, serviceScanTool, captureTool];
