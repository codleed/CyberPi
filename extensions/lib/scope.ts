/**
 * Engagement scope: the authorization model CyberPi enforces on every action.
 *
 * A scope file (`<engagement>/.cyberpi/scope.json`) lists the targets, ports,
 * protocols and techniques the client authorized. Tools consult it before
 * they touch the network. Targets that are not in scope are refused, and the
 * refusal is journalled, so the engagement record shows exactly what was
 * attempted.
 */

import fs from "node:fs";
import os from "node:os";
import { engagementPaths } from "./config.ts";

export interface ScopeRule {
	/** Optional label for the rule. */
	id?: string;
	/**
	 * Target specification:
	 * - `10.0.0.0/24` - IPv4 CIDR
	 * - `2001:db8::/32` - IPv6 CIDR
	 * - `192.168.1.10` - single host
	 * - `example.com` - host and its subdomains
	 * - `*.example.com` - subdomains only
	 * - `exact:example.com` - host only, no subdomains
	 */
	target: string;
	/** Restrict the rule to specific ports. */
	ports?: number[];
	/** Restrict the rule to specific protocols (`tcp`, `udp`). */
	protocols?: string[];
	/** Restrict the rule to specific techniques. */
	techniques?: string[];
	notes?: string;
}

export interface ScopeAuthorization {
	/** Free-text statement of what was authorized. */
	statement?: string;
	authorizedBy?: string;
	/** ISO date the window opens. */
	start?: string;
	/** ISO date the window closes. */
	end?: string;
}

export interface ScopeConfig {
	/** Engagement name, e.g. "acme-web-pentest-2025-03". */
	engagement: string;
	client?: string;
	authorization?: ScopeAuthorization;
	/** Authorized targets. */
	rules: ScopeRule[];
	/**
	 * Techniques allowed anywhere inside the target scope. Empty means every
	 * technique is allowed for the listed targets.
	 */
	techniques?: string[];
	/**
	 * Allow actions against this machine (loopback and local interface
	 * addresses). Defaults to true so the harness can be self-tested.
	 */
	allowSelfTest?: boolean;
	notes?: string;
}

export interface ScopeTarget {
	/** Hostname or IP literal. */
	host: string;
	port?: number;
	scheme?: string;
	/** True when the target is an IP literal. */
	isIp: boolean;
}

export interface ScopeDecision {
	allowed: boolean;
	reason: string;
	/** The rule that authorized the action, when allowed. */
	rule?: ScopeRule;
	/** True when the target was allowed only because self-testing is enabled. */
	selfTest?: boolean;
}

/** Strip comments from a JSONC document so scope files can be annotated. */
export function stripJsonComments(input: string): string {
	let output = "";
	let inString = false;
	let inLineComment = false;
	let inBlockComment = false;
	for (let i = 0; i < input.length; i++) {
		const char = input[i];
		const next = input[i + 1];
		if (inLineComment) {
			if (char === "\n") {
				inLineComment = false;
				output += char;
			}
			continue;
		}
		if (inBlockComment) {
			if (char === "*" && next === "/") {
				inBlockComment = false;
				i++;
			}
			continue;
		}
		if (inString) {
			output += char;
			if (char === "\\") {
				output += next ?? "";
				i++;
			} else if (char === '"') {
				inString = false;
			}
			continue;
		}
		if (char === '"') {
			inString = true;
			output += char;
			continue;
		}
		if (char === "/" && next === "/") {
			inLineComment = true;
			i++;
			continue;
		}
		if (char === "/" && next === "*") {
			inBlockComment = true;
			i++;
			continue;
		}
		output += char;
	}
	return output;
}

/** Parse a scope document. Throws with a precise message on malformed input. */
export function parseScope(raw: string): ScopeConfig {
	let parsed: unknown;
	try {
		parsed = JSON.parse(stripJsonComments(raw));
	} catch (error) {
		throw new Error(`scope.json is not valid JSON: ${(error as Error).message}`);
	}
	if (typeof parsed !== "object" || parsed === null) {
		throw new Error("scope.json must contain a JSON object");
	}
	const config = parsed as Partial<ScopeConfig>;
	if (typeof config.engagement !== "string" || config.engagement.length === 0) {
		throw new Error('scope.json must define a non-empty "engagement" name');
	}
	if (!Array.isArray(config.rules)) {
		throw new Error('scope.json must define a "rules" array');
	}
	for (const [index, rule] of config.rules.entries()) {
		if (typeof rule?.target !== "string" || rule.target.length === 0) {
			throw new Error(`scope.json rule #${index + 1} is missing a "target"`);
		}
	}
	return {
		engagement: config.engagement,
		client: config.client,
		authorization: config.authorization,
		rules: config.rules,
		techniques: config.techniques ?? [],
		allowSelfTest: config.allowSelfTest ?? true,
		notes: config.notes,
	};
}

/** Load the scope for a working directory. Returns null when no scope file exists. */
export function loadScope(cwd: string = process.cwd()): ScopeConfig | null {
	const scopePath = engagementPaths(cwd).scope;
	if (!fs.existsSync(scopePath)) return null;
	return parseScope(fs.readFileSync(scopePath, "utf8"));
}

/** Parse a user-supplied target into host, optional port and optional scheme. */
export function parseTarget(raw: string): ScopeTarget {
	let value = raw.trim();
	if (!value) throw new Error("target is empty");
	let scheme: string | undefined;
	const schemeMatch = /^([a-z][a-z0-9+.-]*):\/\//i.exec(value);
	if (schemeMatch) {
		scheme = schemeMatch[1].toLowerCase();
		value = value.slice(schemeMatch[0].length);
	}
	// Strip path, query and fragment.
	value = value.split(/[/?#]/)[0];
	// Strip credentials.
	const atIndex = value.lastIndexOf("@");
	if (atIndex !== -1) value = value.slice(atIndex + 1);
	let port: number | undefined;
	if (value.startsWith("[")) {
		const end = value.indexOf("]");
		if (end === -1) throw new Error(`malformed IPv6 target: ${raw}`);
		const host = value.slice(1, end);
		const rest = value.slice(end + 1);
		if (rest.startsWith(":")) port = Number(rest.slice(1));
		return { host, port: Number.isFinite(port) ? port : undefined, scheme, isIp: isIpLiteral(host) };
	}
	const colonIndex = value.lastIndexOf(":");
	if (colonIndex !== -1 && value.indexOf(":") === colonIndex) {
		const candidate = Number(value.slice(colonIndex + 1));
		if (Number.isFinite(candidate) && candidate > 0 && candidate <= 65535) {
			port = candidate;
			value = value.slice(0, colonIndex);
		}
	}
	return { host: value.toLowerCase(), port, scheme, isIp: isIpLiteral(value) };
}

/** True when the string is an IPv4 or IPv6 literal. */
export function isIpLiteral(host: string): boolean {
	return parseIp(host) !== null;
}

/** Parse an IPv4 or IPv6 literal into bytes. */
export function parseIp(host: string): Uint8Array | null {
	const value = host.trim();
	if (value.includes(":")) {
		const parts = value.split("::");
		if (parts.length > 2) return null;
		const head = parts[0] ? parts[0].split(":").filter(Boolean) : [];
		const tail = parts.length === 2 ? (parts[1] ? parts[1].split(":").filter(Boolean) : []) : [];
		const missing = 8 - head.length - tail.length;
		if (parts.length === 1 && head.length !== 8) return null;
		if (missing < 0) return null;
		const groups = [...head, ...Array<string>(missing).fill("0"), ...tail];
		if (groups.length !== 8) return null;
		const bytes = new Uint8Array(16);
		for (const [index, group] of groups.entries()) {
			if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
			const num = parseInt(group, 16);
			bytes[index * 2] = (num >> 8) & 0xff;
			bytes[index * 2 + 1] = num & 0xff;
		}
		return bytes;
	}
	const octets = value.split(".");
	if (octets.length !== 4) return null;
	const bytes = new Uint8Array(4);
	for (const [index, octet] of octets.entries()) {
		if (!/^\d{1,3}$/.test(octet)) return null;
		const num = Number(octet);
		if (num > 255) return null;
		bytes[index] = num;
	}
	return bytes;
}

/** True when `ip` falls inside `cidr`. */
export function ipInCidr(ip: string, cidr: string): boolean {
	const [network, bitsRaw] = cidr.split("/");
	const target = parseIp(ip);
	const base = parseIp(network);
	if (!target || !base) return false;
	if (target.length !== base.length) return false;
	const bits = bitsRaw === undefined ? base.length * 8 : Number(bitsRaw);
	if (!Number.isInteger(bits) || bits < 0 || bits > base.length * 8) return false;
	const fullBytes = Math.floor(bits / 8);
	for (let i = 0; i < fullBytes; i++) {
		if (target[i] !== base[i]) return false;
	}
	const remainingBits = bits % 8;
	if (remainingBits === 0) return true;
	const mask = (0xff << (8 - remainingBits)) & 0xff;
	return (target[fullBytes] & mask) === (base[fullBytes] & mask);
}

/** Local interface addresses and loopback names, used for self-testing. */
export function selfTargets(): Set<string> {
	const targets = new Set<string>(["localhost", "localhost.localdomain", "127.0.0.1", "::1", "0.0.0.0"]);
	for (const addresses of Object.values(os.networkInterfaces())) {
		for (const address of addresses ?? []) {
			targets.add(address.address.toLowerCase());
		}
	}
	return targets;
}

/** Check whether a target specification matches a host. */
export function ruleMatchesHost(rule: ScopeRule, host: string): boolean {
	const spec = rule.target.trim().toLowerCase();
	const normalizedHost = host.toLowerCase();
	if (spec.includes("/")) {
		return ipInCidr(normalizedHost, spec);
	}
	if (spec.startsWith("exact:")) {
		return normalizedHost === spec.slice("exact:".length);
	}
	if (spec.startsWith("*.")) {
		const suffix = spec.slice(2);
		return normalizedHost.endsWith(`.${suffix}`) && normalizedHost !== suffix;
	}
	if (isIpLiteral(spec)) {
		return normalizedHost === spec;
	}
	// A bare domain covers the domain and its subdomains.
	return normalizedHost === spec || normalizedHost.endsWith(`.${spec}`);
}

/** Check a single rule against a target, including port, protocol and technique filters. */
export function ruleAllows(
	rule: ScopeRule,
	target: ScopeTarget,
	options: { port?: number; protocol?: string; technique?: string },
): { allowed: boolean; reason: string } {
	if (!ruleMatchesHost(rule, target.host)) {
		return { allowed: false, reason: `host ${target.host} does not match rule target ${rule.target}` };
	}
	if (rule.ports && rule.ports.length > 0) {
		const port = options.port ?? target.port;
		if (port === undefined) {
			return { allowed: false, reason: `rule ${rule.target} is limited to ports ${rule.ports.join(", ")}` };
		}
		if (!rule.ports.includes(port)) {
			return { allowed: false, reason: `port ${port} is not in the allowed ports ${rule.ports.join(", ")}` };
		}
	}
	if (rule.protocols && rule.protocols.length > 0) {
		const protocol = options.protocol?.toLowerCase();
		if (!protocol || !rule.protocols.some((p) => p.toLowerCase() === protocol)) {
			return {
				allowed: false,
				reason: `protocol ${protocol ?? "unknown"} is not in the allowed protocols ${rule.protocols.join(", ")}`,
			};
		}
	}
	if (rule.techniques && rule.techniques.length > 0) {
		const technique = options.technique?.toLowerCase();
		if (!technique || !rule.techniques.some((t) => t.toLowerCase() === technique)) {
			return {
				allowed: false,
				reason: `technique ${technique ?? "unknown"} is not allowed by rule ${rule.target}`,
			};
		}
	}
	return { allowed: true, reason: "authorized" };
}

export interface ScopeCheckOptions {
	port?: number;
	protocol?: string;
	/** Technique identifier, e.g. "password-audit", "exploit". */
	technique?: string;
}

/**
 * Decide whether an action against a target is authorized.
 *
 * Fails closed: with no scope file, or with an empty rule list, nothing but
 * self-testing against the local machine is allowed.
 */
export function checkTarget(
	scope: ScopeConfig | null,
	rawTarget: string,
	options: ScopeCheckOptions = {},
): ScopeDecision {
	let target: ScopeTarget;
	try {
		target = parseTarget(rawTarget);
	} catch (error) {
		return { allowed: false, reason: (error as Error).message };
	}

	if (scope && scope.techniques && scope.techniques.length > 0) {
		const technique = options.technique?.toLowerCase();
		if (technique && !scope.techniques.some((t) => t.toLowerCase() === technique)) {
			return {
				allowed: false,
				reason: `technique "${technique}" is not in the engagement technique allowlist (${scope.techniques.join(", ")})`,
			};
		}
	}

	const selfAllowed = scope?.allowSelfTest ?? true;
	if (selfAllowed && selfTargets().has(target.host.toLowerCase())) {
		return { allowed: true, reason: "self-test target on the local machine", selfTest: true };
	}

	if (!scope) {
		return {
			allowed: false,
			reason:
				"no scope.json found. Create <engagement>/.cyberpi/scope.json and add the authorized targets before running this action.",
		};
	}

	for (const rule of scope.rules) {
		const verdict = ruleAllows(rule, target, options);
		if (verdict.allowed) {
			return { allowed: true, reason: `authorized by rule ${rule.target}`, rule };
		}
	}

	return {
		allowed: false,
		reason:
			`target ${target.host} is not in the authorized scope of engagement "${scope.engagement}". ` +
			`Add it to ${ruleHint(scope)} if the client authorized it.`,
	};
}

/** A short hint pointing at the scope file. */
export function ruleHint(scope: ScopeConfig): string {
	return ".cyberpi/scope.json";
}

/** Human readable summary of a scope, used by the dashboard and prompts. */
export function scopeSummary(scope: ScopeConfig | null): string {
	if (!scope) return "no scope configured";
	const targets = scope.rules.map((rule) => rule.target).join(", ") || "none";
	const techniques = scope.techniques && scope.techniques.length > 0 ? scope.techniques.join(", ") : "all";
	return `${scope.engagement} | targets: ${targets} | techniques: ${techniques}`;
}

/** Technique identifiers understood by the harness. */
export const TECHNIQUES = [
	"recon",
	"port-scan",
	"service-enumeration",
	"web-testing",
	"vulnerability-scan",
	"exploit",
	"password-audit",
	"privilege-escalation",
	"active-directory",
	"pivot",
	"wireless",
	"iot-hardware",
	"cloud-enumeration",
	"forensics",
	"social-engineering",
] as const;

export type Technique = (typeof TECHNIQUES)[number];
