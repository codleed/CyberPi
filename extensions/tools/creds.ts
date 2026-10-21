/**
 * Credential tools: hash identification, hash cracking, password auditing and
 * secret detection.
 *
 * Every tool here drives a local Kali binary (hashcat, hydra, gitleaks,
 * trufflehog). The shared toolkit performs the authorization check, the binary
 * check, the timeout, the artifact capture and the journal entry; this module
 * only describes the command line and how to read the structured output back.
 *
 * Credential material is the point of two of these tools, so it is handled
 * deliberately: the audit reports the logins it recovered, the cracker reports
 * the plaintext it recovered, and the secret scanner never prints a secret at
 * all - only a redacted preview.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { Type } from "@earendil-works/pi-ai";
import type { ToolDefinition } from "@earendil-works/pi-coding-agent";
import type { Static } from "typebox";

import { ensureDir, engagementPaths } from "../lib/config.ts";
import { type RunResult, run, which } from "../lib/exec.ts";
import type { Severity } from "../lib/journal.ts";
import { defineCyberTool, lines } from "../lib/toolkit.ts";

const DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt";
const DEFAULT_POTFILE = "~/.hashcat/hashcat.potfile";
const DEFAULT_RATE = 10;
const DEFAULT_THREADS = 10;
const COMMON_PASSWORD_FILE = "common-passwords.txt";
const MAX_LISTED_FINDINGS = 50;
const MAX_LISTED_HASHES = 20;

/**
 * A deliberately tiny list of the passwords that show up in almost every
 * engagement. It only exists so the audit has something to try when the
 * operator did not supply a wordlist of their own.
 */
const COMMON_PASSWORDS = [
	"password",
	"123456",
	"12345678",
	"1234",
	"qwerty",
	"letmein",
	"welcome",
	"monkey",
	"dragon",
	"iloveyou",
	"abc123",
	"admin",
	"root",
	"guest",
	"changeme",
	"default",
	"passw0rd",
	"shadow",
	"sunshine",
	"trustno1",
];

/* -------------------------------------------------------------------------- */
/* Shared helpers                                                             */
/* -------------------------------------------------------------------------- */

/** Expand a leading `~` to the home directory. */
function expandHome(value: string): string {
	if (value === "~") return os.homedir();
	if (value.startsWith("~/")) return path.join(os.homedir(), value.slice(2));
	return value;
}

/** Create (once) the small common-password list under the engagement notes. */
function ensureCommonPasswordFile(cwd: string): string {
	const paths = engagementPaths(cwd);
	ensureDir(paths.notes);
	const file = path.join(paths.notes, COMMON_PASSWORD_FILE);
	if (!fs.existsSync(file)) {
		fs.writeFileSync(file, `${COMMON_PASSWORDS.join("\n")}\n`, "utf8");
	}
	return file;
}

/** True when a value should be treated as a path to a file of hashes. */
function looksLikeHashFile(value: string): boolean {
	if (/\.(txt|hash|hashes|lst|list)$/i.test(value)) return true;
	const slash = value.lastIndexOf("/");
	if (slash <= 0) return false;
	const dir = value.slice(0, slash);
	return dir.startsWith("/") || dir.startsWith("./") || dir.startsWith("~/") || fs.existsSync(dir);
}

interface HashSource {
	/** File hashcat should read. */
	file: string;
	/** True when the hashes came from the parameter value itself. */
	inline: boolean;
	/** Number of hashes handed to hashcat. */
	count: number;
}

/**
 * Turn the `hashes` parameter into a file hashcat can read. The value is
 * either the path of an existing file or the hash(es) themselves.
 */
function resolveHashSource(value: string, cwd: string, label: string): HashSource {
	const trimmed = value.trim();
	if (trimmed.length === 0) throw new Error("no hashes given");
	if (fs.existsSync(trimmed) && fs.statSync(trimmed).isFile()) {
		const file = path.resolve(cwd, trimmed);
		const count = fs
			.readFileSync(file, "utf8")
			.split(/\s+/)
			.filter((item) => item.length > 0).length;
		return { file, inline: false, count };
	}
	if (looksLikeHashFile(trimmed)) {
		throw new Error(`hash file not found: ${trimmed}`);
	}
	const hashes = trimmed.split(/\s+/).filter((item) => item.length > 0);
	if (hashes.length === 0) throw new Error("no hashes given");
	const paths = engagementPaths(cwd);
	ensureDir(paths.artifacts);
	const file = path.join(paths.artifacts, `${label}-hashes.txt`);
	fs.writeFileSync(file, `${hashes.join("\n")}\n`, "utf8");
	return { file, inline: true, count: hashes.length };
}

/** A single entry of the hashcat "Hash mode list:". */
interface HashMode {
	mode: number;
	name: string;
}

/** Parse the mode table out of `hashcat --help`. */
function parseHashModes(helpText: string): HashMode[] {
	const all = helpText.split("\n");
	const start = all.findIndex((line) => /hash\s+mode\s+list/i.test(line));
	const candidates = start >= 0 ? all.slice(start + 1) : all;
	const modes: HashMode[] = [];
	for (const raw of candidates) {
		const line = raw.replace(/\r$/, "");
		if (line.trim().length === 0) continue;
		const match = /^\s*(\d{1,6})\s*\|\s*(\S.*?)\s*$/.exec(line);
		if (!match) {
			if (modes.length > 0) break;
			continue;
		}
		modes.push({ mode: Number(match[1]), name: match[2] });
	}
	return modes;
}

/** Find the mode number that belongs to a hash type name. */
function matchMode(typeName: string, modes: HashMode[]): { mode?: number; name?: string } {
	const needle = typeName.trim().toLowerCase();
	if (needle.length === 0) return {};
	for (const entry of modes) {
		if (entry.name.toLowerCase() === needle) return { mode: entry.mode, name: entry.name };
	}
	// "MD5 (Unix)" belongs to the mode simply named "MD5".
	for (const entry of modes) {
		if (needle.startsWith(`${entry.name.toLowerCase()} (`)) return { mode: entry.mode, name: entry.name };
	}
	const prefixed = modes.filter((entry) => needle.startsWith(entry.name.toLowerCase()));
	if (prefixed.length === 0) return {};
	// The longest matching name is the most specific one: "NTLMv2" belongs to
	// "NTLM" (mode 1000) and not to "NT" (mode 2).
	let best = prefixed[0];
	for (const entry of prefixed) {
		if (entry.name.length > best.name.length) best = entry;
	}
	return { mode: best.mode, name: best.name };
}

interface IdentifiedHash {
	hash: string;
	type: string;
	mode?: number;
	modeName?: string;
	/** True for the modes hashcat can run with its optimized kernels (m < 1000). */
	fast?: boolean;
}

/** Parse the output of `hashcat --identify`. */
function parseIdentifyOutput(stdout: string, modes: HashMode[]): IdentifiedHash[] {
	const identified: IdentifiedHash[] = [];
	for (const line of lines(stdout)) {
		const index = line.lastIndexOf(":");
		if (index <= 0) continue;
		const type = line.slice(index + 1).trim();
		// A type name always contains a letter; this drops log noise such as
		// "hashcat: hashes supplied: 1".
		if (!/[A-Za-z]/.test(type)) continue;
		const head = line.slice(0, index);
		const separator = head.indexOf(":");
		const hash = (separator >= 0 ? head.slice(separator + 1) : head).trim();
		if (hash.length === 0) continue;
		const matched = matchMode(type, modes);
		identified.push({
			hash,
			type,
			mode: matched.mode,
			modeName: matched.name,
			fast: matched.mode === undefined ? undefined : matched.mode < 1000,
		});
	}
	return identified;
}

/** Build the `modes` filter of cyber_hash_id, if the operator gave one. */
function parseModeFilter(raw: string | undefined): ((entry: IdentifiedHash) => boolean) | undefined {
	if (!raw) return undefined;
	const tokens = raw
		.split(",")
		.map((token) => token.trim().toLowerCase())
		.filter((token) => token.length > 0);
	if (tokens.length === 0) return undefined;
	if (tokens.includes("*") || tokens.includes("all")) return undefined;
	return (entry) => {
		for (const token of tokens) {
			// A number is a mode, never a fragment of a hash type name.
			if (/^\d+$/.test(token)) {
				if (entry.mode === Number(token)) return true;
				continue;
			}
			const name = (entry.modeName ?? entry.type).toLowerCase();
			const type = entry.type.toLowerCase();
			if (name.includes(token) || type.includes(token)) return true;
		}
		return false;
	};
}

/** A short hint of a hash so it can be correlated without echoing it. */
function hashPreview(hash: string): string {
	return hash.length <= 10 ? hash : `${hash.slice(0, 8)}…`;
}

/** Run `hashcat --identify` and `hashcat --help` and pair the results up. */
async function identifyHashes(
	file: string,
	cwd: string,
	artifactDir?: string,
	artifactName?: string,
): Promise<{ identified: IdentifiedHash[]; identify: RunResult }> {
	const [identify, help] = await Promise.all([
		run("hashcat", ["--identify", file], {
			cwd,
			maxBytes: 4_000_000,
			artifactDir,
			artifactName,
		}),
		run("hashcat", ["--help"], { cwd, maxBytes: 8_000_000 }),
	]);
	return { identified: parseIdentifyOutput(identify.stdout, parseHashModes(help.stdout)), identify };
}

/* -------------------------------------------------------------------------- */
/* hashcat output                                                             */
/* -------------------------------------------------------------------------- */

/** Keys hashcat prints in its status block; they are not cracked pairs. */
const HASHCAT_STATUS_KEYS = new Set([
	"Session",
	"Status",
	"Input",
	"Comment",
	"Hash.Type",
	"Hash.Target",
	"Time.Started",
	"Time.Ended",
	"Speed.#1",
	"Speed.#2",
	"Speed.#3",
	"Speed.#4",
	"Recovered",
	"Progress",
	"Recovered.MSalt",
	"Recovered.Session",
	"Candidate.#1",
	"Candidate.#2",
	"Candidate.#3",
	"Candidate.#4",
	"Restore.Point",
	"Restore.Sub",
	"Restore.MTime",
	"Reject",
	"Reject.Detail",
	"Hardware.CPU",
	"Hardware.Memory",
	"Hardware.Clock",
	"Kernel",
	"Format",
	"Attack.Mode",
	"Custom.Rules",
]);

/** Status blocks grow over time; catch the ones that are not in the list. */
const HASHCAT_STATUS_PREFIX = /^(Speed|Candidate|Reject|Restore|Recovered|Time|Hash|Hardware)\./;

interface CrackedPair {
	hash: string;
	plaintext: string;
}

interface CrackOutput {
	cracked: CrackedPair[];
	recovered?: number;
	total?: number;
	speed?: string;
	status?: string;
}

/** Parse the status block and the cracked pairs out of hashcat's output. */
function parseCrackOutput(text: string): CrackOutput {
	const cracked: CrackedPair[] = [];
	let recovered: number | undefined;
	let total: number | undefined;
	let speed: string | undefined;
	let status: string | undefined;
	for (const line of lines(text)) {
		const index = line.indexOf(":");
		if (index <= 0) continue;
		const key = line.slice(0, index).trim();
		const value = line.slice(index + 1).trim();
		if (key === "Recovered") {
			const match = /^(\d+)\/(\d+)/.exec(value);
			if (match) {
				recovered = Number(match[1]);
				total = Number(match[2]);
			}
			continue;
		}
		if (key === "Status") {
			status = value;
			continue;
		}
		if (/^Speed\.#\d+$/.test(key)) {
			speed = value;
			continue;
		}
		if (HASHCAT_STATUS_KEYS.has(key) || HASHCAT_STATUS_PREFIX.test(key)) continue;
		if (key.length < 8 || /\s/.test(key)) continue;
		cracked.push({ hash: key, plaintext: value });
	}
	return { cracked, recovered, total, speed, status };
}

/* -------------------------------------------------------------------------- */
/* hydra output                                                               */
/* -------------------------------------------------------------------------- */

const HYDRA_ATTEMPT = /login:\s*(\S+)\s+password:\s*(\S+)(.*)$/i;

interface HydraAttempt {
	user: string;
	password: string;
	status: "success" | "failure" | "unknown";
}

interface HydraOutput {
	attempts: HydraAttempt[];
	successes: HydraAttempt[];
	validAccounts?: number;
	users?: number;
	passwords?: number;
}

/**
 * Read hydra's output.
 *
 * Not every hydra module tags a successful login the same way, so the number
 * of "valid account(s) found" is used to tell the recovered logins apart from
 * the failed attempts.
 */
function parseHydraOutput(text: string): HydraOutput {
	const attempts: HydraAttempt[] = [];
	for (const line of lines(text)) {
		const match = HYDRA_ATTEMPT.exec(line);
		if (!match) continue;
		const tail = (match[3] ?? "").toLowerCase();
		let status: HydraAttempt["status"] = "unknown";
		if (tail.includes("successful login") || tail.includes("success")) status = "success";
		else if (
			tail.includes("incorrect") ||
			tail.includes("failed") ||
			tail.includes("invalid") ||
			tail.includes("denied") ||
			tail.includes("refused") ||
			tail.includes("closed") ||
			tail.includes("error")
		) {
			status = "failure";
		}
		attempts.push({ user: match[1], password: match[2], status });
	}

	// The counters are read from the summary lines hydra prints at the end of
	// a run, so they have to start the line: other lines mention the same
	// numbers (a wordlist notice, for example).
	let validAccounts: number | undefined;
	for (const match of text.matchAll(/^\s*(?:\[INFO\]\s*)?(\d+)\s+valid accounts?\s+found/gim)) {
		validAccounts = Number(match[1]);
	}
	let users: number | undefined;
	for (const match of text.matchAll(/^\s*(?:\[INFO\]\s*)?(\d+)\s+accounts? found in the specified target/gim)) {
		users = Number(match[1]);
	}
	let passwords: number | undefined;
	for (const match of text.matchAll(/^\s*(?:\[INFO\]\s*)?trying\s+(\d+)\s+passwords?/gim)) {
		passwords = Number(match[1]);
	}

	const successes: HydraAttempt[] = attempts.filter((attempt) => attempt.status === "success");
	if (validAccounts !== undefined && successes.length < validAccounts) {
		// The recovered logins are the ones hydra reported last, so take them
		// from the end of the untagged attempts.
		const untagged = attempts.filter((attempt) => attempt.status === "unknown");
		const missing = Math.min(validAccounts - successes.length, untagged.length);
		for (const attempt of untagged.slice(untagged.length - missing)) successes.push(attempt);
	}
	return { attempts, successes, validAccounts, users, passwords };
}

/* -------------------------------------------------------------------------- */
/* Password audit planning                                                    */
/* -------------------------------------------------------------------------- */

const SERVICE_MODULES = {
	ssh: { module: "ssh", port: 22 },
	ftp: { module: "ftp", port: 21 },
	smtp: { module: "smtp", port: 25 },
	"http-post": { module: "http-post-form", port: 80 },
	"http-get": { module: "http-get", port: 80 },
	"ssh-key": { module: "sshkey", port: 22 },
} as const;

type AuditService = keyof typeof SERVICE_MODULES;

interface AuditTarget {
	host: string;
	port?: number;
	scheme?: string;
	path: string;
}

/** Split a target into host, port, scheme and path. */
function parseAuditTarget(raw: string): AuditTarget {
	let value = raw.trim();
	if (value.length === 0) throw new Error("target is empty");
	let scheme: string | undefined;
	const schemeMatch = /^([a-z][a-z0-9+.-]*):\/\//i.exec(value);
	if (schemeMatch) {
		scheme = schemeMatch[1].toLowerCase();
		value = value.slice(schemeMatch[0].length);
	}
	let targetPath = "";
	const slash = value.indexOf("/");
	if (slash >= 0) {
		targetPath = value.slice(slash);
		value = value.slice(0, slash);
	}
	const at = value.lastIndexOf("@");
	if (at >= 0) value = value.slice(at + 1);
	let port: number | undefined;
	if (value.startsWith("[")) {
		const end = value.indexOf("]");
		if (end === -1) throw new Error(`malformed IPv6 target: ${raw}`);
		const host = value.slice(1, end);
		const rest = value.slice(end + 1);
		if (rest.startsWith(":")) {
			const candidate = Number(rest.slice(1));
			if (Number.isFinite(candidate)) port = candidate;
		}
		return { host: host.toLowerCase(), port, scheme, path: targetPath };
	}
	const colon = value.lastIndexOf(":");
	if (colon > 0 && value.indexOf(":") === colon) {
		const candidate = Number(value.slice(colon + 1));
		if (Number.isInteger(candidate) && candidate > 0 && candidate <= 65535) {
			port = candidate;
			value = value.slice(0, colon);
		}
	}
	return { host: value.toLowerCase(), port, scheme, path: targetPath };
}

/** Split a command-line fragment into arguments, honouring quotes. */
function tokenizeFlags(value: string): string[] {
	const tokens: string[] = [];
	let current = "";
	let quote: string | undefined;
	for (const char of value) {
		if (quote) {
			if (char === quote) quote = undefined;
			else current += char;
			continue;
		}
		if (char === "'" || char === '"') {
			quote = char;
			continue;
		}
		if (/\s/.test(char)) {
			if (current.length > 0) {
				tokens.push(current);
				current = "";
			}
			continue;
		}
		current += char;
	}
	if (current.length > 0) tokens.push(current);
	return tokens;
}

/** Pull an option and its value out of an argument list. */
function takeOption(tokens: string[], option: string): { value?: string; rest: string[] } {
	const index = tokens.indexOf(option);
	if (index < 0) return { rest: tokens };
	const value = tokens[index + 1];
	return { value, rest: [...tokens.slice(0, index), ...tokens.slice(index + 2)] };
}

/**
 * hydra's `-W` is the wait time between two attempts, so a rate in attempts
 * per second becomes the reciprocal number of seconds.
 */
function waitSecondsForRate(rate: number): number {
	return Number((1 / rate).toFixed(4));
}

interface HydraPlan {
	url: string;
	rate: number;
	wait: number;
	threads: number;
}

/** The parts of the hydra plan that only depend on the parameters. */
function describeHydraPlan(params: PasswordAuditParams): HydraPlan {
	const service: AuditService = params.service ?? "ssh";
	const rate = params.rate_limit ?? DEFAULT_RATE;
	const threads = Math.max(1, Math.floor(params.threads ?? DEFAULT_THREADS));
	const target = parseAuditTarget(params.target);
	const serviceModule = SERVICE_MODULES[service];
	const secure = target.scheme === "https";
	const moduleName = secure
		? service === "http-post"
			? "https-post-form"
			: service === "http-get"
				? "https-get"
				: serviceModule.module
		: serviceModule.module;
	const port = target.port ?? (secure ? 443 : serviceModule.port);
	const host = target.host.includes(":") ? `[${target.host}]` : target.host;
	return {
		url: `${moduleName}://${host}:${port}${target.path}`,
		rate,
		wait: waitSecondsForRate(rate),
		threads,
	};
}

/** Work out the hydra command line for a password audit. */
function planHydra(params: PasswordAuditParams, cwd: string): { plan: HydraPlan; args: string[] } {
	if (!params.username && !params.username_file) {
		throw new Error("cyber_password_audit needs a username: pass username or username_file");
	}
	if (params.username_file && !fs.existsSync(params.username_file)) {
		throw new Error(`username file not found: ${params.username_file}`);
	}
	const commonFile = ensureCommonPasswordFile(cwd);
	if (params.password_file && !fs.existsSync(params.password_file)) {
		throw new Error(`password file not found: ${params.password_file}`);
	}
	if (params.rate_limit !== undefined && (!Number.isFinite(params.rate_limit) || params.rate_limit <= 0)) {
		throw new Error("rate_limit must be greater than 0 attempts per second");
	}
	const plan = describeHydraPlan(params);
	const service: AuditService = params.service ?? "ssh";

	let flags = tokenizeFlags(params.service_flag ?? "");
	const args: string[] = [];
	if (params.username) {
		args.push("-l", params.username);
	} else {
		args.push("-L", params.username_file as string);
	}
	if (service === "ssh-key") {
		const taken = takeOption(flags, "-x");
		flags = taken.rest;
		const fallback = path.join(os.homedir(), ".ssh", "id_rsa");
		const key = taken.value ?? (fs.existsSync(fallback) ? fallback : undefined);
		if (!key) {
			throw new Error('the ssh-key service needs a private key: pass service_flag "-x /path/to/id_rsa"');
		}
		if (!fs.existsSync(key)) throw new Error(`ssh key not found: ${key}`);
		args.push("-x", key);
	} else {
		args.push("-P", params.password_file ?? commonFile);
		// An explicit password list is tried in addition to the common list.
		if (params.password_file) args.push("-x", commonFile);
	}
	args.push("-t", String(plan.threads));
	args.push("-W", String(plan.wait));
	if (params.stop_on_success ?? true) args.push("-f");
	if (flags.length > 0) args.push(...flags);
	args.push(plan.url);
	return { plan, args };
}

interface HydraSummary {
	summary: string;
	output: string;
	details: PasswordAuditDetails;
	severity: Severity;
}

/** Turn the output of a hydra run into the report of the audit. */
function summarizeHydra(
	params: PasswordAuditParams,
	plan: HydraPlan,
	result: RunResult | undefined,
): HydraSummary {
	const parsed = parseHydraOutput(fullOutput(result));
	const attempts =
		parsed.attempts.length > 0 ? parsed.attempts.length : (parsed.users ?? 0) * (parsed.passwords ?? 0);
	const body: string[] = [];
	if (parsed.successes.length > 0) {
		body.push("Valid logins:");
		for (const attempt of parsed.successes) body.push(`  ${attempt.user}:${attempt.password}`);
	} else {
		body.push("No valid login was found.");
	}
	body.push("");
	body.push(`Target: ${plan.url}`);
	body.push(`Service: ${params.service ?? "ssh"}`);
	body.push(`Attempts: ${attempts}`);
	body.push(`Rate: ${plan.rate} attempts per second (hydra -W ${plan.wait})`);
	body.push(`Threads: ${plan.threads}`);
	if (parsed.users !== undefined) body.push(`Usernames: ${parsed.users}`);
	if (parsed.passwords !== undefined) body.push(`Passwords: ${parsed.passwords}`);
	if (parsed.validAccounts !== undefined) body.push(`Valid accounts: ${parsed.validAccounts}`);
	if (result?.artifact) body.push(`Full hydra output: ${result.artifact}`);
	if (result && result.code !== 0) {
		const message = (result.stderr || result.stdout).trim().split("\n").slice(-3).join("\n");
		if (message) body.push(`hydra exited with code ${result.code}: ${message}`);
	}
	return {
		summary:
			`password-audit: hydra ${plan.url} - ${attempts} attempt(s) at ${plan.rate}/s, ` +
			`${parsed.successes.length} valid login(s)`,
		output: body.join("\n"),
		details: {
			target: params.target,
			service: params.service ?? "ssh",
			url: plan.url,
			attempts,
			rate: plan.rate,
			threads: plan.threads,
			validLogins: parsed.successes.map((attempt) => ({
				user: attempt.user,
				password: attempt.password,
			})),
			artifact: result?.artifact,
		},
		severity: parsed.successes.length > 0 ? "high" : "info",
	};
}

/* -------------------------------------------------------------------------- */
/* Secret scanning                                                            */
/* -------------------------------------------------------------------------- */

interface SecretFinding {
	source: "gitleaks" | "trufflehog";
	type: string;
	file: string;
	line?: number;
	commit?: string;
	preview: string;
	verified?: boolean;
}

/** Redact a secret down to its first and last two characters. */
function redactPreview(value: string): string {
	const trimmed = value.trim();
	if (trimmed.length === 0) return "";
	if (trimmed.length <= 4) return "*".repeat(trimmed.length);
	const hidden = Math.min(12, trimmed.length - 4);
	return `${trimmed.slice(0, 2)}${"*".repeat(hidden)}${trimmed.slice(-2)}`;
}

interface GitleaksFinding {
	Description?: string;
	RuleID?: string;
	StartLine?: number;
	EndLine?: number;
	File?: string;
	Match?: string;
	Secret?: string;
	Commit?: string;
	Date?: string;
	Tags?: string[];
}

interface TrufflehogFinding {
	SourceMetadata?: {
		Data?: {
			Filesystem?: { file?: string; line?: number };
			Git?: { commit?: string; file?: string; line?: number; repository?: string };
		};
	};
	DetectorName?: string;
	DetectorType?: number;
	DecoderName?: string;
	Verified?: boolean;
	Raw?: string;
	RawV2?: string;
	Redacted?: string;
}

/** Read a JSON document, tolerating trailing noise around it. */
function parseJsonDocument(text: string): unknown {
	const trimmed = text.trim();
	if (trimmed.length === 0) return undefined;
	try {
		return JSON.parse(trimmed);
	} catch {
		const start = trimmed.indexOf("[");
		const end = trimmed.lastIndexOf("]");
		if (start >= 0 && end > start) {
			try {
				return JSON.parse(trimmed.slice(start, end + 1));
			} catch {
				return undefined;
			}
		}
	}
	return undefined;
}

/** Turn a gitleaks JSON report into findings. */
function parseGitleaksReport(text: string): SecretFinding[] {
	const document = parseJsonDocument(text);
	if (!Array.isArray(document)) return [];
	const entries = document as GitleaksFinding[];
	const findings: SecretFinding[] = [];
	for (const entry of entries) {
		if (!entry || typeof entry !== "object") continue;
		findings.push({
			source: "gitleaks",
			type: entry.RuleID ?? entry.Description ?? "secret",
			file: entry.File ?? "unknown",
			line: entry.StartLine,
			commit: entry.Commit,
			preview: redactPreview(entry.Secret ?? entry.Match ?? ""),
			verified: true,
		});
	}
	return findings;
}

/** Turn the JSON lines of trufflehog into findings. */
function parseTrufflehogOutput(stdout: string): SecretFinding[] {
	const findings: SecretFinding[] = [];
	for (const line of lines(stdout)) {
		if (!line.startsWith("{")) continue;
		let entry: TrufflehogFinding;
		try {
			entry = JSON.parse(line) as TrufflehogFinding;
		} catch {
			continue;
		}
		const data = entry.SourceMetadata?.Data;
		findings.push({
			source: "trufflehog",
			type: entry.DetectorName ?? "secret",
			file: data?.Filesystem?.file ?? data?.Git?.file ?? "unknown",
			line: data?.Filesystem?.line ?? data?.Git?.line,
			commit: data?.Git?.commit,
			preview: redactPreview(entry.Raw ?? entry.RawV2 ?? ""),
			verified: entry.Verified,
		});
	}
	return findings;
}

/* -------------------------------------------------------------------------- */
/* Tool parameters                                                            */
/* -------------------------------------------------------------------------- */

const hashIdParams = Type.Object({
	hashes: Type.String({
		description: "A hash, several hashes, or the path of a file containing hashes",
	}),
	modes: Type.Optional(
		Type.String({
			description:
				'Only report these hashcat modes or hash type names, comma separated (for example "0,1000,3200")',
		}),
	),
});

const hashCrackParams = Type.Object({
	hashes: Type.String({
		description: "A hash, several hashes, or the path of a file containing hashes",
	}),
	mode: Type.Optional(Type.Number({ description: "hashcat hash mode (for example 0, 1000, 3200)" })),
	wordlist: Type.Optional(
		Type.String({ description: `Wordlist to crack with (default ${DEFAULT_WORDLIST})` }),
	),
	rules: Type.Optional(Type.String({ description: "hashcat rules file, for example best64.rule" })),
	potfile: Type.Optional(
		Type.String({ description: `Potfile to read and write (default ${DEFAULT_POTFILE})` }),
	),
	session: Type.Optional(Type.String({ description: "hashcat session name, to resume a run later" })),
	time_limit: Type.Optional(
		Type.Number({ description: "Stop after this many seconds (hashcat --runtime)" }),
	),
});

const passwordAuditParams = Type.Object({
	target: Type.String({
		description: "Authorized target as host, host:port or URL (for example 10.0.0.5:22)",
	}),
	service: Type.Optional(
		Type.Union(
			[
				Type.Literal("ssh"),
				Type.Literal("ftp"),
				Type.Literal("smtp"),
				Type.Literal("http-post"),
				Type.Literal("http-get"),
				Type.Literal("ssh-key"),
			],
			{ description: "Service module to audit (default ssh)" },
		),
	),
	username: Type.Optional(Type.String({ description: "Single username to try" })),
	username_file: Type.Optional(Type.String({ description: "File with one username per line" })),
	password_file: Type.Optional(Type.String({ description: "File with one password per line" })),
	threads: Type.Optional(Type.Number({ description: "Parallel connections (default 10)" })),
	rate_limit: Type.Optional(
		Type.Number({ description: "Attempts per second, must be greater than 0 (default 10)" }),
	),
	stop_on_success: Type.Optional(
		Type.Boolean({ description: "Stop at the first successful login (default true)" }),
	),
	service_flag: Type.Optional(
		Type.String({
			description:
				'Extra hydra module option, for example "-m path=/login,user=^USER^,pass=^PASS^" or "-x /root/.ssh/id_rsa"',
		}),
	),
});

const secretScanParams = Type.Object({
	path: Type.String({ description: "Directory or file to scan for secrets" }),
	tools: Type.Optional(
		Type.Union([Type.Literal("gitleaks"), Type.Literal("trufflehog"), Type.Literal("both")], {
			description: "Which scanner to run (default both)",
		}),
	),
	since_commit: Type.Optional(
		Type.String({ description: "Only report secrets introduced at or after this commit" }),
	),
	include_history: Type.Optional(
		Type.Boolean({ description: "Scan the git history instead of only the working tree" }),
	),
});

type PasswordAuditParams = Static<typeof passwordAuditParams>;

/* -------------------------------------------------------------------------- */
/* Tool results                                                               */
/* -------------------------------------------------------------------------- */

interface HashIdDetails {
	identified: number;
	hashes: Array<{
		hash: string;
		type: string;
		mode?: number;
		modeName?: string;
		fast?: boolean;
	}>;
	filter?: string;
}

interface HashCrackDetails {
	mode?: number;
	modeName?: string;
	cracked: CrackedPair[];
	recovered?: number;
	total?: number;
	speed?: string;
	status?: string;
	potfile: string;
	wordlist: string;
	artifact?: string;
}

interface PasswordAuditDetails {
	target: string;
	service: string;
	url: string;
	attempts: number;
	rate: number;
	threads: number;
	validLogins: Array<{ user: string; password: string }>;
	artifact?: string;
}

interface SecretScanDetails {
	tools: string[];
	findings: SecretFinding[];
	artifacts: string[];
}

/** Read the full output of a run, preferring the artifact over the truncated copy. */
function fullOutput(result: RunResult | undefined): string {
	if (!result) return "";
	if (result.artifact) {
		try {
			return fs.readFileSync(result.artifact, "utf8");
		} catch {
			// Fall through to the in-memory copy.
		}
	}
	return `${result.stdout}\n${result.stderr}`;
}

/* -------------------------------------------------------------------------- */
/* Tools                                                                      */
/* -------------------------------------------------------------------------- */

export const credsTools: ToolDefinition[] = [
	defineCyberTool<typeof hashIdParams, HashIdDetails>({
		name: "cyber_hash_id",
		label: "Identify hash",
		description:
			"Identify the algorithm behind a captured hash with hashcat --identify. Accepts a single hash, several " +
			"hashes or a file of hashes. Reports the hash type, whether it is a fast hash and the hashcat mode " +
			"number needed to crack it.",
		promptSnippet: "cyber_hash_id: identify the algorithm behind a captured hash",
		technique: "password-audit",
		requires: ["hashcat"],
		parameters: hashIdParams,
		execute: async (params, ctx) => {
			const cwd = ctx.cwd;
			const source = resolveHashSource(params.hashes, cwd, "hash-id");
			const artifacts = ensureDir(engagementPaths(cwd).artifacts);
			const { identified, identify } = await identifyHashes(source.file, cwd, artifacts, "hash-id.txt");
			if (identify.code !== 0 && identified.length === 0) {
				return {
					summary: `hashcat --identify failed on ${source.file}`,
					output: identify.stderr.trim() || identify.stdout.trim() || "hashcat produced no output",
					details: { identified: 0, hashes: [] },
					isError: true,
				};
			}
			const filter = parseModeFilter(params.modes);
			const selected = filter ? identified.filter(filter) : identified;
			const body: string[] = [];
			for (const entry of selected.slice(0, MAX_LISTED_HASHES)) {
				const mode = entry.mode === undefined ? "unknown mode" : `mode ${entry.mode}`;
				const fast = entry.fast === undefined ? "" : entry.fast ? " (fast hash)" : " (slow hash)";
				const name = entry.modeName && entry.modeName !== entry.type ? ` [${entry.modeName}]` : "";
				body.push(`  ${hashPreview(entry.hash)}  ${entry.type}${name} - ${mode}${fast}`);
			}
			if (selected.length > MAX_LISTED_HASHES) {
				body.push(`  ... and ${selected.length - MAX_LISTED_HASHES} more hash(es)`);
			}
			const unidentified = identified.filter((entry) => entry.mode === undefined).length;
			const notes: string[] = [];
			if (unidentified > 0) notes.push(`${unidentified} hash(es) could not be matched to a hashcat mode`);
			if (filter && selected.length === 0 && identified.length > 0) {
				notes.push(
					`the mode filter "${params.modes}" matched none of the ${identified.length} identified hashes`,
				);
			}
			if (notes.length > 0) body.push(notes.join("\n"));
			return {
				summary:
					`hash-id: hashcat --identify ${source.file} - ` +
					`${selected.length} of ${identified.length} hash(es) identified`,
				output: body.length > 0 ? body.join("\n") : "no hashes were identified",
				details: {
					identified: selected.length,
					hashes: selected.map((entry) => ({
						hash: entry.hash,
						type: entry.type,
						mode: entry.mode,
						modeName: entry.modeName,
						fast: entry.fast,
					})),
					filter: params.modes,
				} satisfies HashIdDetails,
			};
		},
	}),

	defineCyberTool<typeof hashCrackParams, HashCrackDetails>({
		name: "cyber_hash_crack",
		label: "Crack hash",
		description:
			"Crack a captured hash with hashcat. When no mode is given the hash type is identified first. " +
			"Reports the recovered plaintext, the number of cracked hashes, the cracking speed and the potfile " +
			"path. The run can be bounded with time_limit, which is passed to hashcat as --runtime.",
		promptSnippet: "cyber_hash_crack: crack a captured hash with hashcat",
		promptGuidelines: [
			"cyber_hash_crack is CPU heavy and can run for hours: always set time_limit, use a targeted wordlist instead of rockyou, and keep the recovered plaintext out of any document that leaves the engagement.",
			"cyber_hash_crack and cyber_password_audit are loud actions: they produce real login attempts and fill the potfile. Only run them against material the client explicitly authorized in .cyberpi/scope.json.",
		],
		annotations: { destructiveHint: false },
		technique: "password-audit",
		requires: ["hashcat"],
		parameters: hashCrackParams,
		execute: async (params, ctx) => {
			const cwd = ctx.cwd;
			const source = resolveHashSource(params.hashes, cwd, "hash-crack");
			const wordlist = params.wordlist ?? DEFAULT_WORDLIST;
			if (!fs.existsSync(wordlist)) {
				return {
					summary: `wordlist not found: ${wordlist}`,
					output:
						`The wordlist ${wordlist} does not exist. Install the Kali wordlists package ` +
						"(sudo apt install -y wordlists) or pass an explicit wordlist path.",
					details: { cracked: [], potfile: "", wordlist },
					isError: true,
				};
			}
			const potfile = expandHome(params.potfile ?? DEFAULT_POTFILE);
			ensureDir(path.dirname(potfile));
			const rules = params.rules;
			if (rules && !fs.existsSync(rules)) {
				return {
					summary: `rules file not found: ${rules}`,
					details: { cracked: [], potfile, wordlist },
					isError: true,
				};
			}
			if (
				params.time_limit !== undefined &&
				(!Number.isFinite(params.time_limit) || params.time_limit <= 0)
			) {
				return {
					summary: "time_limit must be greater than 0 seconds",
					details: { cracked: [], potfile, wordlist },
					isError: true,
				};
			}

			let mode = params.mode;
			let modeName: string | undefined;
			let modeTypes: string[] = [];
			if (mode === undefined) {
				const inference = await identifyHashes(source.file, cwd);
				const unique = new Map<number, { mode: number; name: string; type: string }>();
				for (const entry of inference.identified) {
					if (entry.mode === undefined) continue;
					if (!unique.has(entry.mode)) {
						unique.set(entry.mode, {
							mode: entry.mode,
							name: entry.modeName ?? entry.type,
							type: entry.type,
						});
					}
				}
				const candidates = [...unique.values()];
				if (candidates.length === 0) {
					return {
						summary: `could not identify the hash type of ${source.file}`,
						output:
							"hashcat --identify did not recognise the hash. Pass the hashcat mode explicitly " +
							"(for example mode 0, 1000 or 3200) or run cyber_hash_id for details.",
						details: { cracked: [], potfile, wordlist },
						isError: true,
					};
				}
				if (candidates.length > 1) {
					return {
						summary: `ambiguous hash type in ${source.file}`,
						output:
							`hashcat --identify reported ${candidates.length} different hash types ` +
							`(${candidates.map((item) => `${item.type} (mode ${item.mode})`).join(", ")}). ` +
							"Pass the mode explicitly to choose one.",
						details: { cracked: [], potfile, wordlist },
						isError: true,
					};
				}
				mode = candidates[0].mode;
				modeName = candidates[0].name;
				modeTypes = [candidates[0].type];
			}

			const args = ["-m", String(mode)];
			// The optimized kernels only exist for the fast hash modes.
			if (mode < 1000) args.push("-O");
			if (params.time_limit !== undefined) {
				args.push("--runtime", String(Math.max(1, Math.floor(params.time_limit))));
			}
			if (rules) args.push("-r", rules);
			if (params.session) args.push("--session", params.session);
			args.push("--potfile-path", potfile);
			args.push(source.file, wordlist);

			const artifacts = ensureDir(engagementPaths(cwd).artifacts);
			const result = await run("hashcat", args, {
				cwd,
				maxBytes: 8_000_000,
				timeoutMs: 3_600_000,
				artifactDir: artifacts,
				artifactName: "hash-crack.txt",
			});
			const parsed = parseCrackOutput(fullOutput(result));
			const cracked = parsed.cracked;
			const recovered = parsed.recovered ?? cracked.length;

			const body: string[] = [];
			if (cracked.length > 0) {
				body.push("Recovered plaintext:");
				for (const pair of cracked) body.push(`  ${pair.plaintext}`);
			} else {
				body.push("No plaintext was recovered in this run.");
			}
			body.push("");
			body.push(`Mode: ${mode}${modeName ? ` (${modeName})` : ""}`);
			body.push(`Cracked: ${recovered}${parsed.total ? `/${parsed.total}` : ""}`);
			if (parsed.speed) body.push(`Speed: ${parsed.speed}`);
			if (parsed.status) body.push(`Status: ${parsed.status}`);
			if (modeTypes.length > 0) body.push(`Hash type: ${modeTypes.join(", ")}`);
			body.push(`Potfile: ${potfile}`);
			body.push(`Wordlist: ${wordlist}`);
			if (result.timedOut) body.push("The run hit the command timeout and was stopped.");
			if (result.artifact) body.push(`Full hashcat output: ${result.artifact}`);

			return {
				summary:
					`hash-crack: hashcat -m ${mode} ${source.file} ${wordlist} - ` +
					`${recovered} cracked${parsed.speed ? ` at ${parsed.speed}` : ""}`,
				output: body.join("\n"),
				details: {
					mode,
					modeName,
					cracked,
					recovered,
					total: parsed.total,
					speed: parsed.speed,
					status: parsed.status,
					potfile,
					wordlist,
					artifact: result.artifact,
				} satisfies HashCrackDetails,
			};
		},
	}),

	defineCyberTool<typeof passwordAuditParams, PasswordAuditDetails>({
		name: "cyber_password_audit",
		label: "Password audit",
		description:
			"Audit a password on an authorized service with hydra. Runs the matching hydra service module against " +
			"the username and password lists and reports every login it recovered. The rate is given in attempts " +
			"per second and is passed to hydra as the wait time between attempts.",
		promptSnippet: "cyber_password_audit: audit passwords on an authorized service with hydra",
		promptGuidelines: [
			"cyber_password_audit is loud: every attempt reaches the target and can trip lockouts, alerts or rate limiters. Keep it strictly inside the authorized scope, start with a low rate, and prefer stop_on_success on production systems.",
		],
		annotations: { destructiveHint: false },
		technique: "password-audit",
		requires: ["hydra"],
		parameters: passwordAuditParams,
		build: (params, ctx) => {
			const { args } = planHydra(params, ctx.cwd);
			return {
				bin: "hydra",
				args,
				label: "password-audit",
				target: params.target,
			};
		},
		summarize: (results, params) => {
			const summary = summarizeHydra(params, describeHydraPlan(params), results[0]);
			return {
				summary: summary.summary,
				output: summary.output,
				details: summary.details,
				severity: summary.severity,
			};
		},
	}),

	defineCyberTool<typeof secretScanParams, SecretScanDetails>({
		name: "cyber_secret_scan",
		label: "Secret scan",
		description:
			"Look for leaked credentials in a codebase or directory with gitleaks and trufflehog. Reports every " +
			"secret by type, file and line, with the commit when the secret comes from the git history. The secret " +
			"itself is never printed, only a redacted preview.",
		promptSnippet: "cyber_secret_scan: find leaked secrets in a codebase with gitleaks and trufflehog",
		technique: "password-audit",
		requires: ["trufflehog"],
		parameters: secretScanParams,
		execute: async (params, ctx) => {
			const cwd = ctx.cwd;
			const scanPath = path.resolve(cwd, params.path);
			if (!fs.existsSync(scanPath)) {
				return {
					summary: `path not found: ${params.path}`,
					details: { tools: [], findings: [], artifacts: [] },
					isError: true,
				};
			}
			const selected = params.tools ?? "both";
			const includeHistory = params.include_history ?? false;
			const stat = fs.statSync(scanPath);
			const repoRoot = stat.isDirectory() ? scanPath : path.dirname(scanPath);
			const isRepository = fs.existsSync(path.join(repoRoot, ".git"));
			const artifacts = ensureDir(engagementPaths(cwd).artifacts);
			const findings: SecretFinding[] = [];
			const notes: string[] = [];
			const used: string[] = [];
			const written: string[] = [];

			if (selected !== "trufflehog") {
				if (which("gitleaks") === null) {
					if (selected === "gitleaks") {
						return {
							summary: "gitleaks is not installed",
							output: "Install it on Kali with: sudo apt install -y gitleaks",
							details: { tools: [], findings: [], artifacts: [] },
							isError: true,
						};
					}
					notes.push("gitleaks is not installed (sudo apt install -y gitleaks); only trufflehog was run");
				} else {
					const reportPath = path.join(artifacts, "secret-scan-gitleaks.json");
					const args = [
						"detect",
						"--source",
						scanPath,
						"--report-format",
						"json",
						"--report-path",
						reportPath,
						"--no-banner",
					];
					if (!includeHistory || !isRepository) {
						args.push("--no-git");
						if (includeHistory) {
							notes.push("the path is not a git repository; gitleaks scanned the working tree only");
						}
					} else if (params.since_commit) {
						args.push(`--log-opts=--all ${params.since_commit}..HEAD`);
					}
					const result = await run("gitleaks", args, {
						cwd,
						maxBytes: 16_000_000,
						timeoutMs: 900_000,
						artifactDir: artifacts,
						artifactName: "secret-scan-gitleaks.txt",
					});
					used.push("gitleaks");
					if (result.artifact) written.push(result.artifact);
					const report = fs.existsSync(reportPath) ? fs.readFileSync(reportPath, "utf8") : result.stdout;
					const gitleaksFindings = parseGitleaksReport(report);
					findings.push(...gitleaksFindings);
					if (result.code !== 0 && gitleaksFindings.length === 0) {
						const message = result.stderr.trim().split("\n").slice(-3).join("\n");
						notes.push(`gitleaks exited with code ${result.code}${message ? `: ${message}` : ""}`);
					}
				}
			}

			if (selected !== "gitleaks") {
				const mode = includeHistory && isRepository ? "git" : "filesystem";
				if (includeHistory && !isRepository) {
					notes.push("the path is not a git repository; trufflehog scanned the working tree only");
				}
				const args =
					mode === "git" ? ["git", `file://${scanPath}`, "--json"] : ["filesystem", scanPath, "--json"];
				if (mode === "git" && params.since_commit) {
					args.push("--since-commit", params.since_commit);
				}
				const result = await run("trufflehog", args, {
					cwd,
					maxBytes: 16_000_000,
					timeoutMs: 900_000,
					artifactDir: artifacts,
					artifactName: "secret-scan-trufflehog.txt",
				});
				used.push("trufflehog");
				if (result.artifact) written.push(result.artifact);
				const trufflehogFindings = parseTrufflehogOutput(result.stdout);
				findings.push(...trufflehogFindings);
				if (result.code !== 0 && trufflehogFindings.length === 0) {
					const message = result.stderr.trim().split("\n").slice(-3).join("\n");
					notes.push(`trufflehog exited with code ${result.code}${message ? `: ${message}` : ""}`);
				}
			}

			const body: string[] = [];
			const render = (title: string, group: SecretFinding[]) => {
				if (group.length === 0) return;
				body.push(`${title} (${group.length}):`);
				for (const finding of group.slice(0, MAX_LISTED_FINDINGS)) {
					const where = finding.line ? `${finding.file}:${finding.line}` : finding.file;
					const commit = finding.commit ? `  commit ${finding.commit.slice(0, 12)}` : "";
					body.push(`  ${finding.type}  ${where}  ${finding.preview}${commit}`);
				}
				if (group.length > MAX_LISTED_FINDINGS) {
					body.push(`  ... and ${group.length - MAX_LISTED_FINDINGS} more`);
				}
				body.push("");
			};
			render("gitleaks", findings.filter((finding) => finding.source === "gitleaks"));
			render("trufflehog", findings.filter((finding) => finding.source === "trufflehog"));
			if (findings.length === 0) body.push("No secrets were reported.");
			if (notes.length > 0) body.push(notes.join("\n"));
			if (written.length > 0) body.push(`Full scanner output: ${written.join(", ")}`);

			return {
				summary:
					`secret-scan: ${used.join(" + ") || "no scanner"} on ${params.path} - ` +
					`${findings.length} secret(s) reported`,
				output: body.join("\n"),
				details: { tools: used, findings, artifacts: written } satisfies SecretScanDetails,
			};
		},
	}),
];
