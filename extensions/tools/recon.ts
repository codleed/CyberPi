/**
 * Reconnaissance tools: passive subdomain enumeration, DNS lookups and WHOIS.
 *
 * All three are read-only with respect to the target, but they are network
 * actions, so they declare the `recon` technique and are checked against the
 * engagement scope by the shared toolkit before anything is spawned.
 */

import path from "node:path";
import { Type } from "@earendil-works/pi-ai";
import type { ToolDefinition } from "@earendil-works/pi-coding-agent";
import type { Static } from "typebox";
import type { RunResult } from "../lib/exec.ts";
import { writeArtifact } from "../lib/journal.ts";
import { addHosts } from "../lib/surface.ts";
import { defineCyberTool, lines, parseJsonLines } from "../lib/toolkit.ts";

/** Passive enumeration is slow and asked for repeatedly, so it is cached. */
const SUBDOMAIN_CACHE_TTL_MS = 30 * 60 * 1000;
/** Budget handed to subfinder itself, in minutes. */
const SUBDOMAIN_TIMEOUT_MINUTES = 8;
/** Hard limit of the tool call, in milliseconds. */
const SUBDOMAIN_TIMEOUT_MS = 10 * 60 * 1000;
/** Host names printed into the transcript before the artifact takes over. */
const MAX_HOSTS_IN_TRANSCRIPT = 50;

/** DNS record types the harness knows how to ask for. */
const DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"] as const;

/** A resolver must be an IP address or a plain hostname. */
const RESOLVER_PATTERN = /^[A-Za-z0-9._:-]+$/;

/** A single JSON line produced by subfinder. */
interface SubfinderEntry {
	host?: string;
	input?: string;
	source?: string;
}

interface SubdomainDetails {
	domain: string;
	hosts: string[];
	count: number;
	sources: string[];
	artifact?: string;
}

interface DnsDetails {
	domain: string;
	recordTypes: string[];
	resolver?: string;
	records: Record<string, string[]>;
}

interface WhoisDetails {
	domain: string;
	registrar?: string;
	created?: string;
	updated?: string;
	expires?: string;
	registrantOrganization?: string;
	registrantCountry?: string;
	registrantState?: string;
	asn?: string;
	asnOrganization?: string;
	nameServers: string[];
	artifact?: string;
}

/** The registration facts a whois record can yield. */
interface WhoisInfo {
	registrar?: string;
	created?: string;
	updated?: string;
	expires?: string;
	registrantOrganization?: string;
	registrantCountry?: string;
	registrantState?: string;
	asn?: string;
	asnOrganization?: string;
	nameServers: string[];
}

/** Normalize a domain so it can be used as an argument and a file name stem. */
function normalizeDomain(value: string): string {
	let domain = value.trim().toLowerCase();
	domain = domain.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
	domain = domain.split(/[/?#]/)[0];
	domain = domain.replace(/\.$/, "");
	return domain;
}

/** Make a string safe to use as a file name. */
function safeFileName(value: string): string {
	const cleaned = value.replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^[._]+|[._]+$/g, "");
	return cleaned.length > 0 ? cleaned : "target";
}

/** The first non-empty line of a block of text. */
function firstLine(text: string): string {
	for (const line of lines(text)) return line;
	return "";
}

/**
 * Recover the engagement root from the artifact the runner wrote.
 *
 * The summarize step of the toolkit does not receive the tool context, so the
 * root cannot be taken from `ctx.cwd`. The runner stores command output in
 * `<engagement>/.cyberpi/artifacts/<label>.txt`, which carries the root.
 */
function engagementRootFrom(results: RunResult[]): string {
	for (const result of results) {
		if (!result.artifact) continue;
		return path.dirname(path.dirname(path.dirname(result.artifact)));
	}
	return process.cwd();
}

/** True when a value looks like an IPv4 or IPv6 address. */
function isIpAddress(value: string): boolean {
	if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return true;
	return value.includes(":") && /^[0-9a-f:]+$/i.test(value);
}

/** Extract the host names and the source names from subfinder output. */
function parseSubfinder(stdout: string): { hosts: string[]; sources: string[] } {
	const hosts: string[] = [];
	const sources = new Set<string>();
	for (const entry of parseJsonLines<SubfinderEntry>(stdout)) {
		const host = typeof entry.host === "string" ? entry.host.trim().toLowerCase() : "";
		if (host.length === 0) continue;
		if (!hosts.includes(host)) hosts.push(host);
		const source = typeof entry.source === "string" ? entry.source.trim() : "";
		if (source.length > 0) sources.add(source);
	}
	if (hosts.length === 0) {
		// Older subfinder builds print bare host names even with -json.
		for (const line of lines(stdout)) {
			if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9-]+)+$/i.test(line)) continue;
			const host = line.toLowerCase();
			if (!hosts.includes(host)) hosts.push(host);
		}
	}
	return { hosts, sources: [...sources].sort() };
}

/** Reduce an ISO timestamp to its date part. */
function formatDate(value: string | undefined): string | undefined {
	if (!value) return undefined;
	const iso = /^(\d{4}-\d{2}-\d{2})/.exec(value);
	return iso ? iso[1] : value;
}

/** Read a `key: value` field out of whois output. */
function whoisField(text: string, aliases: string[]): string | undefined {
	for (const line of lines(text)) {
		const index = line.indexOf(":");
		if (index <= 0) continue;
		const key = line.slice(0, index).trim().toLowerCase();
		if (!aliases.includes(key)) continue;
		const value = line.slice(index + 1).trim();
		if (value.length > 0) return value;
	}
	return undefined;
}

/** Collect the name servers, in both the ARIN and the RIPE layout. */
function whoisNameServers(text: string): string[] {
	const keys = new Set(["name server", "name servers", "nameserver", "nserver", "ns"]);
	const raw = text
		.split("\n")
		.map((line) => line.replace(/\r$/, ""))
		.filter((line) => line.trim().length > 0);
	const servers: string[] = [];
	const push = (token: string): void => {
		const host = token.trim().toLowerCase().replace(/\.$/, "");
		if (host.length === 0 || isIpAddress(host)) return;
		if (!servers.includes(host)) servers.push(host);
	};
	for (let index = 0; index < raw.length; index++) {
		const line = raw[index];
		const separator = line.indexOf(":");
		if (separator <= 0) continue;
		const key = line.slice(0, separator).trim().toLowerCase();
		if (!keys.has(key)) continue;
		const value = line.slice(separator + 1).trim();
		if (value.length > 0) {
			for (const token of value.split(/\s+/)) push(token);
			continue;
		}
		// "Name servers:" followed by an indented block of host names.
		for (let next = index + 1; next < raw.length; next++) {
			const candidate = raw[next];
			if (!/^\s/.test(candidate)) break;
			const token = candidate.trim().split(/\s+/)[0];
			if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i.test(token)) break;
			push(token);
		}
	}
	return servers;
}

/** Split an AS number out of a value such as "AS15169 Google LLC". */
function splitAsn(value: string | undefined): { asn?: string; organization?: string } {
	if (!value) return {};
	const match = /^(AS\d+)\s*(.*)$/i.exec(value.trim());
	if (!match) return { asn: value.trim() };
	return { asn: match[1].toUpperCase(), organization: match[2].trim() || undefined };
}

/** Parse a whois record into the facts the harness reports. */
function parseWhois(text: string): WhoisInfo | undefined {
	const noMatch = /no match for|no entries found|no data found|no object found|not found/i.test(text);
	const info: WhoisInfo = {
		registrar: whoisField(text, ["registrar"]),
		created: whoisField(text, [
			"creation date",
			"created",
			"created on",
			"domain registration date",
			"registered",
			"registration time",
		]),
		updated: whoisField(text, ["updated date", "last updated", "last modified", "last-modified", "changed"]),
		expires: whoisField(text, [
			"registry expiry date",
			"registrar registration expiration date",
			"expiration date",
			"expiry date",
			"expire",
			"expires",
			"paid-till",
			"renewal date",
		]),
		registrantOrganization:
			whoisField(text, [
				"registrant organization",
				"registrant org",
				"org",
				"org-name",
				"organization",
				"organisation",
			]) ?? whoisField(text, ["descr", "description"]),
		registrantCountry: whoisField(text, ["registrant country", "country"]),
		registrantState: whoisField(text, ["registrant state/province", "registrant state", "state"]),
		nameServers: whoisNameServers(text),
	};
	const asn = splitAsn(whoisField(text, ["origin", "aut-num", "asn", "as"]));
	info.asn = asn.asn;
	info.asnOrganization = asn.organization;
	if (isEmptyWhois(info)) {
		// Nothing recognizable was extracted: either there is no record, or the
		// registry uses a layout the parser does not know.
		if (noMatch || lines(text).length <= 2) return undefined;
	}
	return info;
}

/** True when no registration fact could be extracted from a whois record. */
function isEmptyWhois(info: WhoisInfo): boolean {
	return (
		!info.registrar &&
		!info.created &&
		!info.updated &&
		!info.expires &&
		!info.registrantOrganization &&
		!info.asn &&
		info.nameServers.length === 0
	);
}

/** Render the whois facts as a few readable lines. */
function formatWhois(domain: string, info: WhoisInfo, artifact?: string): string {
	const rows: string[] = [];
	const row = (label: string, value: string | undefined): void => {
		if (value && value.length > 0) rows.push(`  ${label.padEnd(13)}${value}`);
	};
	row("registrar:", info.registrar);
	row("created:", formatDate(info.created));
	row("updated:", formatDate(info.updated));
	row("expires:", formatDate(info.expires));
	const registrant = info.registrantOrganization
		? `${info.registrantOrganization}${info.registrantCountry ? ` (${info.registrantCountry})` : ""}`
		: info.registrantCountry;
	row("registrant:", registrant);
	row("asn:", info.asn ? `${info.asn}${info.asnOrganization ? ` ${info.asnOrganization}` : ""}` : undefined);
	row("nameservers:", info.nameServers.length > 0 ? info.nameServers.join(", ") : undefined);
	const rendered = [domain, ...rows];
	if (artifact) rendered.push("", `raw whois output: ${artifact}`);
	return rendered.join("\n");
}

const subdomainParameters = Type.Object({
	domain: Type.String({ description: "Root domain to enumerate, e.g. example.com" }),
	domain_list: Type.Optional(
		Type.String({ description: "Path to a file with one domain per line, handed to subfinder as -dL" }),
	),
	all_sources: Type.Optional(Type.Boolean({ description: "Query every configured source (subfinder -all)" })),
	sources: Type.Optional(
		Type.String({ description: "Comma separated list of sources to query, e.g. crtsh,shodan (overrides all_sources)" }),
	),
	limit: Type.Optional(Type.Number({ description: "Maximum number of host names to keep", minimum: 1 })),
});

const dnsRecordTypeSchema = Type.Union(
	[
		Type.Literal("A"),
		Type.Literal("AAAA"),
		Type.Literal("MX"),
		Type.Literal("NS"),
		Type.Literal("TXT"),
		Type.Literal("CNAME"),
		Type.Literal("SOA"),
		Type.Literal("ALL"),
	],
	{ description: "Record type to look up, or ALL to query every supported type in parallel" },
);

type DnsRecordType = Static<typeof dnsRecordTypeSchema>;

const dnsParameters = Type.Object({
	domain: Type.String({ description: "Domain to query, e.g. example.com" }),
	record_type: Type.Optional(dnsRecordTypeSchema),
	resolver: Type.Optional(Type.String({ description: "Resolver to query, e.g. 1.1.1.1 or dns.google" })),
});

const whoisParameters = Type.Object({
	domain: Type.String({ description: "Domain to look up, e.g. example.com" }),
});

/** The record types a call actually queries. */
function resolveRecordTypes(requested: DnsRecordType | undefined): DnsRecordType[] {
	if (requested === "ALL") return [...DNS_RECORD_TYPES];
	return [requested ?? "A"];
}

export const reconTools: ToolDefinition[] = [
	defineCyberTool<typeof subdomainParameters, SubdomainDetails>({
		name: "cyber_subdomain",
		label: "Subdomain enumeration",
		description:
			"Passive subdomain enumeration for an authorized domain using subfinder. " +
			"Discovers host names from public sources, records them in the engagement surface index " +
			"and writes the complete host list to an artifact.",
		promptSnippet: "cyber_subdomain: passive subdomain enumeration with subfinder",
		technique: "recon",
		requires: ["subfinder"],
		installHint:
			"Install subfinder with: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
		action: "recon",
		parameters: subdomainParameters,
		target: (params) => params.domain,
		cacheTtlMs: SUBDOMAIN_CACHE_TTL_MS,
		timeoutMs: SUBDOMAIN_TIMEOUT_MS,
		build: (params) => {
			const domain = normalizeDomain(params.domain);
			if (domain.length === 0) throw new Error("a domain is required");
			const args = ["-json", "-silent", "-d", domain];
			if (params.domain_list) args.push("-dL", params.domain_list);
			if (params.sources) args.push("-s", params.sources);
			else if (params.all_sources) args.push("-all");
			args.push("-timeout", String(SUBDOMAIN_TIMEOUT_MINUTES));
			return { bin: "subfinder", args, label: `subfinder-${safeFileName(domain)}`, target: domain };
		},
		summarize: (results, params) => {
			const domain = normalizeDomain(params.domain);
			const result = results[0];
			if (!result) {
				return {
					summary: `subfinder produced no result for ${domain}`,
					details: { domain, hosts: [], count: 0, sources: [] },
					isError: true,
					severity: "medium",
				};
			}
			if (result.timedOut) {
				return {
					summary: `subfinder timed out after ${SUBDOMAIN_TIMEOUT_MS / 1000}s for ${domain}`,
					details: { domain, hosts: [], count: 0, sources: [] },
					isError: true,
					severity: "medium",
				};
			}
			const parsed = parseSubfinder(result.stdout);
			if (result.code !== 0 && parsed.hosts.length === 0) {
				return {
					summary: `subfinder failed for ${domain}: ${firstLine(result.stderr) || `exit code ${result.code}`}`,
					details: { domain, hosts: [], count: 0, sources: [] },
					isError: true,
					severity: "medium",
				};
			}
			const limit = params.limit && params.limit > 0 ? Math.floor(params.limit) : undefined;
			const hosts = limit ? parsed.hosts.slice(0, limit) : parsed.hosts;
			const root = engagementRootFrom(results);
			const artifact = writeArtifact(
				root,
				`subdomains-${safeFileName(domain)}.txt`,
				hosts.length > 0 ? `${hosts.join("\n")}\n` : "",
			);
			if (hosts.length > 0) {
				addHosts(
					root,
					hosts.map((host) => ({ host, source: "subfinder" })),
				);
			}
			const shown = hosts.slice(0, MAX_HOSTS_IN_TRANSCRIPT);
			const output = [
				shown.join("\n"),
				hosts.length > shown.length
					? `... and ${hosts.length - shown.length} more, see the artifact below`
					: "",
				`Full host list: ${artifact}`,
			]
				.filter((part) => part.length > 0)
				.join("\n");
			const sources = parsed.sources.length > 0 ? ` (sources: ${parsed.sources.join(", ")})` : "";
			return {
				summary:
					hosts.length === 0
						? `No subdomains found for ${domain}`
						: `Found ${hosts.length} subdomain${hosts.length === 1 ? "" : "s"} for ${domain}${sources}`,
				output,
				details: { domain, hosts, count: hosts.length, sources: parsed.sources, artifact },
				severity: "info",
			};
		},
	}),

	defineCyberTool<typeof dnsParameters, DnsDetails>({
		name: "cyber_dns",
		label: "DNS records",
		description:
			"Look up DNS records for an authorized domain with dig. " +
			"Supports A, AAAA, MX, NS, TXT, CNAME and SOA records, a custom resolver, " +
			"and an ALL mode that queries every record type in parallel.",
		promptSnippet: "cyber_dns: DNS record lookup for an authorized domain",
		technique: "recon",
		requires: ["dig"],
		installHint: "Install dig on Kali with: sudo apt install -y dnsutils",
		action: "recon",
		parameters: dnsParameters,
		target: (params) => params.domain,
		build: (params) => {
			const domain = normalizeDomain(params.domain);
			if (domain.length === 0) throw new Error("a domain is required");
			const resolver = params.resolver?.trim();
			if (resolver && !RESOLVER_PATTERN.test(resolver)) {
				throw new Error(`invalid resolver "${resolver}": expected an IP address or a hostname`);
			}
			return resolveRecordTypes(params.record_type).map((type) => ({
				bin: "dig",
				args: ["+short", ...(resolver ? [`@${resolver}`] : []), domain, type],
				label: `dig-${safeFileName(domain)}-${type}`,
				target: domain,
			}));
		},
		summarize: (results, params) => {
			const domain = normalizeDomain(params.domain);
			const types = resolveRecordTypes(params.record_type);
			const records: Record<string, string[]> = {};
			const failures: string[] = [];
			for (const [index, result] of results.entries()) {
				const type = types[index] ?? "A";
				if (result.timedOut) {
					failures.push(`${type}: timed out`);
					continue;
				}
				if (result.code !== 0) {
					failures.push(`${type}: ${firstLine(result.stderr) || `exit code ${result.code}`}`);
					continue;
				}
				records[type] = lines(result.stdout);
			}
			const addresses = [...(records.A ?? []), ...(records.AAAA ?? [])].filter(isIpAddress);
			if (addresses.length > 0) {
				addHosts(engagementRootFrom(results), [{ host: domain, addresses, source: "dig" }]);
			}
			const rendered: string[] = [];
			for (const type of types) {
				const values = records[type];
				if (!values || values.length === 0) {
					rendered.push(`${type.padEnd(6)}(none)`);
					continue;
				}
				for (const value of values) rendered.push(`${type.padEnd(6)}${value}`);
			}
			if (failures.length > 0) rendered.push("", `errors: ${failures.join("; ")}`);
			const total = Object.values(records).reduce((count, values) => count + values.length, 0);
			const resolver = params.resolver?.trim();
			return {
				summary:
					total === 0
						? `No ${types.join("/")} records for ${domain}${resolver ? ` via ${resolver}` : ""}`
						: `${total} ${types.join("/")} record${total === 1 ? "" : "s"} for ${domain}${resolver ? ` via ${resolver}` : ""}`,
				output: rendered.join("\n"),
				details: { domain, recordTypes: types, resolver, records },
				severity: failures.length > 0 ? "medium" : "info",
				isError: failures.length > 0 && total === 0,
			};
		},
	}),

	defineCyberTool<typeof whoisParameters, WhoisDetails>({
		name: "cyber_whois",
		label: "WHOIS registration data",
		description:
			"Read the WHOIS record of an authorized domain: registrar, creation and expiry dates, " +
			"name servers, registrant country and the registrant organization or ASN.",
		promptSnippet: "cyber_whois: registrar, dates, name servers and ASN of an authorized domain",
		technique: "recon",
		requires: ["whois"],
		installHint: "Install whois on Kali with: sudo apt install -y whois",
		action: "recon",
		parameters: whoisParameters,
		target: (params) => params.domain,
		build: (params) => {
			const domain = normalizeDomain(params.domain);
			if (domain.length === 0) throw new Error("a domain is required");
			return { bin: "whois", args: [domain], label: `whois-${safeFileName(domain)}`, target: domain };
		},
		summarize: (results, params) => {
			const domain = normalizeDomain(params.domain);
			const result = results[0];
			if (!result) {
				return {
					summary: `whois produced no result for ${domain}`,
					details: { domain, nameServers: [] },
					isError: true,
					severity: "medium",
				};
			}
			const text = `${result.stdout}\n${result.stderr}`;
			const info = parseWhois(text);
			if (!info) {
				return {
					summary: `whois has no record for ${domain}`,
					output: firstLine(result.stdout) || firstLine(result.stderr),
					details: { domain, nameServers: [] },
					isError: true,
					severity: "low",
				};
			}
			if (isEmptyWhois(info)) {
				return {
					summary: `the whois record for ${domain} could not be parsed`,
					output: result.artifact
						? `The whois record for ${domain} uses a layout this parser does not know.\nRaw output: ${result.artifact}`
						: `The whois record for ${domain} uses a layout this parser does not know.`,
					details: { domain, ...info, artifact: result.artifact },
					severity: "low",
				};
			}
			return {
				summary:
					`${domain}: ${info.registrar ?? "registrar unknown"}` +
					`${info.created ? `, created ${formatDate(info.created)}` : ""}` +
					`${info.expires ? `, expires ${formatDate(info.expires)}` : ""}`,
				output: formatWhois(domain, info, result.artifact),
				details: { domain, ...info, artifact: result.artifact },
				severity: "info",
			};
		},
	}),
];
