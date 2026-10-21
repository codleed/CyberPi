/**
 * Vulnerability assessment tools: nuclei, sqlmap and dalfox.
 *
 * Each tool runs a real scanner from the Kali toolchain, parses its structured
 * output and reports what it found. Nothing is faked: when a scanner is
 * missing the toolchain check refuses the call, and when a scanner finds
 * nothing the tool says exactly that.
 *
 * `cyber_vuln_scan` needs more than one command (the scan itself plus a lookup
 * in the local CVE database for the CISA KEV catalog) and has to check every
 * host of a target list against the engagement scope, so it uses the custom
 * `execute` path of the toolkit. The other two tools are single commands and
 * use the declarative `build` + `summarize` path.
 */

import fs from "node:fs";

import { Type } from "@earendil-works/pi-ai";
import type { ToolDefinition } from "@earendil-works/pi-coding-agent";

import { cacheGet, cacheKey, cacheSet } from "../lib/cache.ts";
import { CVEDB_SCRIPT } from "../lib/config.ts";
import { run, which } from "../lib/exec.ts";
import { appendJournal, writeArtifact } from "../lib/journal.ts";
import { checkTarget, loadScope } from "../lib/scope.ts";
import { type CyberToolOutcome, defineCyberTool, lines, parseJson, parseJsonLines } from "../lib/toolkit.ts";

/** How many individual findings are listed before the list is cut short. */
const MAX_LISTED = 50;

/** Default minimum severity of a nuclei scan. */
const DEFAULT_SEVERITY = "low";

/** Default number of concurrent nuclei requests. */
const DEFAULT_CONCURRENCY = 25;

/** Default sqlmap level and risk. */
const DEFAULT_SQLMAP_LEVEL = 1;
const DEFAULT_SQLMAP_RISK = 1;

/** sqlmap technique letters for the techniques this tool exposes. */
const SQLMAP_TECHNIQUE_LETTERS: Record<string, string> = {
	boolean: "B",
	"time-based": "T",
	union: "U",
};

/** Severities from lowest to highest, used to expand the severity filter. */
const SEVERITY_LADDER = ["info", "low", "medium", "high", "critical"];

/** Nuclei tags that are common enough to recognise a tag list. */
const NUCLEI_TAG_WORDS = new Set([
	"auth",
	"backup",
	"bypass",
	"cloud",
	"config",
	"container",
	"cors",
	"cve",
	"csrf",
	"default-login",
	"deserialization",
	"directory",
	"dns",
	"dos",
	"env",
	"exposed",
	"exposure",
	"file",
	"fileupload",
	"graphql",
	"headless",
	"inj",
	"injection",
	"jwt",
	"k8s",
	"lfi",
	"linux",
	"login",
	"misconfig",
	"mongodb",
	"mssql",
	"mysql",
	"open",
	"panel",
	"password",
	"php",
	"prototype-pollution",
	"rce",
	"rfi",
	"redirect",
	"router",
	"secrets",
	"sqli",
	"ssrf",
	"ssti",
	"tech",
	"tomcat",
	"traversal",
	"unauth",
	"upload",
	"vuln",
	"webshell",
	"windows",
	"wordpress",
	"xss",
]);

/** Matches a CVE identifier anywhere in a string. */
const CVE_PATTERN = /\bCVE-\d{4}-\d{4,7}\b/gi;

/** File names that hold one target per line. */
const LIST_EXTENSIONS = [".txt", ".lst", ".list", ".urls", ".csv", ".in"];

/** The last sqlmap run, carried from `build` to `summarize`. */
interface SqlmapRun {
	technique: string;
	letter: string;
	level: number;
	risk: number;
	notes: string[];
}

let sqlmapRun: SqlmapRun | undefined;

/** One nuclei finding, flattened out of the JSONL record. */
interface NucleiFinding {
	templateId: string;
	templatePath: string;
	severity: string;
	name: string;
	url: string;
	matcher: string;
	cves: string[];
}

/** One entry of the CISA KEV catalog. */
interface KevEntry {
	cveId: string;
	name?: string;
	vendor?: string;
	product?: string;
	dateAdded?: string;
	dueDate?: string;
}

/** The KEV catalog as read from the local CVE database. */
interface KevCatalog {
	available: boolean;
	ids: Set<string>;
	entries: Map<string, KevEntry>;
	note?: string;
}

/** Structured result of a nuclei scan. */
interface VulnScanDetails {
	target?: string;
	blocked?: boolean;
	reason?: string;
	findings?: number;
	bySeverity?: Record<string, number>;
	cveFindings?: number;
	kevFindings?: number;
	kevAvailable?: boolean;
	artifact?: string;
	command?: string;
	exitCode?: number | null;
	cached?: boolean;
	results?: NucleiFinding[];
}

/** One confirmed SQL injection point. */
interface SqlmapPoint {
	parameter: string;
	type: string;
	title: string;
	payloads: string[];
}

/** Structured result of a sqlmap assessment. */
interface SqliDetails {
	target?: string;
	verdict?: string;
	parameters?: string[];
	points?: SqlmapPoint[];
	payloads?: number;
	dbms?: string;
	artifact?: string;
	command?: string;
	exitCode?: number | null;
}

/** One dalfox XSS issue. */
interface DalfoxFinding {
	type: string;
	label: string;
	method: string;
	param: string;
	url: string;
	payload: string;
	location: string;
}

/** Structured result of a dalfox assessment. */
interface XssDetails {
	target?: string;
	confirmed?: number;
	reflected?: number;
	byType?: Record<string, number>;
	issues?: DalfoxFinding[];
	artifact?: string;
	command?: string;
	exitCode?: number | null;
}

/** Coerce a JSON value into a trimmed string. */
function toText(value: unknown): string | undefined {
	if (typeof value === "string" && value.trim().length > 0) return value.trim();
	return undefined;
}

/** Coerce a JSON value into a plain object. */
function toRecord(value: unknown): Record<string, unknown> | undefined {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
	return value as Record<string, unknown>;
}

/** Keep only the string members of an array. */
function toStringArray(value: unknown): string[] {
	if (!Array.isArray(value)) return [];
	return value.filter((item): item is string => typeof item === "string");
}

/** Clamp a numeric option into a sane range. */
function clampCount(value: number | undefined, fallback: number, min: number, max: number): number {
	if (value === undefined || !Number.isFinite(value)) return fallback;
	const rounded = Math.floor(value);
	if (rounded < min) return min;
	if (rounded > max) return max;
	return rounded;
}

/** Count occurrences in a map, used for the summary breakdowns. */
function bump(counts: Map<string, number>, key: string, amount = 1): void {
	counts.set(key, (counts.get(key) ?? 0) + amount);
}

/** Turn a counter map into a plain object with sorted keys. */
function toSortedRecord(counts: Map<string, number>): Record<string, number> {
	const record: Record<string, number> = {};
	for (const key of [...counts.keys()].sort()) {
		record[key] = counts.get(key) ?? 0;
	}
	return record;
}

/** Every CVE identifier mentioned in the given strings. */
function findCveIds(values: string[]): string[] {
	const found = new Set<string>();
	for (const value of values) {
		if (!value) continue;
		for (const match of value.matchAll(CVE_PATTERN)) {
			found.add(match[0].toUpperCase());
		}
	}
	return [...found];
}

/** Make a value safe to put inside a Markdown table cell. */
function escapeCell(value: string): string {
	return value.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

/** Shorten a payload so a report line stays readable. */
function truncate(value: string, max = 120): string {
	if (value.length <= max) return value;
	return `${value.slice(0, Math.max(0, max - 3))}...`;
}

/** Map a nuclei severity onto the severity scale of the journal. */
function toJournalSeverity(severity: string): "info" | "low" | "medium" | "high" | "critical" {
	switch (severity.toLowerCase()) {
		case "critical":
			return "critical";
		case "high":
			return "high";
		case "medium":
			return "medium";
		case "low":
			return "low";
		default:
			return "info";
	}
}

/** Rank of a severity, so the most severe ones can be listed first. */
function severityRank(severity: string): number {
	const index = SEVERITY_LADDER.indexOf(severity.trim().toLowerCase());
	return index === -1 ? -1 : index;
}

/**
 * Decide which nuclei flag a template selection belongs to.
 *
 * A list of lowercase words is a tag selection (`cve,rce`), anything else is a
 * list of template identifiers or template paths. The explicit `tags:` and
 * `templates:` prefixes always win.
 */
function nucleiTemplateSelector(value: string): { flag: "-t" | "-tags"; values: string[] } {
	const trimmed = value.trim();
	if (/^tags\s*:/i.test(trimmed)) {
		return { flag: "-tags", values: splitList(trimmed.replace(/^tags\s*:/i, "")) };
	}
	if (/^templates?\s*:/i.test(trimmed)) {
		return { flag: "-t", values: splitList(trimmed.replace(/^templates?\s*:/i, "")) };
	}
	const values = splitList(trimmed);
	const looksLikeTags =
		values.length > 0 &&
		values.every((item) => /^[a-z][a-z0-9_-]*$/.test(item)) &&
		values.some((item) => NUCLEI_TAG_WORDS.has(item));
	return { flag: looksLikeTags ? "-tags" : "-t", values };
}

/** Split a comma separated list into its non-empty parts. */
function splitList(value: string): string[] {
	return value
		.split(",")
		.map((item) => item.trim())
		.filter((item) => item.length > 0);
}

/**
 * Expand a minimum severity into the list of severities nuclei should run.
 *
 * nuclei matches the severities it is given, so a minimum severity is passed
 * as every severity from that level upwards. `unknown` has no place on the
 * ladder and is passed on its own.
 */
function severityFilter(value: string): string {
	const normalized = value.trim().toLowerCase();
	if (normalized === "unknown") return "unknown";
	const index = SEVERITY_LADDER.indexOf(normalized);
	if (index === -1) return normalized;
	return SEVERITY_LADDER.slice(index).join(",");
}

/** Decide whether a target is a single URL or a file holding a list of targets. */
function resolveTargetInput(raw: string): { url?: string; listFile?: string } {
	const trimmed = raw.trim();
	if (trimmed.startsWith("@")) {
		return { listFile: trimmed.slice(1).trim() };
	}
	if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
		return { url: trimmed };
	}
	try {
		if (fs.existsSync(trimmed)) {
			return fs.statSync(trimmed).isFile() ? { listFile: trimmed } : { url: trimmed };
		}
	} catch {
		return { url: trimmed };
	}
	// A path that does not exist is reported as a missing target list rather
	// than as a target, so the operator gets a message that names the file.
	if (/[\\/]/.test(trimmed)) {
		const first = trimmed.split(/[\\/]/)[0];
		return first.includes(".") ? { url: trimmed } : { listFile: trimmed };
	}
	if (LIST_EXTENSIONS.some((extension) => trimmed.toLowerCase().endsWith(extension))) {
		return { listFile: trimmed };
	}
	return { url: trimmed };
}

/** Read a list of targets, one per line, from a file. */
function readTargetList(file: string): string[] {
	if (!fs.existsSync(file)) {
		throw new Error(`target list not found: ${file}`);
	}
	const targets = lines(fs.readFileSync(file, "utf8")).filter((line) => !line.startsWith("#"));
	if (targets.length === 0) {
		throw new Error(`target list is empty: ${file}`);
	}
	return targets;
}

/** Parse the JSONL findings nuclei writes to stdout. */
function parseNucleiFindings(text: string): NucleiFinding[] {
	const findings: NucleiFinding[] = [];
	for (const entry of parseJsonLines<unknown>(text)) {
		const record = toRecord(entry);
		if (!record) continue;
		const info = toRecord(record.info);
		const classification = toRecord(info?.classification);
		const templateId = toText(record.templateID) ?? toText(record.template) ?? "";
		const templatePath = toText(record.templatePath) ?? "";
		const severity = (toText(info?.severity) ?? toText(record.severity) ?? "unknown").toLowerCase();
		const name = toText(info?.name) ?? "";
		const url = toText(record["matched-at"]) ?? toText(record.url) ?? toText(record.host) ?? "";
		const matcher = toText(record["matcher-name"]) ?? toText(record.matcher) ?? "";
		const tags = toStringArray(info?.tags);
		const cves = findCveIds([templateId, templatePath, toText(classification?.["cve-id"]) ?? "", name, ...tags]);
		if (!templateId && !url) continue;
		findings.push({ templateId, templatePath, severity, name, url, matcher, cves });
	}
	return findings;
}

/** Walk a JSON document and collect every object it contains. */
function collectRecords(value: unknown, out: Record<string, unknown>[]): void {
	if (Array.isArray(value)) {
		for (const item of value) collectRecords(item, out);
		return;
	}
	const record = toRecord(value);
	if (!record) return;
	out.push(record);
	for (const item of Object.values(record)) collectRecords(item, out);
}

/** Build a KEV entry from one record of the CVE database. */
function kevEntryFrom(record: Record<string, unknown>): KevEntry | undefined {
	let cveId = "";
	for (const [key, value] of Object.entries(record)) {
		if (typeof value !== "string" || !/cve/i.test(key)) continue;
		const ids = findCveIds([value]);
		if (ids.length > 0) {
			cveId = ids[0];
			break;
		}
	}
	if (!cveId) return undefined;
	return {
		cveId,
		name: toText(record.vulnerabilityName) ?? toText(record.name) ?? toText(record.shortDescription),
		vendor: toText(record.vendorProject) ?? toText(record.vendor),
		product: toText(record.product),
		dateAdded: toText(record.dateAdded),
		dueDate: toText(record.dueDate),
	};
}

/**
 * Read the CISA KEV catalog from the local CVE database.
 *
 * The lookup is a local query, so it never touches the network. When the
 * database has not been synced yet the scan still runs, the KEV highlight is
 * simply reported as unavailable.
 */
async function loadKevCatalog(workdir: string): Promise<KevCatalog> {
	const empty: KevCatalog = { available: false, ids: new Set<string>(), entries: new Map<string, KevEntry>() };
	if (which("python3") === null) {
		return { ...empty, note: "python3 is not installed, so the CISA KEV catalog could not be checked" };
	}
	const result = await run("python3", [CVEDB_SCRIPT, "kev", "--json"], {
		cwd: workdir,
		timeoutMs: 30_000,
		maxBytes: 4_000_000,
	});
	if (result.code !== 0) {
		const reason = (result.stderr || result.stdout).trim().split("\n").slice(-2).join(" ").trim();
		return { ...empty, note: `the local CVE database is unavailable (${reason || `exit ${result.code}`})` };
	}
	const parsed = parseJson<unknown>(result.stdout);
	if (parsed === undefined) {
		return { ...empty, note: "the local CVE database did not return usable JSON" };
	}
	const records: Record<string, unknown>[] = [];
	collectRecords(parsed, records);
	const ids = new Set<string>();
	const entries = new Map<string, KevEntry>();
	for (const record of records) {
		const entry = kevEntryFrom(record);
		if (!entry) continue;
		ids.add(entry.cveId);
		if (!entries.has(entry.cveId)) entries.set(entry.cveId, entry);
	}
	if (ids.size === 0) {
		return { available: true, ids, entries, note: "the local CVE database holds no KEV entries (run cyber_cve_sync)" };
	}
	return { available: true, ids, entries };
}

/** Parse the injection points sqlmap reports in its final summary. */
function parseSqlmapPoints(text: string): SqlmapPoint[] {
	const points: SqlmapPoint[] = [];
	const marker = /sqlmap identified the following injection point\(s\):/i.exec(text);
	if (!marker) return points;
	const section = text.slice(marker.index + marker[0].length);
	for (const block of section.split(/^\s*-{3,}\s*$/m)) {
		const parameter = /^\s*Parameter:\s*(.+)$/im.exec(block)?.[1]?.trim();
		const type = /^\s*Type:\s*(.+)$/im.exec(block)?.[1]?.trim();
		const title = /^\s*Title:\s*(.+)$/im.exec(block)?.[1]?.trim();
		const payloads = [...block.matchAll(/^\s*Payload:\s*(.+)$/gim)].map((match) => match[1].trim());
		if (!parameter && !type && payloads.length === 0) continue;
		points.push({
			parameter: parameter ?? "(unknown)",
			type: type ?? "unknown",
			title: title ?? "",
			payloads,
		});
	}
	return points;
}

/** Decide the verdict of a sqlmap run. */
function sqlmapVerdict(text: string, points: SqlmapPoint[]): string {
	if (points.length > 0) return "vulnerable";
	if (/is not injectable|does not seem to be injectable|no SQL injection point|is not vulnerable/i.test(text)) {
		return "not injectable";
	}
	if (/might be injectable|appears to be injectable/i.test(text)) return "suspected";
	return "inconclusive";
}

/** dalfox type codes and what they mean. */
const DALFOX_TYPE_LABELS: Record<string, string> = {
	V: "verified",
	R: "reflected",
	B: "blind",
	D: "dom",
	A: "attribute",
	C: "cors",
};

/** Turn a dalfox type code into a readable label. */
function dalfoxTypeLabel(type: string): string {
	const mapped = DALFOX_TYPE_LABELS[type.trim().toUpperCase()];
	return mapped ?? type.trim().toLowerCase();
}

/** Parse the JSON findings dalfox writes, in either JSON or JSONL shape. */
function parseDalfoxFindings(text: string): DalfoxFinding[] {
	const values: unknown[] = [];
	for (const line of lines(text)) {
		if (!line.startsWith("{")) continue;
		const parsed = parseJson<unknown>(line);
		if (parsed !== undefined) values.push(parsed);
	}
	if (values.length === 0) {
		const whole = parseJson<unknown>(text.trim());
		if (Array.isArray(whole)) values.push(...whole);
		else if (whole !== undefined) values.push(whole);
	}

	const findings: DalfoxFinding[] = [];
	for (const value of values) {
		const record = toRecord(value);
		if (!record) continue;
		const type = toText(record.type) ?? "";
		const param = toText(record.param) ?? "";
		const payloads = toStringArray(record.poc);
		if (!type && !param && payloads.length === 0) continue;
		if (/^(summary|statistics|stat|total)$/i.test(type)) continue;
		const evidence = toRecord(record.evidence);
		const method = toText(record.method) ?? "";
		const location = dalfoxLocation(method, param, evidence);
		findings.push({
			type,
			label: dalfoxTypeLabel(type),
			method,
			param,
			url: toText(record.url) ?? "",
			payload: payloads[0] ?? "",
			location,
		});
	}
	return findings;
}

/** Parse the human readable output of dalfox, used when json was not asked for. */
function parseDalfoxText(text: string): DalfoxFinding[] {
	const findings: DalfoxFinding[] = [];
	for (const line of lines(text)) {
		const match = /^\[([A-Za-z])\]\s+.*?\((GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\)\s+in\s+(\S+)\s+parameter/i.exec(line);
		if (!match) continue;
		const method = match[2].toUpperCase();
		findings.push({
			type: match[1],
			label: dalfoxTypeLabel(match[1]),
			method,
			param: match[3],
			url: "",
			payload: "",
			location: `${method}, param ${match[3]}`,
		});
	}
	return findings;
}

/** Describe where dalfox saw the payload land. */
function dalfoxLocation(method: string, param: string, evidence: Record<string, unknown> | undefined): string {
	const parts: string[] = [];
	if (method) parts.push(method);
	if (param) parts.push(`param ${param}`);
	for (const key of Object.keys(evidence ?? {})) {
		const match = /^PoC-(Header|Cookie|Attribute|Body|Reflected|HTML|DOM|Value)$/i.exec(key);
		if (match) parts.push(match[1].toLowerCase());
	}
	return parts.join(", ");
}

const vulnScanParams = Type.Object({
	target: Type.String({
		description: "URL to scan, or the path of a file holding one target per line (prefix with @ to force a file)",
	}),
	templates: Type.Optional(
		Type.String({
			description:
				"Template selection: comma separated nuclei template ids, or tags such as cve,rce. " +
				"Use an explicit tags: or templates: prefix to force one of the two.",
		}),
	),
	severity: Type.Optional(
		Type.Enum(["info", "low", "medium", "high", "critical", "unknown"], {
			description: `Minimum severity to report, passed to nuclei as -severity (default ${DEFAULT_SEVERITY})`,
		}),
	),
	concurrency: Type.Optional(Type.Number({ description: `Concurrent nuclei requests (default ${DEFAULT_CONCURRENCY})` })),
	rate_limit: Type.Optional(Type.Number({ description: "Maximum requests per second (nuclei -rate-limit)" })),
	include_raw: Type.Optional(
		Type.Boolean({
			description:
				"Include the raw JSONL findings in the result. A finding may carry extracted values, so keep the " +
				"artifact as the authoritative copy.",
		}),
	),
});

const sqliParams = Type.Object({
	target: Type.String({ description: "URL to test, e.g. https://example.com/page?id=1" }),
	parameter: Type.Optional(Type.String({ description: "Test only this parameter, e.g. id" })),
	technique: Type.Optional(
		Type.Enum(["boolean", "time-based", "union"], { description: "Injection technique to test (default boolean)" }),
	),
	level: Type.Optional(Type.Number({ description: `sqlmap --level, 1-5 (default ${DEFAULT_SQLMAP_LEVEL})` })),
	risk: Type.Optional(Type.Number({ description: `sqlmap --risk, 1-3 (default ${DEFAULT_SQLMAP_RISK})` })),
	dbs: Type.Optional(Type.String({ description: "Restrict the back-end database type, e.g. mysql,postgresql" })),
	forms: Type.Optional(Type.Boolean({ description: "Also test the forms found on the target page (--forms)" })),
	crawl_depth: Type.Optional(Type.Number({ description: "sqlmap --crawl depth" })),
});

const xssParams = Type.Object({
	target: Type.String({ description: "URL to test, e.g. https://example.com/search?q=test" }),
	blind: Type.Optional(Type.Boolean({ description: "Test for blind XSS with an out-of-band callback (--blind)" })),
	mining_dict: Type.Optional(Type.Boolean({ description: "Mine the target for injectable parameters (--mining-dict)" })),
	skip_bav: Type.Optional(Type.Boolean({ description: "Skip the basic another vulnerability analysis (--skip-bav)" })),
	proxy: Type.Optional(Type.String({ description: "Proxy to send the requests through, e.g. http://127.0.0.1:8080" })),
	format: Type.Optional(Type.Enum(["json", "text"], { description: "Output format of dalfox (default json)" })),
});

export const vulnTools: ToolDefinition[] = [
	defineCyberTool<typeof vulnScanParams, VulnScanDetails>({
		name: "cyber_vuln_scan",
		label: "Template vulnerability scan",
		description:
			"Scan a target with nuclei templates. Parses the JSONL findings into severity, template, matched URL and " +
			"matcher, counts them by severity and highlights every finding that maps to a CVE or appears in the CISA " +
			"KEV catalog. Accepts a single URL or a file of targets. The severity is a minimum, so the scan runs every " +
			"template from that severity upwards. The raw JSONL is written to the engagement artifacts.",
		promptSnippet: "cyber_vuln_scan: template vulnerability scan with nuclei",
		technique: "vulnerability-scan",
		annotations: { destructiveHint: false, openWorldHint: true },
		requires: ["nuclei"],
		installHint: "Install nuclei on Kali with: sudo apt install -y nuclei",
		parameters: vulnScanParams,
		cacheTtlMs: 600_000,
		timeoutMs: 900_000,
		action: "vuln_scan",
		// The target of a list file cannot be checked as a whole: the scope of
		// every host in the list is checked inside execute instead.
		target: (params) => resolveTargetInput(params.target).url,
		execute: async (params, ctx) => {
			const workdir = ctx.cwd;
			const key = cacheKey("cyber_vuln_scan", params);
			const cached = cacheGet<CyberToolOutcome<VulnScanDetails>>(workdir, key);
			if (cached) {
				return {
					...cached,
					details: cached.details ? { ...cached.details, cached: true } : cached.details,
				};
			}

			const input = resolveTargetInput(params.target);
			if (!input.url && !input.listFile) {
				return { summary: "cyber_vuln_scan needs a target URL or a file of targets.", isError: true };
			}

			const targets = input.listFile ? readTargetList(input.listFile) : [];
			if (targets.length > 0) {
				const scope = loadScope(workdir);
				const denied: string[] = [];
				for (const target of targets) {
					const decision = checkTarget(scope, target, { technique: "vulnerability-scan" });
					if (!decision.allowed) denied.push(`${target} (${decision.reason})`);
				}
				if (denied.length > 0) {
					const summary =
						`Blocked by engagement scope: ${denied.length} target(s) of ${input.listFile} are not authorized: ` +
						`${denied.slice(0, 5).join("; ")}`;
					appendJournal(workdir, {
						ts: new Date().toISOString(),
						tool: "cyber_vuln_scan",
						action: "blocked",
						target: params.target,
						summary,
						severity: "info",
					});
					return {
						summary,
						details: { blocked: true, reason: summary, target: params.target },
						isError: true,
					};
				}
			}

			const args = ["-jsonl", "-silent", "-duc"];
			if (input.listFile) args.push("-l", input.listFile);
			else args.push("-u", input.url as string);
			if (params.templates) {
				const selector = nucleiTemplateSelector(params.templates);
				if (selector.values.length > 0) args.push(selector.flag, ...selector.values);
			}
			args.push("-severity", severityFilter(params.severity ?? DEFAULT_SEVERITY));
			args.push("-c", String(clampCount(params.concurrency, DEFAULT_CONCURRENCY, 1, 500)));
			if (params.rate_limit !== undefined) {
				args.push("-rate-limit", String(clampCount(params.rate_limit, 150, 1, 100_000)));
			}

			const result = await run("nuclei", args, {
				cwd: workdir,
				timeoutMs: 900_000,
				maxBytes: 16_000_000,
			});

			const rawJsonl = result.stdout;
			const artifact = writeArtifact(workdir, `vuln_scan-${new Date().toISOString().replace(/[:.]/g, "-")}.jsonl`, rawJsonl);
			const findings = parseNucleiFindings(rawJsonl);

			const bySeverity = new Map<string, number>();
			for (const finding of findings) bump(bySeverity, finding.severity);
			const cveFindings = findings.filter((finding) => finding.cves.length > 0);

			const kev =
				cveFindings.length > 0
					? await loadKevCatalog(workdir)
					: { available: false, ids: new Set<string>(), entries: new Map<string, KevEntry>() };
			const kevFindings = findings.filter((finding) => finding.cves.some((id) => kev.ids.has(id)));

			let highest: "info" | "low" | "medium" | "high" | "critical" = "info";
			for (const finding of findings) {
				const severity = toJournalSeverity(finding.severity);
				const order = ["info", "low", "medium", "high", "critical"];
				if (order.indexOf(severity) > order.indexOf(highest)) highest = severity;
			}

			const counts = [...bySeverity.entries()]
				.sort((a, b) => severityRank(b[0]) - severityRank(a[0]) || b[1] - a[1])
				.map(([key, count]) => `${key} ${count}`);
			const summary =
				`nuclei found ${findings.length} issue(s) on ${input.url ?? input.listFile}` +
				`${counts.length > 0 ? ` (${counts.join(", ")})` : ""}` +
				`; ${cveFindings.length} CVE-mapped, ${kevFindings.length} in CISA KEV.`;

			const output: string[] = [];
			if (counts.length > 0) output.push(`Severity counts: ${counts.join(", ")}`);
			if (findings.length > 0) {
				output.push("");
				output.push("| Severity | Template | Matched URL | Matcher | CVE |");
				output.push("| --- | --- | --- | --- | --- |");
				for (const finding of findings.slice(0, MAX_LISTED)) {
					const cve =
						finding.cves.length > 0
							? finding.cves.map((id) => (kev.ids.has(id) ? `${id} (KEV)` : id)).join(", ")
							: "-";
					output.push(
						`| ${finding.severity.toUpperCase()} | ${escapeCell(finding.templateId || "-")} | ` +
							`${escapeCell(finding.url || "-")} | ${escapeCell(finding.matcher || "-")} | ${escapeCell(cve)} |`,
					);
				}
				if (findings.length > MAX_LISTED) {
					output.push(`| ... | ${findings.length - MAX_LISTED} more finding(s) in the artifact | | | |`);
				}
			} else {
				output.push("No findings.");
			}

			if (cveFindings.length > 0) {
				output.push("");
				output.push("CVE and KEV findings:");
				for (const finding of cveFindings.slice(0, MAX_LISTED)) {
					const kevIds = finding.cves.filter((id) => kev.ids.has(id));
					const kevNote = kevIds.length > 0 ? " [CISA KEV]" : "";
					const entry = kevIds.length > 0 ? kev.entries.get(kevIds[0]) : undefined;
					const name = entry?.name ? ` - ${entry.name}` : "";
					output.push(
						`  ${finding.severity.toUpperCase()} ${finding.cves.join(", ")}${kevNote}${name} - ${finding.url || finding.templateId}`,
					);
				}
			}
			if (kev.note) {
				output.push("");
				output.push(`KEV catalog: ${kev.note}`);
			}

			output.push("");
			output.push(`Raw JSONL: ${artifact}`);
			if (params.include_raw) {
				const rawLines = lines(rawJsonl);
				output.push("");
				output.push("Raw findings:");
				for (const line of rawLines.slice(0, 60)) output.push(line);
				if (rawLines.length > 60) output.push(`... and ${rawLines.length - 60} more line(s) in the artifact`);
			}

			appendJournal(workdir, {
				ts: new Date().toISOString(),
				tool: "cyber_vuln_scan",
				action: "scan",
				target: input.url ?? input.listFile,
				command: result.cmd,
				exitCode: result.code,
				durationMs: result.durationMs,
				summary,
				severity: highest,
				artifact,
			});

			const outcome: CyberToolOutcome<VulnScanDetails> = {
				summary,
				output: output.join("\n"),
				severity: highest,
				details: {
					target: input.url ?? input.listFile,
					findings: findings.length,
					bySeverity: toSortedRecord(bySeverity),
					cveFindings: cveFindings.length,
					kevFindings: kevFindings.length,
					kevAvailable: kev.available,
					artifact,
					command: result.cmd,
					exitCode: result.code,
					results: findings.slice(0, MAX_LISTED),
				},
			};
			cacheSet(workdir, key, outcome, 600_000);
			return outcome;
		},
	}),

	defineCyberTool<typeof sqliParams, SqliDetails>({
		name: "cyber_sqli",
		label: "SQL injection assessment",
		description:
			"Assess a URL for SQL injection with sqlmap in batch mode. Reports the injectable parameters, the " +
			"injection type of each of them, the back-end database and how many payloads were captured, without " +
			"dumping every payload into the transcript.",
		promptSnippet: "cyber_sqli: SQL injection assessment with sqlmap",
		technique: "web-testing",
		annotations: { destructiveHint: false, openWorldHint: true },
		requires: ["sqlmap"],
		installHint: "Install sqlmap on Kali with: sudo apt install -y sqlmap",
		parameters: sqliParams,
		cacheTtlMs: 600_000,
		timeoutMs: 900_000,
		action: "sqli",
		build: (params) => {
			const target = params.target?.trim();
			if (!target) {
				throw new Error("cyber_sqli needs an explicit target URL, for example https://example.com/page?id=1");
			}
			const technique = params.technique ?? "boolean";
			const letter = SQLMAP_TECHNIQUE_LETTERS[technique] ?? "B";
			let level = clampCount(params.level, DEFAULT_SQLMAP_LEVEL, 1, 5);
			let risk = clampCount(params.risk, DEFAULT_SQLMAP_RISK, 1, 3);
			const notes: string[] = [];
			if (letter === "U" && (level < 2 || risk < 2)) {
				notes.push("sqlmap only tests union queries with --level >= 2 and --risk >= 2, both were raised to 2.");
				level = Math.max(level, 2);
				risk = Math.max(risk, 2);
			}
			sqlmapRun = { technique, letter, level, risk, notes };
			const args = [
				"-u",
				target,
				"--batch",
				`--level=${level}`,
				`--risk=${risk}`,
				`--technique=${letter}`,
				"--disable-coloring",
			];
			if (params.parameter?.trim()) args.push("-p", params.parameter.trim());
			if (params.dbs?.trim()) args.push(`--dbms=${params.dbs.trim()}`);
			if (params.forms) args.push("--forms");
			if (params.crawl_depth !== undefined) {
				args.push(`--crawl=${clampCount(params.crawl_depth, 0, 0, 10)}`);
			}
			return { bin: "sqlmap", args, label: "sqli", target };
		},
		summarize: (results, params) => {
			const result = results[0];
			const artifact = result?.artifact;
			const raw =
				artifact && fs.existsSync(artifact) ? fs.readFileSync(artifact, "utf8") : (result?.stdout ?? "");
			const points = parseSqlmapPoints(raw);
			const payloads = [...raw.matchAll(/^\s*Payload:\s*(.+)$/gim)].map((match) => match[1].trim());
			const dbms = /back-end DBMS(?:\s+is|:)\s*([^\n\r,]+)/i.exec(raw)?.[1]?.trim().replace(/['"]/g, "");
			const verdict = sqlmapVerdict(raw, points);
			const suspected = [
				...new Set(
					[...raw.matchAll(/parameter '([^']+)' (?:might be|appears to be) injectable/gi)].map(
						(match) => match[1],
					),
				),
			];
			const parameters = points.map((point) => point.parameter);

			const output: string[] = [];
			output.push(
				`Technique: ${sqlmapRun?.technique ?? params.technique ?? "boolean"} | ` +
					`level ${sqlmapRun?.level ?? clampCount(params.level, DEFAULT_SQLMAP_LEVEL, 1, 5)} | ` +
					`risk ${sqlmapRun?.risk ?? clampCount(params.risk, DEFAULT_SQLMAP_RISK, 1, 3)}`,
			);
			if (dbms) output.push(`Back-end DBMS: ${dbms}`);
			for (const note of sqlmapRun?.notes ?? []) output.push(`Note: ${note}`);

			if (points.length > 0) {
				output.push("");
				output.push("Injectable parameters:");
				for (const point of points.slice(0, MAX_LISTED)) {
					const payload = point.payloads[0] ? ` (payload: ${truncate(point.payloads[0])})` : "";
					const title = point.title ? ` - ${point.title}` : "";
					output.push(`  ${point.parameter} [${point.type}]${title}${payload}`);
				}
				if (points.length > MAX_LISTED) {
					output.push(`  ... and ${points.length - MAX_LISTED} more parameter(s)`);
				}
			} else if (suspected.length > 0) {
				output.push("");
				output.push(`Suspected parameters: ${suspected.join(", ")}`);
			} else {
				output.push("");
				output.push("No injectable parameter was confirmed.");
			}
			output.push("");
			output.push(`Payloads captured: ${payloads.length} (full output: ${artifact ?? "not stored"})`);

			if (result && result.code !== 0) {
				const error = (result.stderr || result.stdout).trim();
				if (error.length > 0) {
					output.push("");
					output.push(`sqlmap exited with code ${result.code}: ${truncate(error.split("\n").slice(-3).join(" "), 300)}`);
				}
			}

			let summary: string;
			if (verdict === "vulnerable") {
				summary =
					`SQL injection confirmed on ${params.target}: ${points.length} injectable parameter(s) ` +
					`(${parameters.join(", ")}${dbms ? `; back-end ${dbms}` : ""}).`;
			} else if (verdict === "not injectable") {
				summary = `No SQL injection found on ${params.target}${dbms ? ` (back-end ${dbms})` : ""}.`;
			} else if (verdict === "suspected") {
				summary = `Possible SQL injection on ${params.target}: sqlmap flagged parameter(s) ${suspected.join(", ")}.`;
			} else {
				summary = `sqlmap could not decide whether ${params.target} is injectable${dbms ? ` (back-end ${dbms})` : ""}.`;
			}

			return {
				summary,
				output: output.join("\n"),
				severity: verdict === "vulnerable" ? "high" : verdict === "suspected" ? "medium" : "info",
				details: {
					target: params.target,
					verdict,
					parameters,
					points,
					payloads: payloads.length,
					dbms,
					artifact,
					command: result?.cmd,
					exitCode: result?.code ?? null,
				},
			};
		},
	}),

	defineCyberTool<typeof xssParams, XssDetails>({
		name: "cyber_xss",
		label: "Cross-site scripting assessment",
		description:
			"Test a URL for cross-site scripting with dalfox. Reports how many issues were confirmed and how many were " +
			"reflected, with the type of each issue and the parameter the payload landed in.",
		promptSnippet: "cyber_xss: cross-site scripting assessment with dalfox",
		technique: "web-testing",
		annotations: { destructiveHint: false, openWorldHint: true },
		requires: ["dalfox"],
		installHint: "Install dalfox on Kali with: go install github.com/hahwul/dalfox/v2@latest",
		parameters: xssParams,
		cacheTtlMs: 300_000,
		timeoutMs: 600_000,
		action: "xss",
		build: (params) => {
			const target = params.target?.trim();
			if (!target) {
				throw new Error("cyber_xss needs an explicit target URL, for example https://example.com/search?q=test");
			}
			const args = ["url", target, "--format", params.format ?? "json", "--no-color"];
			if (params.blind) args.push("--blind");
			if (params.mining_dict) args.push("--mining-dict");
			if (params.skip_bav) args.push("--skip-bav");
			if (params.proxy?.trim()) args.push("--proxy", params.proxy.trim());
			return { bin: "dalfox", args, label: "xss", target };
		},
		summarize: (results, params) => {
			const result = results[0];
			const artifact = result?.artifact;
			const raw =
				artifact && fs.existsSync(artifact) ? fs.readFileSync(artifact, "utf8") : (result?.stdout ?? "");
			const findings = params.format === "text" ? parseDalfoxText(raw) : parseDalfoxFindings(raw);
			const unparsed = params.format !== "text" && findings.length === 0 && raw.trim().length > 0;

			const byType = new Map<string, number>();
			for (const finding of findings) bump(byType, finding.label);
			const confirmed = findings.filter((finding) => finding.label === "verified").length;
			const reflected = findings.filter((finding) => finding.label === "reflected").length;

			const output: string[] = [];
			if (findings.length > 0) {
				const counts = [...byType.entries()].map(([key, count]) => `${key} ${count}`).join(", ");
				output.push(`Issues: ${findings.length} (${counts})`);
				output.push("");
				output.push("| Type | Method | Parameter | Location | Payload |");
				output.push("| --- | --- | --- | --- | --- |");
				for (const finding of findings.slice(0, MAX_LISTED)) {
					output.push(
						`| ${escapeCell(finding.label)} | ${escapeCell(finding.method || "-")} | ` +
							`${escapeCell(finding.param || "-")} | ${escapeCell(finding.location || "-")} | ` +
							`${escapeCell(truncate(finding.payload || "-", 80))} |`,
					);
				}
				if (findings.length > MAX_LISTED) {
					output.push(`| ... | | | ${findings.length - MAX_LISTED} more issue(s) in the artifact | |`);
				}
			} else if (unparsed) {
				output.push("dalfox produced output that could not be read as JSON. Run the scan again with format json.");
			} else {
				output.push("No cross-site scripting issue was found.");
			}
			if (params.format === "text") {
				output.push("");
				output.push("dalfox output:");
				for (const line of lines(raw).slice(0, 40)) output.push(`  ${line}`);
			}
			if (result && result.code !== 0) {
				const error = (result.stderr || result.stdout).trim();
				if (error.length > 0) {
					output.push("");
					output.push(`dalfox exited with code ${result.code}: ${truncate(error.split("\n").slice(-3).join(" "), 300)}`);
				}
			}

			const summary =
				findings.length > 0
					? `XSS assessment of ${params.target}: ${confirmed} confirmed and ${reflected} reflected issue(s) ` +
						`(${findings.length} in total).`
					: unparsed
						? `dalfox output for ${params.target} could not be parsed. Run the scan again with format json.`
						: `No cross-site scripting issue found on ${params.target}.`;

			return {
				summary,
				output: output.join("\n"),
				severity: confirmed > 0 ? "high" : findings.length > 0 ? "medium" : "info",
				details: {
					target: params.target,
					confirmed,
					reflected,
					byType: toSortedRecord(byType),
					issues: findings.slice(0, MAX_LISTED),
					artifact,
					command: result?.cmd,
					exitCode: result?.code ?? null,
				},
			};
		},
	}),
];
