/**
 * CVE intelligence tools backed by the bundled offline CVE database.
 *
 * `tools/cvedb/cvedb.py` mirrors the NVD catalogue, the CISA Known Exploited
 * Vulnerabilities catalog and FIRST EPSS scores into a local SQLite file.
 * Every query in this module is answered from that local database, so a
 * lookup never touches the network and answers in milliseconds.
 *
 * The exploit map cross-references the database with the exploit tooling that
 * ships with Kali (`searchsploit` and `msfconsole`) to answer the question that
 * actually matters during an engagement: is there a working exploit for this,
 * and is it being exploited in the wild?
 */

import fs from "node:fs";
import path from "node:path";
import { Type } from "@earendil-works/pi-ai";
import type { ToolDefinition } from "@earendil-works/pi-coding-agent";
import { CVEDB_SCRIPT, cveDatabasePath, ensureDir, engagementPaths } from "../lib/config.ts";
import { type RunPlan, type RunResult, run, runMany, which } from "../lib/exec.ts";
import {
	defineCyberTool,
	parseJson,
	type CyberToolOutcome,
	type CyberToolSummary,
} from "../lib/toolkit.ts";

const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,}$/i;
const NUMERIC_CVE_PATTERN = /^\d{4}-\d{4,}$/;
const CPE_PATTERN = /^cpe:2\.3:/i;
const MAX_PRODUCTS_SHOWN = 15;
const MAX_REFERENCES_SHOWN = 25;
const EXPLOIT_SEARCH_CONCURRENCY = 4;
const MAX_VERSION_PRODUCTS = 6;
const MAX_VERSION_LOOKUP = 200;

/**
 * A product affected by a CVE.
 *
 * The version fields carry the affected range when the database records one.
 */
export interface CveProduct {
	vendor: string;
	product: string;
	version: string;
	status: string;
	cpe: string;
	versionStart?: string;
	versionStartExclusive?: boolean;
	versionEnd?: string;
	versionEndExclusive?: boolean;
}

/** A single reference URL of an advisory. */
export interface CveReference {
	url: string;
	tags: string[];
}

/** A normalised CVE record. */
export interface CveEntry {
	cveId: string;
	description: string;
	cvssScore?: number;
	cvssVector: string;
	severity: string;
	cwes: string[];
	products: CveProduct[];
	kev: boolean;
	kevDateAdded: string;
	kevName: string;
	kevDueDate: string;
	kevRansomware: string;
	epss?: number;
	epssPercentile?: number;
	references: CveReference[];
	published: string;
	modified: string;
}

interface CveLookupDetails {
	cveId: string;
	description: string;
	severity: string;
	cvssScore?: number;
	cvssVector: string;
	cwes: string[];
	kev: boolean;
	epss?: number;
	products: CveProduct[];
	references: CveReference[];
	published: string;
	modified: string;
}

interface CveSyncDetails {
	cves: number;
	kev: number;
	epss: number;
	database: string;
	lastSync: string;
	full: boolean;
	includeKev: boolean;
	includeEpss: boolean;
	pages?: number;
}

interface ExploitMapRow {
	cveId: string;
	product: string;
	version?: string;
	versionStatus: string;
	cvss?: number;
	severity: string;
	kev: boolean;
	epss?: number;
	exploitdb: string[];
	metasploit: string[];
	publicExploit: boolean;
	verdict: string;
}

interface ExploitMapDetails {
	query: string;
	kind: string;
	version?: string;
	rows: ExploitMapRow[];
	artifact?: string;
	sources: string[];
}

export interface FlagArg {
	flag: string;
	value?: string;
}

interface SearchsploitHit {
	id: string;
	title: string;
	path: string;
	url: string;
}

interface MetasploitModule {
	path: string;
	disclosure: string;
	rank: string;
	description: string;
}

/* -------------------------------------------------------------------------- */
/* Generic value helpers                                                       */
/* -------------------------------------------------------------------------- */

function asRecord(value: unknown): Record<string, unknown> | undefined {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
	return value as Record<string, unknown>;
}

function asArray(value: unknown): unknown[] {
	if (Array.isArray(value)) return value;
	if (value === undefined || value === null) return [];
	return [value];
}

function pickValue(source: Record<string, unknown>, keys: string[]): unknown {
	for (const key of keys) {
		const value = source[key];
		if (value !== undefined && value !== null && value !== "") return value;
	}
	return undefined;
}

function pickString(source: Record<string, unknown>, keys: string[]): string | undefined {
	const value = pickValue(source, keys);
	if (typeof value === "string") {
		const trimmed = value.trim();
		return trimmed.length > 0 ? trimmed : undefined;
	}
	if (typeof value === "number" || typeof value === "boolean") return String(value);
	return undefined;
}

function pickNumber(source: Record<string, unknown>, keys: string[]): number | undefined {
	const value = pickValue(source, keys);
	if (typeof value === "number") return Number.isFinite(value) ? value : undefined;
	if (typeof value === "string") {
		const parsed = Number.parseFloat(value);
		if (Number.isFinite(parsed)) return parsed;
	}
	return undefined;
}

function pickBoolean(source: Record<string, unknown>, keys: string[]): boolean {
	const value = pickValue(source, keys);
	if (typeof value === "boolean") return value;
	if (typeof value === "number") return value !== 0;
	if (typeof value === "string") {
		const lower = value.trim().toLowerCase();
		if (lower === "true" || lower === "yes" || lower === "1") return true;
		if (lower === "false" || lower === "no" || lower === "0") return false;
	}
	return false;
}

function pickStringList(source: Record<string, unknown>, keys: string[]): string[] {
	const value = pickValue(source, keys);
	const result: string[] = [];
	for (const item of asArray(value)) {
		if (typeof item === "string") {
			const trimmed = item.trim();
			if (trimmed.length > 0) result.push(trimmed);
			continue;
		}
		const record = asRecord(item);
		if (!record) continue;
		const text = pickString(record, ["id", "cweId", "cwe_id", "name", "value", "description"]);
		if (text) result.push(text);
	}
	return result;
}

/* -------------------------------------------------------------------------- */
/* CPE handling                                                               */
/* -------------------------------------------------------------------------- */

function decodeCpePart(value: string | undefined): string {
	if (!value || value === "*" || value === "-") return "";
	return value.replace(/\\(.)/g, "$1").replace(/_/g, " ");
}

/**
 * Split a CPE into its vendor, product and version components.
 *
 * CPE 2.3 is `cpe:2.3:part:vendor:product:version:...` and CPE 2.2 is
 * `cpe:/part:vendor:product:version`.
 */
function parseCpe(cpe: string): { vendor: string; product: string; version: string } {
	const parts = cpe.split(":");
	if (parts[0].toLowerCase() !== "cpe") {
		return { vendor: "", product: "", version: "" };
	}
	if (parts[1] === "2.3") {
		return {
			vendor: decodeCpePart(parts[3]),
			product: decodeCpePart(parts[4]),
			version: decodeCpePart(parts[5]),
		};
	}
	if (parts[1]?.startsWith("/")) {
		return {
			vendor: decodeCpePart(parts[2]),
			product: decodeCpePart(parts[3]),
			version: decodeCpePart(parts[4]),
		};
	}
	return { vendor: "", product: "", version: "" };
}

/* -------------------------------------------------------------------------- */
/* Version handling                                                            */
/* -------------------------------------------------------------------------- */

function tokenizeVersion(value: string): Array<number | string> {
	const tokens: Array<number | string> = [];
	const matches = value.toLowerCase().match(/[0-9]+|[a-z]+/g);
	if (!matches) return tokens;
	for (const match of matches) {
		tokens.push(/^[0-9]+$/.test(match) ? Number.parseInt(match, 10) : match);
	}
	return tokens;
}

/** Compare two version strings. Returns -1, 0 or 1. */
export function compareVersions(left: string, right: string): number {
	const a = tokenizeVersion(left);
	const b = tokenizeVersion(right);
	const length = Math.max(a.length, b.length);
	for (let index = 0; index < length; index++) {
		const x = a[index];
		const y = b[index];
		if (x === undefined) {
			if (typeof y === "number") return y === 0 ? 0 : -1;
			return 1;
		}
		if (y === undefined) {
			if (typeof x === "number") return x === 0 ? 0 : 1;
			return -1;
		}
		if (typeof x === "number" && typeof y === "number") {
			if (x !== y) return x < y ? -1 : 1;
			continue;
		}
		const xs = String(x);
		const ys = String(y);
		if (xs !== ys) return xs < ys ? -1 : 1;
	}
	return 0;
}

export type VersionVerdict = "affected" | "not-affected" | "unknown";

export function matchProductVersion(product: CveProduct, version: string): VersionVerdict {
	const start = product.versionStart;
	const end = product.versionEnd;
	if (start || end) {
		if (start) {
			const comparison = compareVersions(version, start);
			if (product.versionStartExclusive ? comparison <= 0 : comparison < 0) return "not-affected";
		}
		if (end) {
			const comparison = compareVersions(version, end);
			if (product.versionEndExclusive ? comparison >= 0 : comparison > 0) return "not-affected";
		}
		return "affected";
	}
	const value = product.version.trim();
	if (value === "" || value === "*" || value.toLowerCase() === "n/a") return "unknown";
	if (value === "-") return "not-affected";
	return compareVersions(version, value) === 0 ? "affected" : "not-affected";
}

/** Aggregate the version verdict of a whole advisory. */
export function versionVerdict(entry: CveEntry, version: string): VersionVerdict {
	let sawDefinitive = false;
	let sawUnknown = false;
	for (const product of entry.products) {
		const verdict = matchProductVersion(product, version);
		if (verdict === "affected") return "affected";
		if (verdict === "unknown") sawUnknown = true;
		else sawDefinitive = true;
	}
	if (sawDefinitive && !sawUnknown) return "not-affected";
	return "unknown";
}

function renderVersionRange(product: CveProduct): string {
	if (product.versionStart && product.versionEnd) {
		const left = product.versionStartExclusive ? `>${product.versionStart}` : `>=${product.versionStart}`;
		const right = product.versionEndExclusive ? `<${product.versionEnd}` : `<=${product.versionEnd}`;
		return `${left}, ${right}`;
	}
	if (product.versionStart) {
		return product.versionStartExclusive ? `>${product.versionStart}` : `>=${product.versionStart}`;
	}
	if (product.versionEnd) {
		return product.versionEndExclusive ? `<${product.versionEnd}` : `<=${product.versionEnd}`;
	}
	if (product.version) return product.version;
	return "all versions";
}

/* -------------------------------------------------------------------------- */
/* CVE record normalisation                                                    */
/* -------------------------------------------------------------------------- */

function normalizeProducts(raw: unknown): CveProduct[] {
	const result: CveProduct[] = [];
	for (const item of asArray(raw)) {
		if (typeof item === "string") {
			const cpe = item.trim();
			if (!cpe) continue;
			const parsed = parseCpe(cpe);
			result.push({
				vendor: parsed.vendor,
				product: parsed.product,
				version: parsed.version,
				status: "",
				cpe,
			});
			continue;
		}
		const record = asRecord(item);
		if (!record) continue;
		const nested = pickValue(record, ["cpeMatch", "cpe_match", "matches", "nodes", "children", "configurations"]);
		if (Array.isArray(nested)) {
			result.push(...normalizeProducts(nested));
			continue;
		}
		const cpeValue = pickValue(record, ["cpe", "cpe_uri", "cpeUri", "criteria", "cpe23Uri"]);
		let cpe = typeof cpeValue === "string" ? cpeValue : "";
		if (!cpe) {
			const nestedCpe = asRecord(cpeValue);
			cpe = nestedCpe ? pickString(nestedCpe, ["cpe", "uri", "criteria"]) ?? "" : "";
		}
		const fromCpe = parseCpe(cpe);
		const versionStart = pickString(record, ["versionStartIncluding", "version_start_including", "versionStart"]);
		const versionEnd = pickString(record, ["versionEndIncluding", "version_end_including"]);
		const versionStartExclusive = pickString(record, ["versionStartExcluding", "version_start_excluding"]);
		const versionEndExclusive = pickString(record, ["versionEndExcluding", "version_end_excluding"]);
		result.push({
			vendor: pickString(record, ["vendor", "vendor_name", "vendorName"]) ?? fromCpe.vendor,
			product: pickString(record, ["product", "product_name", "productName", "name"]) ?? fromCpe.product,
			version:
				pickString(record, ["version", "version_value", "versionValue", "affected_version", "release"]) ??
				fromCpe.version,
			status: pickString(record, ["status", "state", "vulnerable"]) ?? "",
			cpe,
			versionStart,
			versionStartExclusive: versionStartExclusive !== undefined,
			versionEnd: versionEnd ?? versionEndExclusive,
			versionEndExclusive: versionEndExclusive !== undefined,
		});
	}
	return result;
}

function normalizeReferences(raw: unknown): CveReference[] {
	const result: CveReference[] = [];
	for (const item of asArray(raw)) {
		if (typeof item === "string") {
			const url = item.trim();
			if (url) result.push({ url, tags: [] });
			continue;
		}
		const record = asRecord(item);
		if (!record) continue;
		const url = pickString(record, ["url", "link", "href", "uri", "ref"]);
		if (!url) continue;
		result.push({ url, tags: pickStringList(record, ["tags", "tag", "type"]) });
	}
	return result;
}

function severityFor(score: number | undefined, provided: string | undefined): string {
	if (provided && provided.trim().length > 0) return provided.trim().toUpperCase();
	if (score === undefined) return "UNKNOWN";
	if (score >= 9) return "CRITICAL";
	if (score >= 7) return "HIGH";
	if (score >= 4) return "MEDIUM";
	if (score > 0) return "LOW";
	return "NONE";
}

/** Locate the CVSS data of a record, flat or nested the way NVD publishes it. */
function pickCvss(source: Record<string, unknown>): {
	score?: number;
	vector: string;
	severity: string;
} {
	const scoreKeys = ["cvss_score", "cvssScore", "cvss_base_score", "cvss_v3_score", "baseScore", "base_score", "score"];
	const vectorKeys = ["cvss_vector", "cvssVector", "vector", "vectorString", "cvss_v3_vector", "cvss_string"];
	const severityKeys = ["severity", "cvss_severity", "baseSeverity", "base_severity"];
	const candidates: Array<Record<string, unknown>> = [];
	const nestedCvss = asRecord(pickValue(source, ["cvss", "cvss_data", "cvssData"]));
	if (nestedCvss) candidates.push(nestedCvss);
	const metrics = asRecord(source.metrics);
	if (metrics) {
		for (const key of ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
			const metric = asArray(metrics[key])[0];
			const data = asRecord(asRecord(metric)?.cvssData);
			if (data) candidates.push(data);
		}
	}
	candidates.push(source);
	let score: number | undefined;
	let vector: string | undefined;
	let severity: string | undefined;
	for (const candidate of candidates) {
		if (score === undefined) score = pickNumber(candidate, scoreKeys);
		if (vector === undefined) vector = pickString(candidate, vectorKeys);
		if (severity === undefined) severity = pickString(candidate, severityKeys);
		if (score !== undefined && vector !== undefined && severity !== undefined) break;
	}
	return { score, vector: vector ?? "", severity: severity ?? "" };
}

/** Read the English description of a record. */
function pickDescription(source: Record<string, unknown>): string {
	const direct = pickString(source, ["description", "summary", "desc", "details"]);
	if (direct) return direct;
	for (const item of asArray(source.descriptions)) {
		const record = asRecord(item);
		if (!record) continue;
		const lang = pickString(record, ["lang", "language"]) ?? "en";
		if (!lang.toLowerCase().startsWith("en")) continue;
		const value = pickString(record, ["value", "description", "text"]);
		if (value) return value;
	}
	return "";
}

/** Turn a raw record of the CVE database into the normalised shape. */
export function normalizeCve(raw: unknown): CveEntry {
	const record = asRecord(raw) ?? {};
	const nested = asRecord(pickValue(record, ["cve", "vulnerability"]));
	const source =
		nested && pickString(nested, ["cve_id", "cveId", "id", "cve"]) !== undefined ? nested : record;
	const cvss = pickCvss(source);
	const cwes = pickStringList(source, ["cwe", "cwes", "cwe_ids", "cweIds", "weaknesses", "weakness"]);
	const cveId =
		pickString(source, ["cve_id", "cveId", "cveID", "id", "cve"]) ??
		pickString(record, ["cve_id", "cveId", "id"]) ??
		"";
	// The database publishes EPSS as an object and the KEV entry separately.
	const epssRecord = asRecord(source.epss);
	const kevEntry = asRecord(source.kev_entry);
	const epss =
		pickNumber(source, ["epss", "epss_score", "epssScore", "epss_percentage"]) ??
		(epssRecord ? pickNumber(epssRecord, ["score", "epss", "value"]) : undefined);
	const epssPercentile =
		pickNumber(source, ["epss_percentile", "epssPercentile", "percentile"]) ??
		(epssRecord ? pickNumber(epssRecord, ["percentile"]) : undefined);
	const kevDateAdded =
		pickString(source, ["kev_date_added", "kevDateAdded", "date_added", "dateAdded"]) ??
		(kevEntry ? pickString(kevEntry, ["date_added", "dateAdded"]) : undefined) ??
		"";
	return {
		cveId: cveId.toUpperCase(),
		description: pickDescription(source),
		cvssScore: cvss.score,
		cvssVector: cvss.vector,
		severity: severityFor(cvss.score, cvss.severity),
		cwes,
		products: normalizeProducts(
			pickValue(source, ["products", "affected_products", "affectedProducts", "affected", "configurations", "cpe_matches"]),
		),
		kev: pickBoolean(source, ["kev", "known_exploited", "cisa_kev", "in_kev", "kev_flag"]),
		kevDateAdded,
		kevName: kevEntry ? pickString(kevEntry, ["vuln_name", "name", "vulnName"]) ?? "" : "",
		kevDueDate: kevEntry ? pickString(kevEntry, ["due_date", "dueDate"]) ?? "" : "",
		kevRansomware: kevEntry ? pickString(kevEntry, ["ransomware"]) ?? "" : "",
		epss,
		epssPercentile,
		references: normalizeReferences(pickValue(source, ["references", "reference", "refs", "links"])),
		published: pickString(source, ["published", "published_date", "publishedDate", "published_at"]) ?? "",
		modified:
			pickString(source, ["modified", "modified_date", "modifiedDate", "last_modified", "lastModified"]) ?? "",
	};
}

/** Extract the list of CVEs carried by a database response. */
export function extractEntries(payload: unknown): CveEntry[] {
	if (Array.isArray(payload)) {
		return payload.map((item) => normalizeCve(item)).filter((entry) => entry.cveId.length > 0);
	}
	const record = asRecord(payload);
	if (!record) return [];
	for (const key of ["results", "cves", "entries", "items", "vulnerabilities", "data"]) {
		const value = record[key];
		if (Array.isArray(value)) {
			return value.map((item) => normalizeCve(item)).filter((entry) => entry.cveId.length > 0);
		}
	}
	const single = normalizeCve(record);
	return single.cveId.length > 0 ? [single] : [];
}

/* -------------------------------------------------------------------------- */
/* Rendering                                                                   */
/* -------------------------------------------------------------------------- */

function renderTable(headers: string[], rows: string[][]): string {
	const widths = headers.map((header, index) => {
		let width = header.length;
		for (const row of rows) width = Math.max(width, (row[index] ?? "").length);
		return width;
	});
	const renderRow = (cells: string[]): string =>
		cells.map((cell, index) => cell.padEnd(widths[index])).join("  ").trimEnd();
	const separator = widths.map((width) => "-".repeat(width)).join("  ");
	return [renderRow(headers), separator, ...rows.map(renderRow)].join("\n");
}

function formatScore(score: number | undefined): string {
	return score === undefined ? "-" : score.toFixed(1);
}

function formatEpss(value: number | undefined): string {
	return value === undefined ? "-" : value.toFixed(4);
}

function renderCveDetail(entry: CveEntry, includeReferences: boolean): string {
	const out: string[] = [];
	const headline = entry.cvssScore === undefined ? entry.severity : `${entry.severity} (CVSS ${entry.cvssScore.toFixed(1)})`;
	out.push(`${entry.cveId} — ${headline}`);
	if (entry.cvssVector) out.push(`Vector:    ${entry.cvssVector}`);
	out.push(`CWE:       ${entry.cwes.length > 0 ? entry.cwes.join(", ") : "not assigned"}`);
	out.push(
		entry.kev
			? `KEV:       yes — known exploited in the wild${entry.kevDateAdded ? ` (CISA catalog, added ${entry.kevDateAdded})` : ""}`
			: "KEV:       no",
	);
	if (entry.kev && entry.kevName) {
		const due = entry.kevDueDate ? `, remediation due ${entry.kevDueDate}` : "";
		const ransomware = entry.kevRansomware && entry.kevRansomware.toLowerCase() === "known" ? ", ransomware use known" : "";
		out.push(`           ${entry.kevName}${due}${ransomware}`);
	}
	if (entry.epss !== undefined) {
		const percentile =
			entry.epssPercentile === undefined ? "" : ` (percentile ${entry.epssPercentile.toFixed(4)})`;
		out.push(`EPSS:      ${entry.epss.toFixed(4)}${percentile}`);
	}
	out.push(
		`Published: ${entry.published || "unknown"}    Modified: ${entry.modified || "unknown"}`,
	);
	if (entry.description) {
		out.push("", "Description", entry.description.split(/\n+/).map((line) => `  ${line.trim()}`).join("\n"));
	}
	out.push("", `Affected products (${entry.products.length})`);
	if (entry.products.length === 0) {
		out.push("  none recorded");
	} else {
		for (const product of entry.products.slice(0, MAX_PRODUCTS_SHOWN)) {
			const name = [product.vendor, product.product].filter((part) => part.length > 0).join(" ") || "unknown product";
			const range = product.version || product.versionStart || product.versionEnd ? `  ${renderVersionRange(product)}` : "";
			const status = product.status ? ` (${product.status})` : "";
			out.push(`  ${name}${range}${status}`);
		}
		if (entry.products.length > MAX_PRODUCTS_SHOWN) {
			out.push(`  ... and ${entry.products.length - MAX_PRODUCTS_SHOWN} more`);
		}
	}
	if (includeReferences) {
		out.push("", `References (${entry.references.length})`);
		if (entry.references.length === 0) {
			out.push("  none recorded");
		} else {
			for (const reference of entry.references.slice(0, MAX_REFERENCES_SHOWN)) {
				const tags = reference.tags.length > 0 ? ` [${reference.tags.join(", ")}]` : "";
				out.push(`  ${reference.url}${tags}`);
			}
			if (entry.references.length > MAX_REFERENCES_SHOWN) {
				out.push(`  ... and ${entry.references.length - MAX_REFERENCES_SHOWN} more`);
			}
		}
	}
	return out.join("\n");
}

/* -------------------------------------------------------------------------- */
/* CVE database CLI                                                            */
/* -------------------------------------------------------------------------- */

let cvedbFlagsCache: Set<string> | undefined | null = null;

/**
 * Extract the option flags declared by a Python argparse CLI.
 *
 * The registry documents the flags, but the script is the authority at run
 * time: parsing `add_argument` calls keeps the tools working when the CLI
 * grows or loses an option instead of failing with an argparse error.
 */
export function parseCvedbFlags(source: string): Set<string> {
	const flags = new Set<string>();
	const pattern = /add_argument\(\s*((?:[^()"]|"[^"]*"|'[^']*')*)/g;
	let match = pattern.exec(source);
	while (match !== null) {
		for (const flag of match[1].match(/--[a-zA-Z0-9][a-zA-Z0-9-]*/g) ?? []) flags.add(flag);
		match = pattern.exec(source);
	}
	return flags;
}

/**
 * Read the option flags the bundled CLI actually accepts.
 *
 * Returns undefined when the script cannot be read or declares no options at
 * all; in that case every documented flag is passed through unchanged.
 */
function cvedbFlags(): Set<string> | undefined {
	if (cvedbFlagsCache !== null) return cvedbFlagsCache;
	let source: string;
	try {
		source = fs.readFileSync(CVEDB_SCRIPT, "utf8");
	} catch {
		cvedbFlagsCache = undefined;
		return undefined;
	}
	const flags = parseCvedbFlags(source);
	if (flags.size === 0) {
		cvedbFlagsCache = undefined;
		return undefined;
	}
	cvedbFlagsCache = flags;
	return flags;
}

/**
 * Build a CLI argument list, dropping flags the bundled script does not know.
 *
 * `flags` defaults to the flags detected in the bundled script; pass `null`
 * to keep every flag.
 */
export function buildCvedbArgs(
	parts: Array<string | FlagArg>,
	flags: Set<string> | null | undefined = cvedbFlags(),
): string[] {
	const result: string[] = [];
	for (const part of parts) {
		if (typeof part === "string") {
			result.push(part);
			continue;
		}
		if (flags && !flags.has(part.flag)) continue;
		result.push(part.flag);
		if (part.value !== undefined) result.push(part.value);
	}
	return result;
}

async function runCvedb(
	args: string[],
	options: { cwd: string; timeoutMs: number; artifactName?: string; maxBytes?: number },
): Promise<RunResult> {
	return run("python3", [CVEDB_SCRIPT, ...args], {
		cwd: options.cwd,
		timeoutMs: options.timeoutMs,
		maxBytes: options.maxBytes ?? 2_000_000,
		artifactDir: engagementPaths(options.cwd).artifacts,
		artifactName: options.artifactName,
	});
}

/** Read the counters a sync reports. */
export interface SyncDescription {
	ingested: number;
	total: number;
	kev: number;
	epss: number;
	pages: number;
	duration?: number;
	database: string;
	lastSync: string;
}

/** Describe the outcome of a `cvedb.py sync` run. */
export function describeSync(payload: unknown): SyncDescription {
	const record = asRecord(payload) ?? {};
	const nvd = asRecord(record.nvd) ?? {};
	const counts = asRecord(record.counts) ?? {};
	const ingested = pickNumber(nvd, ["cves", "ingested"]) ?? 0;
	const total = pickNumber(counts, ["cves"]) ?? ingested;
	const database =
		pickString(record, ["database", "database_path", "db_path", "database_file", "db"]) ?? cveDatabasePath();
	const lastSync =
		pickString(record, ["finished_at", "finishedAt", "last_sync", "last_sync_at", "completed_at"]) ??
		databaseLastModified(database);
	return {
		ingested,
		total,
		kev: pickNumber(counts, ["kev"]) ?? 0,
		epss: pickNumber(counts, ["epss"]) ?? 0,
		pages: pickNumber(nvd, ["pages"]) ?? 0,
		duration: pickNumber(record, ["duration_seconds"]),
		database,
		lastSync: lastSync || "unknown",
	};
}

/** The most useful error text a failed command produced. */
function errorMessage(result: RunResult): string {
	const record = asRecord(parseJson<unknown>(result.stdout));
	const message = record ? pickString(record, ["error", "message"]) : undefined;
	if (message) return message;
	const stderr = result.stderr.trim();
	if (stderr.length > 0) return stderr;
	const stdout = result.stdout.trim();
	return stdout.length > 0 ? stdout : `exit code ${result.code}`;
}

function databaseLastModified(databasePath: string): string {
	try {
		const stats = fs.statSync(databasePath);
		return stats.mtime.toISOString();
	} catch {
		return "";
	}
}

/* -------------------------------------------------------------------------- */
/* Exploit reference parsing                                                   */
/* -------------------------------------------------------------------------- */

function stripAnsi(text: string): string {
	return text.replace(/\u001b\[[0-9;]*[A-Za-z]/g, "");
}

/** Parse the textual output of `searchsploit`. */
export function parseSearchsploit(text: string): SearchsploitHit[] {
	const hits: SearchsploitHit[] = [];
	const chunks = text.split(/EDB-ID:\s*/i).slice(1);
	for (const chunk of chunks) {
		const chunkLines = chunk.split("\n");
		const id = (chunkLines[0] ?? "").trim();
		if (!id) continue;
		let title = "";
		let file = "";
		for (const line of chunkLines.slice(1)) {
			if (!title) {
				const titleMatch = /^Title:\s*(.+)$/i.exec(line);
				if (titleMatch) {
					title = titleMatch[1].trim();
					continue;
				}
			}
			if (!file) {
				const fileMatch = /^(?:File|Path):\s*(.+)$/i.exec(line);
				if (fileMatch) {
					file = fileMatch[1].trim();
					continue;
				}
			}
		}
		hits.push({
			id,
			title,
			path: file,
			url: /^\d+$/.test(id) ? `https://www.exploit-db.com/exploits/${id}` : "",
		});
	}
	return hits;
}

/** Parse the textual output of `msfconsole -q -x "search ..."`. */
export function parseMetasploit(text: string): MetasploitModule[] {
	const modules: MetasploitModule[] = [];
	for (const rawLine of stripAnsi(text).split("\n")) {
		const line = rawLine.trim();
		if (line.length === 0) continue;
		if (/^(Matching Modules|Showing|Refreshing|No results|No modules|Usage:)/i.test(line)) continue;
		if (/^[=\-]{3,}$/.test(line)) continue;
		const parts = line.split(/\s{2,}/);
		if (parts.length < 2) continue;
		if (!/^\d+$/.test(parts[0])) continue;
		const modulePath = parts[1];
		if (!modulePath.includes("/")) continue;
		modules.push({
			path: modulePath,
			disclosure: /^\d{4}-\d{2}-\d{2}$/.test(parts[2] ?? "") ? parts[2] : "",
			rank: parts[3] ?? "",
			description: parts.slice(4).join(" ").trim(),
		});
	}
	return modules;
}

function truncateCell(value: string, max: number): string {
	if (value.length <= max) return value;
	return `${value.slice(0, Math.max(0, max - 1))}…`;
}

/* -------------------------------------------------------------------------- */
/* Query parsing                                                               */
/* -------------------------------------------------------------------------- */

interface ParsedQuery {
	kind: "cve" | "cpe" | "product";
	raw: string;
	cveId?: string;
	cpe?: string;
	product?: string;
	version?: string;
}

function parseQuery(raw: string): ParsedQuery {
	const value = raw.trim();
	if (CVE_ID_PATTERN.test(value)) {
		return { kind: "cve", raw: value, cveId: value.toUpperCase() };
	}
	if (NUMERIC_CVE_PATTERN.test(value)) {
		return { kind: "cve", raw: value, cveId: `CVE-${value}` };
	}
	if (CPE_PATTERN.test(value)) {
		return { kind: "cpe", raw: value, cpe: value };
	}
	const versionMatch = /^(.*?)[\s_-]+(\d+(?:\.\d+)*(?:[-+][A-Za-z0-9.]+)?)$/.exec(value);
	if (versionMatch && versionMatch[1].trim().length > 0) {
		return {
			kind: "product",
			raw: value,
			product: versionMatch[1].trim(),
			version: versionMatch[2].trim(),
		};
	}
	return { kind: "product", raw: value, product: value };
}

/**
 * The terms a product query is matched against.
 *
 * The database matches a product term against the vendor and the product
 * name separately, so "apache log4j" only matches when the terms are tried
 * one by one.
 */
function productTerms(product: string): string[] {
	const terms: string[] = [];
	const push = (value: string): void => {
		const trimmed = value.trim().toLowerCase();
		if (trimmed.length > 0 && !terms.includes(trimmed)) terms.push(trimmed);
	};
	push(product);
	for (const word of product.split(/[\s_]+/)) push(word);
	return terms;
}

/** How well an advisory matches the terms of a product query. */
function matchScore(entry: CveEntry, terms: string[]): number {
	let best = 0;
	for (const product of entry.products) {
		const vendor = product.vendor.toLowerCase();
		const name = product.product.toLowerCase();
		for (const term of terms) {
			if (name === term) best = Math.max(best, 4);
			else if (vendor === term) best = Math.max(best, 3);
			else if (name.includes(term)) best = Math.max(best, 2);
			else if (vendor.includes(term)) best = Math.max(best, 1);
		}
	}
	return best;
}

/** The affected product that matches the query best. */
function bestProduct(entry: CveEntry, terms: string[]): string {
	let chosen = "";
	let best = -1;
	for (const product of entry.products) {
		const name = [product.vendor, product.product].filter((part) => part.length > 0).join(" ");
		if (name.length === 0) continue;
		const vendor = product.vendor.toLowerCase();
		const productName = product.product.toLowerCase();
		let score = 0;
		for (const term of terms) {
			if (productName === term) score = Math.max(score, 4);
			else if (vendor === term) score = Math.max(score, 3);
			else if (productName.includes(term)) score = Math.max(score, 2);
			else if (vendor.includes(term)) score = Math.max(score, 1);
		}
		if (score > best) {
			best = score;
			chosen = name;
		}
	}
	if (chosen.length > 0) return chosen;
	const first = entry.products[0];
	return first
		? [first.vendor, first.product].filter((part) => part.length > 0).join(" ") || entry.cveId
		: "-";
}

/** Search the database for a product and rank the hits by match quality. */
async function searchProductEntries(cwd: string, product: string, limit: number): Promise<CveEntry[]> {
	const terms = productTerms(product);
	const collected = new Map<string, CveEntry>();
	for (const term of terms) {
		const result = await runCvedb(
			buildCvedbArgs([
				"search",
				{ flag: "--product", value: term },
				{ flag: "--limit", value: String(limit) },
				{ flag: "--json" },
			]),
			{ cwd, timeoutMs: 120_000, artifactName: "exploit-map-db.json", maxBytes: 8_000_000 },
		);
		if (result.code !== 0) continue;
		for (const entry of extractEntries(parseJson<unknown>(result.stdout))) {
			if (!collected.has(entry.cveId)) collected.set(entry.cveId, entry);
		}
	}
	return [...collected.values()]
		.sort((left, right) => {
			const score = matchScore(right, terms) - matchScore(left, terms);
			if (score !== 0) return score;
			const cvss = (right.cvssScore ?? 0) - (left.cvssScore ?? 0);
			if (cvss !== 0) return cvss;
			return right.cveId.localeCompare(left.cveId);
		})
		.slice(0, limit);
}

/**
 * Find the CVEs the database lists for an exact product version.
 *
 * The database keeps the CPE of every affected product, so a version is
 * confirmed when the CPE of that version exists.
 */
async function confirmAffectedVersions(
	cwd: string,
	entries: CveEntry[],
	version: string,
): Promise<Set<string>> {
	const confirmed = new Set<string>();
	const products = new Map<string, { vendor: string; product: string }>();
	for (const entry of entries) {
		for (const product of entry.products) {
			if (product.vendor.length === 0 || product.product.length === 0) continue;
			const key = `${product.vendor}:${product.product}`;
			if (!products.has(key)) products.set(key, { vendor: product.vendor, product: product.product });
		}
	}
	let examined = 0;
	for (const product of products.values()) {
		if (examined >= MAX_VERSION_PRODUCTS) break;
		examined += 1;
		for (const part of ["a", "o", "h"]) {
			const cpe = `cpe:2.3:${part}:${product.vendor}:${product.product}:${version}`;
			const result = await runCvedb(
				buildCvedbArgs([
					"search",
					{ flag: "--cpe", value: cpe },
					{ flag: "--limit", value: String(MAX_VERSION_LOOKUP) },
					{ flag: "--json" },
				]),
				{ cwd, timeoutMs: 120_000, maxBytes: 8_000_000 },
			);
			if (result.code !== 0) continue;
			for (const entry of extractEntries(parseJson<unknown>(result.stdout))) {
				confirmed.add(entry.cveId);
			}
		}
	}
	return confirmed;
}

/* -------------------------------------------------------------------------- */
/* Tools                                                                       */
/* -------------------------------------------------------------------------- */

export const cveTools: ToolDefinition[] = [
	defineCyberTool({
		name: "cyber_cve_lookup",
		label: "CVE lookup",
		description:
			"Look up a single CVE in the offline CyberPi CVE database (NVD, CISA KEV and FIRST EPSS). " +
			"Returns the description, CVSS score and vector, severity, CWE, the affected products with their " +
			"version ranges when the database records them, the KEV flag, the EPSS score, the references and " +
			"the published/modified dates.",
		promptSnippet: "cyber_cve_lookup: offline CVE detail lookup with CVSS vector, CISA KEV and EPSS",
		technique: "vulnerability-scan",
		requires: ["python3"],
		installHint: "Install Python 3 on Kali with: sudo apt install -y python3",
		parameters: Type.Object({
			cve_id: Type.String({ description: "CVE identifier, for example CVE-2021-44228" }),
			include_references: Type.Optional(
				Type.Boolean({ description: "Include the reference URL list (default true)" }),
			),
		}),
		cacheTtlMs: 3_600_000,
		timeoutMs: 60_000,
		build: (params) => ({
			bin: "python3",
			args: [CVEDB_SCRIPT, ...buildCvedbArgs(["get", params.cve_id.trim(), { flag: "--json" }])],
			label: "cve-lookup",
		}),
		summarize: (results, params): CyberToolSummary<CveLookupDetails> => {
			const result = results[0];
			const cveId = params.cve_id.trim().toUpperCase();
			if (!result) {
				return { summary: "No CVE database query was executed.", isError: true };
			}
			if (result.timedOut) {
				return {
					summary: `The CVE database did not answer within the 60s lookup timeout for ${cveId}.`,
					isError: true,
				};
			}
			if (result.code !== 0) {
				return {
					summary: `CVE database lookup for ${cveId} failed (exit ${result.code}).`,
					output: errorMessage(result),
					isError: true,
				};
			}
			if (!CVE_ID_PATTERN.test(cveId)) {
				return {
					summary: `"${params.cve_id}" is not a CVE identifier. Use the form CVE-YYYY-NNNN.`,
					isError: true,
				};
			}
			const payload = parseJson<unknown>(result.stdout);
			const entries = extractEntries(payload);
			if (entries.length === 0) {
				return {
					summary: `CVE ${cveId} is not in the local database. Run cyber_cve_sync to refresh it.`,
					output: result.stdout.trim().slice(0, 2000),
					isError: true,
				};
			}
			const entry = entries[0];
			const details: CveLookupDetails = {
				cveId: entry.cveId,
				description: entry.description,
				severity: entry.severity,
				cvssScore: entry.cvssScore,
				cvssVector: entry.cvssVector,
				cwes: entry.cwes,
				kev: entry.kev,
				epss: entry.epss,
				products: entry.products,
				references: entry.references,
				published: entry.published,
				modified: entry.modified,
			};
			const includeReferences = params.include_references !== false;
			return {
				summary:
					`${entry.cveId}: ${entry.severity}` +
					`${entry.cvssScore === undefined ? "" : ` (CVSS ${entry.cvssScore.toFixed(1)})`}` +
					`${entry.kev ? " — known exploited in the wild (CISA KEV)" : ""}` +
					`${entry.epss === undefined ? "" : ` — EPSS ${entry.epss.toFixed(4)}`}`,
				output: renderCveDetail(entry, includeReferences),
				details,
				severity: entry.kev ? "high" : entry.cvssScore !== undefined && entry.cvssScore >= 7 ? "medium" : "info",
			};
		},
	}),

	defineCyberTool({
		name: "cyber_cve_sync",
		label: "CVE database sync",
		description:
			"Synchronise the offline CVE database with the NVD catalogue, the CISA KEV catalog and FIRST " +
			"EPSS scores. Reports how many CVEs were ingested, the KEV and EPSS counts, the database path " +
			"and the last sync time. Can take many minutes.",
		promptSnippet: "cyber_cve_sync: refresh the offline CVE database (NVD, CISA KEV, EPSS)",
		technique: "vulnerability-scan",
		requires: ["python3"],
		installHint: "Install Python 3 on Kali with: sudo apt install -y python3",
		parameters: Type.Object({
			full: Type.Optional(
				Type.Boolean({ description: "Re-download the complete NVD catalogue instead of recent changes" }),
			),
			include_kev: Type.Optional(
				Type.Boolean({ description: "Include the CISA Known Exploited Vulnerabilities catalog (default true)" }),
			),
			include_epss: Type.Optional(
				Type.Boolean({ description: "Include FIRST EPSS exploit prediction scores (default true)" }),
			),
			pages: Type.Optional(Type.Number({ description: "Maximum number of NVD API pages to fetch" })),
		}),
		timeoutMs: 900_000,
		build: (params) => {
			const args: Array<string | FlagArg> = ["sync"];
			if (params.full === true) args.push({ flag: "--full" });
			if (params.include_kev === false) args.push({ flag: "--no-kev" });
			if (params.include_epss === false) args.push({ flag: "--no-epss" });
			if (params.pages !== undefined && Number.isFinite(params.pages)) {
				args.push({ flag: "--pages", value: String(Math.trunc(params.pages)) });
			}
			return {
				bin: "python3",
				args: [CVEDB_SCRIPT, ...buildCvedbArgs(args)],
				label: "cve-sync",
			};
		},
		summarize: (results, params): CyberToolSummary<CveSyncDetails> => {
			const result = results[0];
			if (!result) {
				return { summary: "No CVE database sync was executed.", isError: true };
			}
			if (result.timedOut) {
				return {
					summary: "The CVE database sync timed out before it finished. Run it again to resume.",
					isError: true,
				};
			}
			if (result.code !== 0) {
				return {
					summary: `CVE database sync failed (exit ${result.code}).`,
					output: errorMessage(result),
					isError: true,
				};
			}
			const payload = parseJson<unknown>(result.stdout);
			const sync = describeSync(payload);
			const details: CveSyncDetails = {
				cves: sync.total,
				kev: sync.kev,
				epss: sync.epss,
				database: sync.database,
				lastSync: sync.lastSync,
				full: params.full === true,
				includeKev: params.include_kev !== false,
				includeEpss: params.include_epss !== false,
				pages: params.pages,
			};
			const out: string[] = [];
			out.push(`CVE database synced: ${sync.ingested} CVEs ingested (${sync.total} in the database).`);
			out.push(`  KEV entries:  ${sync.kev}`);
			out.push(`  EPSS scores:  ${sync.epss}`);
			out.push(`  Database:     ${sync.database}`);
			out.push(`  Last sync:    ${sync.lastSync}`);
			if (sync.pages > 0) out.push(`  NVD pages:    ${sync.pages}`);
			if (sync.duration !== undefined) out.push(`  Duration:     ${sync.duration}s`);
			if (params.full === true) out.push("  Mode:         full catalogue refresh");
			if (params.include_kev === false) out.push("  KEV catalog:  skipped");
			if (params.include_epss === false) out.push("  EPSS scores:  skipped");
			const flags = cvedbFlags();
			if (params.pages !== undefined && flags && !flags.has("--pages")) {
				out.push("  Note: the bundled cvedb.py does not support --pages, the page limit was ignored.");
			}
			return {
				summary:
					`CVE database synced: ${sync.ingested} CVEs ingested, ${sync.total} in the database, ` +
					`${sync.kev} KEV, ${sync.epss} EPSS.`,
				output: out.join("\n"),
				details,
			};
		},
	}),

	defineCyberTool({
		name: "cyber_exploit_map",
		label: "Exploit map",
		description:
			"Map a CVE, a product or a product version to the exploits that are known for it. Queries the " +
			"local CVE database and cross-references searchsploit (exploit-db) and Metasploit, then reports " +
			"CVSS, the CISA KEV flag, EPSS, the exploit references and whether a public exploit exists.",
		promptSnippet: "cyber_exploit_map: map a CVE, product or version to known public exploits",
		technique: "exploit",
		requires: ["python3"],
		installHint:
			"Install Python 3 on Kali with: sudo apt install -y python3; add exploitdb and metasploit-framework for exploit references",
		parameters: Type.Object({
			query: Type.String({
				description: "A CVE id (CVE-2021-44228), a product name (apache log4j) or a CPE (cpe:2.3:a:...)",
			}),
			limit: Type.Optional(Type.Number({ description: "Maximum number of CVEs to map (default 25)" })),
			include_metasploit: Type.Optional(
				Type.Boolean({ description: "Cross-reference Metasploit modules (default true)" }),
			),
		}),
		timeoutMs: 600_000,
		execute: async (params, ctx): Promise<CyberToolOutcome<ExploitMapDetails>> => {
			const cwd = ctx.cwd;
			const parsed = parseQuery(params.query);
			const limit = Math.min(Math.max(Math.trunc(params.limit ?? 25), 1), 200);
			const includeMetasploit = params.include_metasploit !== false;
			const terms = parsed.product ? productTerms(parsed.product) : [];

			let entries: CveEntry[] = [];
			if (parsed.kind === "cve") {
				const dbResult = await runCvedb(
					buildCvedbArgs(["get", parsed.cveId ?? parsed.raw, { flag: "--json" }]),
					{ cwd, timeoutMs: 120_000, artifactName: "exploit-map-db.json", maxBytes: 8_000_000 },
				);
				if (dbResult.timedOut) {
					return { summary: "The CVE database did not answer in time.", isError: true };
				}
				if (dbResult.code !== 0) {
					return {
						summary: `CVE database query failed (exit ${dbResult.code}).`,
						output: dbResult.stderr.trim() || dbResult.stdout.trim() || "no output",
						isError: true,
					};
				}
				entries = extractEntries(parseJson<unknown>(dbResult.stdout));
			} else if (parsed.kind === "cpe") {
				const dbResult = await runCvedb(
					buildCvedbArgs([
						"by-cpe",
						parsed.cpe ?? parsed.raw,
						{ flag: "--limit", value: String(limit) },
						{ flag: "--json" },
					]),
					{ cwd, timeoutMs: 120_000, artifactName: "exploit-map-db.json", maxBytes: 8_000_000 },
				);
				if (dbResult.timedOut) {
					return { summary: "The CVE database did not answer in time.", isError: true };
				}
				if (dbResult.code !== 0) {
					return {
						summary: `CVE database query failed (exit ${dbResult.code}).`,
						output: dbResult.stderr.trim() || dbResult.stdout.trim() || "no output",
						isError: true,
					};
				}
				entries = extractEntries(parseJson<unknown>(dbResult.stdout));
			} else {
				entries = await searchProductEntries(cwd, parsed.product ?? parsed.raw, limit);
			}

			if (entries.length === 0) {
				return {
					summary: `No CVEs in the local database match "${parsed.raw}". Run cyber_cve_sync to refresh it.`,
					isError: true,
				};
			}
			if (parsed.version) {
				entries = entries.filter((entry) => versionVerdict(entry, parsed.version as string) !== "not-affected");
			}
			entries = entries.slice(0, limit);

			// A version is only confirmed when the database holds the CPE of that
			// exact product version; the CVE table itself stores no ranges.
			const versionConfirmed = parsed.version
				? await confirmAffectedVersions(cwd, entries, parsed.version)
				: new Set<string>();

			const searchsploitPath = which("searchsploit");
			const msfconsolePath = which("msfconsole");
			const plans: RunPlan[] = [];
			const planOwners: Array<{ cveId: string; kind: "searchsploit" | "metasploit" }> = [];
			for (const entry of entries) {
				if (searchsploitPath) {
					plans.push({ bin: "searchsploit", args: [entry.cveId] });
					planOwners.push({ cveId: entry.cveId, kind: "searchsploit" });
				}
				if (includeMetasploit && msfconsolePath) {
					const numeric = entry.cveId.replace(/^CVE-/i, "");
					plans.push({ bin: "msfconsole", args: ["-q", "-x", `search cve:${numeric}`] });
					planOwners.push({ cveId: entry.cveId, kind: "metasploit" });
				}
			}

			const searchResults: RunResult[] = [];
			for (let index = 0; index < plans.length; index += EXPLOIT_SEARCH_CONCURRENCY) {
				const batch = plans.slice(index, index + EXPLOIT_SEARCH_CONCURRENCY);
				const results = await runMany(batch, { cwd, timeoutMs: 120_000 });
				searchResults.push(...results);
			}

			const exploitdbHits = new Map<string, SearchsploitHit[]>();
			const metasploitHits = new Map<string, MetasploitModule[]>();
			searchResults.forEach((result, index) => {
				const owner = planOwners[index];
				if (!owner) return;
				if (result.code !== 0 && !result.stdout.trim()) return;
				if (owner.kind === "searchsploit") {
					const hits = parseSearchsploit(result.stdout);
					if (hits.length > 0) exploitdbHits.set(owner.cveId, hits);
				} else {
					const modules = parseMetasploit(result.stdout);
					if (modules.length > 0) metasploitHits.set(owner.cveId, modules);
				}
			});

			const rows: ExploitMapRow[] = entries.map((entry) => {
				const dbHits = exploitdbHits.get(entry.cveId) ?? [];
				const msfHits = metasploitHits.get(entry.cveId) ?? [];
				const productName = bestProduct(entry, terms);
				const publicExploit = dbHits.length > 0 || msfHits.length > 0;
				let verdict = "no public exploit found";
				if (entry.kev) verdict = "yes — exploited in the wild (CISA KEV)";
				else if (dbHits.length > 0 && msfHits.length > 0) verdict = "yes — exploit-db and Metasploit";
				else if (dbHits.length > 0) verdict = "yes — exploit-db";
				else if (msfHits.length > 0) verdict = "yes — Metasploit";
				let versionStatus = "";
				if (parsed.version) {
					versionStatus = versionConfirmed.has(entry.cveId) ? "affected" : "not listed";
				}
				return {
					cveId: entry.cveId,
					product: productName,
					version: parsed.version,
					versionStatus,
					cvss: entry.cvssScore,
					severity: entry.severity,
					kev: entry.kev,
					epss: entry.epss,
					exploitdb: dbHits.map((hit) => `EDB-${hit.id}`),
					metasploit: msfHits.map((module) => module.path),
					publicExploit,
					verdict,
				};
			});

			const sources: string[] = ["cve database"];
			if (searchsploitPath) sources.push("searchsploit (exploit-db)");
			else sources.push("searchsploit not installed — exploit-db references skipped");
			if (includeMetasploit) {
				if (msfconsolePath) sources.push("metasploit (msfconsole)");
				else sources.push("msfconsole not installed — Metasploit references skipped");
			} else {
				sources.push("metasploit skipped by request");
			}

			const artifact = writeExploitMapArtifact(cwd, {
				query: parsed.raw,
				kind: parsed.kind,
				version: parsed.version,
				rows,
				sources,
			});

			const exploitable = rows.filter((row) => row.publicExploit).length;
			const headers = ["CVE", "PRODUCT"];
			if (parsed.version) headers.push("VERSION");
			headers.push("CVSS", "KEV", "EPSS", "EXPLOIT REFERENCE", "PUBLIC EXPLOIT");
			const table = renderTable(
				headers,
				rows.map((row) => {
					const references = [
						...row.exploitdb.map((id) => `exploitdb:${id}`),
						...row.metasploit.map((module) => `msf:${module}`),
					];
					const cells = [row.cveId, truncateCell(row.product, 28)];
					if (parsed.version) cells.push(row.versionStatus || "-");
					cells.push(
						formatScore(row.cvss),
						row.kev ? "yes" : "no",
						formatEpss(row.epss),
						truncateCell(references.length > 0 ? references.join(", ") : "-", 46),
						row.verdict,
					);
					return cells;
				}),
			);

			const out: string[] = [];
			out.push(
				`Mapped ${rows.length} CVE${rows.length === 1 ? "" : "s"} for "${parsed.raw}"` +
					`${parsed.version ? ` (version ${parsed.version})` : ""}.` +
					` ${exploitable} with a public exploit, ${rows.filter((row) => row.kev).length} in the CISA KEV catalog.`,
			);
			out.push("");
			out.push(table);
			out.push("");
			if (parsed.version) {
				out.push(
					`Version ${parsed.version} is confirmed when the database holds the CPE of that exact product version; ` +
						"a blank entry only means the version is not listed, not that the product is unaffected.",
				);
				out.push("");
			}
			out.push(`Sources: ${sources.join(", ")}.`);
			if (artifact) out.push(`Full result: ${artifact}`);

			return {
				summary:
					`Exploit map for "${parsed.raw}": ${rows.length} CVE${rows.length === 1 ? "" : "s"}, ` +
					`${exploitable} with a public exploit, ${rows.filter((row) => row.kev).length} known exploited in the wild.`,
				output: out.join("\n"),
				details: {
					query: parsed.raw,
					kind: parsed.kind,
					version: parsed.version,
					rows,
					artifact,
					sources,
				},
				severity: exploitable > 0 ? "high" : "info",
			};
		},
	}),
];

/** Persist the structured exploit map next to the other engagement artifacts. */
function writeExploitMapArtifact(
	cwd: string,
	payload: {
		query: string;
		kind: string;
		version?: string;
		rows: ExploitMapRow[];
		sources: string[];
	},
): string | undefined {
	try {
		const artifacts = engagementPaths(cwd).artifacts;
		ensureDir(artifacts);
		const stem = payload.query.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "query";
		const target = path.join(artifacts, `exploit-map-${stem}.json`);
		fs.writeFileSync(target, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
		return target;
	} catch {
		return undefined;
	}
}
