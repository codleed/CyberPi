/**
 * Web application tools: HTTP probing, crawling and content discovery.
 *
 * Every tool runs a real scanner from the Kali toolchain, parses its structured
 * output and merges what it finds into the engagement surface index, so later
 * questions about the target are answered from `surface.json` instead of from
 * another scan.
 */

import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";

import { Type } from "@earendil-works/pi-ai";
import type { ToolDefinition } from "@earendil-works/pi-coding-agent";
import type { Static } from "typebox";

import { ensureDir, engagementPaths } from "../lib/config.ts";
import { checkTarget, loadScope } from "../lib/scope.ts";
import { addEndpoints } from "../lib/surface.ts";
import { defineCyberTool, lines, parseJson, parseJsonLines } from "../lib/toolkit.ts";

const DEFAULT_HTTP_THREADS = 50;
const DEFAULT_CRAWL_DEPTH = 3;
const DEFAULT_FFUF_THREADS = 40;
const DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt";

/** How many individual findings are listed before the list is cut short. */
const MAX_LISTED = 50;

/**
 * The engagement directory the current session runs in.
 *
 * `build` records it before `summarize` reads it; the session working
 * directory does not change in between, so the two always agree.
 */
let cwd = process.cwd();

interface HttpProbeEndpoint {
	url: string;
	status?: number;
	title?: string;
	technology?: string[];
	webserver?: string;
	screenshot?: string;
}

interface HttpProbeDetails {
	/** Number of targets handed to httpx. */
	total: number;
	/** Targets that answered. */
	reachable: number;
	/** Targets that did not answer. */
	unreachable: number;
	/** Every live URL httpx reported. */
	endpoints: HttpProbeEndpoint[];
}

interface CrawlDetails {
	/** URLs reported by the crawler, duplicates included. */
	total: number;
	/** Distinct URLs. */
	unique: number;
	byExtension: Record<string, number>;
	byStatus: Record<string, number>;
	urls: Array<{ url: string; status?: number; technology?: string[] }>;
}

interface DirEnumDetails {
	/** Number of ffuf hits. */
	hits: number;
	wordlist: string;
	/** The fuzzed URL. */
	url: string;
	results: Array<{ url: string; path: string; status?: number; size?: number; word?: string }>;
}

/** One httpx JSONL record. */
interface HttpxResult {
	url?: string;
	input?: string;
	host?: string;
	port?: string | number;
	scheme?: string;
	status_code?: number | string;
	title?: string;
	webserver?: string;
	tech?: string[];
	content_type?: string;
	content_length?: number;
	screenshot_path?: string;
	final_url?: string;
	location?: string;
}

/** One katana JSONL record. */
interface KatanaResult {
	timestamp?: string;
	request?: { method?: string; endpoint?: string; url?: string; tag?: string };
	response?: { status_code?: number; body?: string; technologies?: string[]; tech?: string[]; content_length?: number };
}

/** One ffuf JSON record. */
interface FfufResult {
	input?: { FUZZ?: string };
	position?: number;
	status?: number;
	length?: number;
	words?: number;
	lines?: number;
	"content-type"?: string;
	redirectlocation?: string;
	url?: string;
	duration?: number;
	host?: string;
	method?: string;
}

/** The document ffuf writes with `-of json`. */
interface FfufJsonFile {
	commandline?: string;
	time?: string;
	results?: FfufResult[];
}

/** Coerce a JSON value into a finite number. */
function toNumber(value: unknown): number | undefined {
	if (typeof value === "number" && Number.isFinite(value)) return value;
	if (typeof value === "string" && value.trim().length > 0) {
		const parsed = Number(value);
		if (Number.isFinite(parsed)) return parsed;
	}
	return undefined;
}

/** Coerce a JSON value into a trimmed string. */
function toText(value: unknown): string | undefined {
	if (typeof value === "string" && value.trim().length > 0) return value.trim();
	return undefined;
}

/** Hostname of an absolute URL, lowercased. */
function hostFromUrl(url: string): string {
	try {
		return new URL(url).hostname.toLowerCase();
	} catch {
		return url.split("/")[0].split(":")[0].toLowerCase();
	}
}

/** Path of an absolute URL. */
function pathFromUrl(url: string): string {
	try {
		return new URL(url).pathname;
	} catch {
		const withoutQuery = url.split("?")[0].split("#")[0];
		const index = withoutQuery.indexOf("/", withoutQuery.indexOf("//") + 2);
		return index === -1 ? "/" : withoutQuery.slice(index);
	}
}

/** Lowercase file extension of a URL path, or `none`. */
function extensionFromUrl(url: string): string {
	const last = pathFromUrl(url).split("/").filter(Boolean).pop() ?? "";
	const dot = last.lastIndexOf(".");
	if (dot <= 0) return "none";
	return last.slice(dot + 1).toLowerCase();
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

/** Read a list of URLs, one per line, from a file. */
function readUrlList(file: string): string[] {
	if (!fs.existsSync(file)) {
		throw new Error(`urls_file not found: ${file}`);
	}
	return lines(fs.readFileSync(file, "utf8")).filter((line) => !line.startsWith("#"));
}

/** Number of URLs in a list file, or zero when it cannot be read. */
function urlListCount(file: string): number {
	try {
		return readUrlList(file).length;
	} catch {
		return 0;
	}
}

/**
 * Fail closed when a target is not authorized.
 *
 * The toolkit scope-checks the primary target of a call; a list of URLs needs
 * every entry checked before the scanner is started.
 */
function assertAuthorized(cwd: string, targets: string[], technique: string): void {
	const scope = loadScope(cwd);
	for (const target of targets) {
		const decision = checkTarget(scope, target, { technique });
		if (!decision.allowed) {
			throw new Error(`Blocked by engagement scope: ${decision.reason}`);
		}
	}
}

/** Parse the JSON document ffuf writes, tolerating a banner around it. */
function parseFfufResults(text: string): FfufResult[] {
	const document = parseJson<FfufJsonFile | FfufResult[]>(text);
	if (Array.isArray(document)) return document;
	if (document && typeof document === "object") {
		const record = document as FfufJsonFile & FfufResult;
		if (Array.isArray(record.results)) return record.results;
		if (typeof record.url === "string") return [record];
	}
	const start = text.indexOf("[");
	const end = text.lastIndexOf("]");
	if (start !== -1 && end > start) {
		const slice = parseJson<FfufResult[]>(text.slice(start, end + 1));
		if (Array.isArray(slice)) return slice;
	}
	return [];
}

/**
 * Where ffuf writes its JSON report inside the engagement artifacts.
 *
 * The name carries a digest of the request so that two enumeration runs do
 * not overwrite each other's report.
 */
function dirEnumOutputPath(cwd: string, params: Static<typeof dirEnumParams>): string {
	const key = JSON.stringify([
		params.target,
		params.wordlist ?? "",
		params.extensions ?? "",
		params.threads ?? 0,
		params.match_size ?? "",
		params.status_codes ?? "",
	]);
	const stamp = createHash("sha1").update(key).digest("hex").slice(0, 8);
	return path.join(ensureDir(engagementPaths(cwd).artifacts), `dir_enum-${stamp}.json`);
}

/** Turn a base URL into a ffuf target that carries the FUZZ keyword. */
function fuzzUrl(target: string): string {
	if (target.includes("FUZZ")) return target;
	const trimmed = target.endsWith("/") ? target.slice(0, -1) : target;
	return `${trimmed}/FUZZ`;
}

const httpProbeParams = Type.Object({
	target: Type.Optional(Type.String({ description: "URL to probe, e.g. https://example.com" })),
	urls_file: Type.Optional(Type.String({ description: "File with one URL per line to probe instead of a single target" })),
	ports: Type.Optional(Type.String({ description: "Ports to probe, e.g. 80,443,8080" })),
	threads: Type.Optional(Type.Number({ description: `Concurrent threads (default ${DEFAULT_HTTP_THREADS})` })),
	follow_redirects: Type.Optional(Type.Boolean({ description: "Follow HTTP redirects" })),
	screenshot: Type.Optional(Type.Boolean({ description: "Capture a screenshot of every live page (httpx -ss)" })),
});

const crawlParams = Type.Object({
	target: Type.String({ description: "URL to crawl, e.g. https://example.com" }),
	depth: Type.Optional(Type.Number({ description: `Maximum crawl depth (default ${DEFAULT_CRAWL_DEPTH})` })),
	concurrency: Type.Optional(Type.Number({ description: "Number of concurrent fetchers" })),
	known_files: Type.Optional(Type.String({ description: "Known files katana should crawl: all, robotstxt, sitemapxml" })),
	output: Type.Optional(Type.Enum(["json", "text"], { description: "Output format (default json)" })),
});

const dirEnumParams = Type.Object({
	target: Type.String({ description: "Base URL to fuzz, e.g. https://example.com or https://example.com/FUZZ" }),
	wordlist: Type.Optional(Type.String({ description: `Wordlist to use (default ${DEFAULT_WORDLIST})` })),
	extensions: Type.Optional(Type.String({ description: "Extensions to try, e.g. php,html" })),
	threads: Type.Optional(Type.Number({ description: `Concurrent threads (default ${DEFAULT_FFUF_THREADS})` })),
	match_size: Type.Optional(Type.String({ description: "Match response size, e.g. 0,1024 or >1000" })),
	status_codes: Type.Optional(Type.String({ description: "Match HTTP status codes, e.g. 200,301 or all" })),
});

export const webTools: ToolDefinition[] = [
	defineCyberTool<typeof httpProbeParams, HttpProbeDetails>({
		name: "cyber_http_probe",
		label: "HTTP probe",
		description:
			"Probe HTTP(S) endpoints with httpx. Reports which URLs answer, with status code, page title, " +
			"web server and detected technology, and records every live URL in the surface index. " +
			"Accepts a single target or a file of URLs.",
		promptSnippet: "cyber_http_probe: probe HTTP(S) endpoints with httpx",
		technique: "recon",
		requires: ["httpx"],
		installHint: "Install httpx on Kali with: sudo apt install -y httpx",
		parameters: httpProbeParams,
		action: "http-probe",
		cacheTtlMs: 300_000,
		timeoutMs: 300_000,
		target: (params) => {
			if (params.target) return params.target;
			if (!params.urls_file) return undefined;
			try {
				return readUrlList(params.urls_file)[0];
			} catch {
				return undefined;
			}
		},
		build: (params, ctx) => {
			cwd = ctx.cwd;
			const urls = params.urls_file ? readUrlList(params.urls_file) : params.target ? [params.target] : [];
			if (urls.length === 0) {
				throw new Error("cyber_http_probe needs either a target URL or a urls_file listing the URLs to probe.");
			}
			assertAuthorized(ctx.cwd, urls, "recon");
			const threads = clampCount(params.threads, DEFAULT_HTTP_THREADS, 1, 500);
			const args = ["-json", "-silent", "-title", "-td", "-t", String(threads)];
			if (params.follow_redirects) args.push("-fr");
			if (params.ports) args.push("-p", params.ports);
			if (params.screenshot) args.push("-ss");
			if (params.urls_file) args.push("-l", params.urls_file);
			else args.push("-u", params.target as string);
			return { bin: "httpx", args, label: "http_probe", target: params.target ?? urls[0] };
		},
		summarize: (results, params) => {
			const result = results[0];
			const entries = parseJsonLines<HttpxResult>(result?.stdout ?? "");
			const endpoints: HttpProbeEndpoint[] = [];
			for (const entry of entries) {
				const url = toText(entry.url) ?? toText(entry.final_url);
				if (!url) continue;
				endpoints.push({
					url,
					status: toNumber(entry.status_code),
					title: toText(entry.title),
					technology: Array.isArray(entry.tech) ? entry.tech.filter((item): item is string => typeof item === "string") : undefined,
					webserver: toText(entry.webserver),
					screenshot: toText(entry.screenshot_path),
				});
			}

			const reachableKeys = new Set<string>();
			for (const entry of entries) {
				const key = toText(entry.input) ?? hostFromUrl(toText(entry.url) ?? "");
				if (key) reachableKeys.add(key);
			}
			const probed = params.urls_file ? urlListCount(params.urls_file) : params.target ? 1 : 0;
			const total = Math.max(probed, reachableKeys.size);
			const reachable = reachableKeys.size;
			const unreachable = Math.max(0, total - reachable);

			addEndpoints(
				cwd,
				endpoints.map((endpoint) => ({
					url: endpoint.url,
					host: hostFromUrl(endpoint.url),
					status: endpoint.status,
					title: endpoint.title,
					technology: endpoint.technology,
					source: "httpx",
				})),
			);

			const output: string[] = [];
			if (endpoints.length > 0) {
				output.push("Live endpoints:");
				for (const endpoint of endpoints.slice(0, MAX_LISTED)) {
					const status = endpoint.status === undefined ? "???" : String(endpoint.status);
					const title = endpoint.title ? ` - ${endpoint.title}` : "";
					const server = endpoint.webserver ? ` [${endpoint.webserver}]` : "";
					const tech = endpoint.technology && endpoint.technology.length > 0 ? ` {${endpoint.technology.join(", ")}}` : "";
					output.push(`  ${status}  ${endpoint.url}${title}${server}${tech}`);
				}
				if (endpoints.length > MAX_LISTED) {
					output.push(`  ... and ${endpoints.length - MAX_LISTED} more`);
				}
			} else if (result && result.code !== 0) {
				output.push("No results: httpx did not complete successfully.");
			}
			const screenshots = endpoints.filter((endpoint) => endpoint.screenshot);
			if (screenshots.length > 0) {
				output.push("");
				output.push("Screenshots:");
				for (const endpoint of screenshots.slice(0, MAX_LISTED)) {
					output.push(`  ${endpoint.url} -> ${endpoint.screenshot}`);
				}
			}
			if (result && result.code !== 0) {
				const error = (result.stderr || result.stdout).trim();
				if (error.length > 0) {
					output.push("");
					output.push(`httpx exited with code ${result.code}: ${error.split("\n").slice(-5).join(" ")}`);
				}
			}

			const failed = result !== undefined && result.code !== 0;
			return {
				summary:
					`Probed ${total} target(s) with httpx: ${reachable} reachable, ${unreachable} unreachable` +
					`${failed ? ` (exit code ${result?.code})` : "."}`,
				output: output.join("\n"),
				severity: failed ? "medium" : "info",
				details: { total, reachable, unreachable, endpoints },
			};
		},
	}),

	defineCyberTool<typeof crawlParams, CrawlDetails>({
		name: "cyber_crawl",
		label: "Site crawl",
		description:
			"Crawl a site with katana to depth N and list the unique URLs it finds, broken down by path " +
			"extension and HTTP status. Every URL is added to the surface index.",
		promptSnippet: "cyber_crawl: crawl a site with katana",
		technique: "web-testing",
		requires: ["katana"],
		installHint: "Install katana on Kali with: sudo apt install -y katana",
		parameters: crawlParams,
		action: "crawl",
		cacheTtlMs: 600_000,
		timeoutMs: 600_000,
		build: (params, ctx) => {
			cwd = ctx.cwd;
			const depth = clampCount(params.depth, DEFAULT_CRAWL_DEPTH, 1, 10);
			const args = ["-u", params.target, "-d", String(depth), "-silent"];
			if (params.output !== "text") {
				// JSONL output; the body is dropped so the stream stays parseable.
				args.push("-j", "-ob");
			}
			if (params.concurrency !== undefined) {
				args.push("-c", String(clampCount(params.concurrency, 10, 1, 100)));
			}
			if (params.known_files) args.push("-kf", params.known_files);
			return { bin: "katana", args, label: "crawl", target: params.target };
		},
		summarize: (results, params) => {
			const result = results[0];
			const stdout = result?.stdout ?? "";
			const found = new Map<string, { url: string; status?: number; technology?: string[] }>();
			let total = 0;

			if (params.output === "text") {
				for (const line of lines(stdout)) {
					if (!line.startsWith("http://") && !line.startsWith("https://")) continue;
					total += 1;
					if (!found.has(line)) found.set(line, { url: line });
				}
			} else {
				for (const entry of parseJsonLines<KatanaResult>(stdout)) {
					const url = toText(entry.request?.url) ?? toText(entry.request?.endpoint);
					if (!url) continue;
					total += 1;
					const previous = found.get(url);
					const status = toNumber(entry.response?.status_code);
					const technologies = Array.isArray(entry.response?.technologies)
						? entry.response.technologies.filter((item): item is string => typeof item === "string")
						: undefined;
					found.set(url, {
						url,
						status: status ?? previous?.status,
						technology: technologies ?? previous?.technology,
					});
				}
			}

			const byExtension = new Map<string, number>();
			const byStatus = new Map<string, number>();
			for (const entry of found.values()) {
				bump(byExtension, extensionFromUrl(entry.url));
				if (entry.status !== undefined) bump(byStatus, String(entry.status));
			}

			const urls = [...found.values()];

			addEndpoints(
				cwd,
				urls.map((entry) => ({
					url: entry.url,
					host: hostFromUrl(entry.url),
					status: entry.status,
					technology: entry.technology,
					source: "katana",
				})),
			);

			const output: string[] = [];
			const extensionSummary = [...byExtension.entries()]
				.map(([extension, count]) => `${extension}=${count}`)
				.join(", ");
			const statusSummary = [...byStatus.entries()]
				.sort((a, b) => a[0].localeCompare(b[0]))
				.map(([status, count]) => `${status}=${count}`)
				.join(", ");
			output.push(
				`Unique URLs: ${urls.length} of ${total} discovered` +
					`${extensionSummary ? ` | extensions ${extensionSummary}` : ""}` +
					`${statusSummary ? ` | status ${statusSummary}` : ""}`,
			);
			if (urls.length > 0) {
				output.push("");
				output.push("Crawled URLs:");
				for (const entry of urls.slice(0, MAX_LISTED)) {
					const status = entry.status === undefined ? "???" : String(entry.status);
					output.push(`  ${status}  ${entry.url}`);
				}
				if (urls.length > MAX_LISTED) output.push(`  ... and ${urls.length - MAX_LISTED} more`);
			} else if (result && result.code !== 0) {
				output.push("No results: katana did not complete successfully.");
			}
			if (result && result.code !== 0) {
				const error = (result.stderr || result.stdout).trim();
				if (error.length > 0) {
					output.push("");
					output.push(`katana exited with code ${result.code}: ${error.split("\n").slice(-5).join(" ")}`);
				}
			}

			const failed = result !== undefined && result.code !== 0;
			return {
				summary:
					`Crawled ${params.target} to depth ${clampCount(params.depth, DEFAULT_CRAWL_DEPTH, 1, 10)}: ` +
					`${urls.length} unique URLs${failed ? ` (exit code ${result?.code})` : "."}`,
				output: output.join("\n"),
				severity: failed ? "medium" : "info",
				details: {
					total,
					unique: urls.length,
					byExtension: toSortedRecord(byExtension),
					byStatus: toSortedRecord(byStatus),
					urls,
				},
			};
		},
	}),

	defineCyberTool<typeof dirEnumParams, DirEnumDetails>({
		name: "cyber_dir_enum",
		label: "Content discovery",
		description:
			"Discover hidden paths and files with ffuf. Fuzzes a wordlist against a base URL and reports " +
			"the hits with their status code and response size. Every discovered path is added to the surface index.",
		promptSnippet: "cyber_dir_enum: content discovery with ffuf",
		technique: "web-testing",
		requires: ["ffuf"],
		installHint: "Install ffuf and seclists on Kali with: sudo apt install -y ffuf seclists",
		parameters: dirEnumParams,
		action: "content-discovery",
		cacheTtlMs: 600_000,
		timeoutMs: 600_000,
		build: (params, ctx) => {
			cwd = ctx.cwd;
			const wordlist = params.wordlist ?? DEFAULT_WORDLIST;
			if (!fs.existsSync(wordlist)) {
				throw new Error(
					`wordlist not found: ${wordlist}. Install seclists (sudo apt install -y seclists) ` +
						"or pass the path of an existing wordlist in the wordlist parameter.",
				);
			}
			const url = fuzzUrl(params.target);
			const threads = clampCount(params.threads, DEFAULT_FFUF_THREADS, 1, 200);
			const args = ["-w", wordlist, "-u", url, "-t", String(threads), "-of", "json", "-noninteractive"];
			if (params.extensions) args.push("-e", params.extensions);
			if (params.status_codes) args.push("-mc", params.status_codes);
			if (params.match_size) args.push("-ms", params.match_size);
			args.push("-o", dirEnumOutputPath(ctx.cwd, params));
			return { bin: "ffuf", args, label: "dir_enum", target: params.target };
		},
		summarize: (results, params) => {
			const result = results[0];
			const outputFile = dirEnumOutputPath(cwd, params);
			let records: FfufResult[] = [];
			if (result?.code === 0 && fs.existsSync(outputFile)) {
				records = parseFfufResults(fs.readFileSync(outputFile, "utf8"));
			}
			if (records.length === 0) {
				records = parseFfufResults(result?.stdout ?? "");
			}

			const hits: DirEnumDetails["results"] = [];
			for (const record of records) {
				const url = toText(record.url);
				if (!url) continue;
				hits.push({
					url,
					path: pathFromUrl(url),
					status: toNumber(record.status),
					size: toNumber(record.length),
					word: toText(record.input?.FUZZ),
				});
			}

			const wordlist = params.wordlist ?? DEFAULT_WORDLIST;
			const url = fuzzUrl(params.target);

			addEndpoints(
				cwd,
				hits.map((hit) => ({
					url: hit.url,
					host: hostFromUrl(hit.url),
					status: hit.status,
					source: "ffuf",
				})),
			);

			const output: string[] = [];
			output.push(`Wordlist: ${wordlist}`);
			if (hits.length === 0) {
				output.push(result && result.code !== 0 ? "No results: ffuf did not complete successfully." : "No hits.");
			} else {
				output.push(`Hits: ${hits.length}`);
				output.push("");
				for (const hit of hits.slice(0, MAX_LISTED)) {
					const status = hit.status === undefined ? "???" : String(hit.status);
					const size = hit.size === undefined ? "?" : String(hit.size);
					output.push(`  ${status}  ${hit.path}  (${size} bytes)`);
				}
				if (hits.length > MAX_LISTED) output.push(`  ... and ${hits.length - MAX_LISTED} more`);
			}
			if (result && result.code !== 0) {
				const error = (result.stderr || result.stdout).trim();
				if (error.length > 0) {
					output.push("");
					output.push(`ffuf exited with code ${result.code}: ${error.split("\n").slice(-5).join(" ")}`);
				}
			}

			const failed = result !== undefined && result.code !== 0;
			return {
				summary:
					`ffuf found ${hits.length} hit(s) under ${url}` + `${failed ? ` (exit code ${result?.code})` : "."}`,
				output: output.join("\n"),
				severity: failed ? "medium" : "info",
				details: { hits: hits.length, wordlist, url, results: hits },
			};
		},
	}),
];
