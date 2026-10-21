/**
 * Reporting tools: findings, the deliverable, the action journal and the
 * attack surface index.
 *
 * These four tools never touch the network. They read and write the local
 * engagement record, so they declare no technique and are never refused by
 * the scope check.
 */

import fs from "node:fs";
import path from "node:path";
import { Type } from "@earendil-works/pi-ai";
import type { ToolDefinition } from "@earendil-works/pi-coding-agent";
import { ensureDir, engagementPaths } from "../lib/config.ts";
import { listFindings, nextFindingId, renderFinding, saveFinding, type Finding } from "../lib/findings.ts";
import { journalStats, readJournal, type JournalEntry, type Severity } from "../lib/journal.ts";
import { loadScope, type ScopeConfig } from "../lib/scope.ts";
import { readSurface, surfaceStats } from "../lib/surface.ts";
import { defineCyberTool } from "../lib/toolkit.ts";

const SEVERITY_VALUES = ["info", "low", "medium", "high", "critical"] as const;

/** Severities in the order a report presents them. */
const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITIES = new Set<string>(SEVERITY_VALUES);

function isSeverity(value: string): value is Severity {
	return SEVERITIES.has(value);
}

/* -------------------------------------------------------------------------- */
/* Tables                                                                     */
/* -------------------------------------------------------------------------- */

function cell(value: string | number | undefined): string {
	if (value === undefined) return "-";
	return String(value).replace(/\r?\n/g, " ").trim() || "-";
}

/** Pluralize a noun for a count. */
function plural(count: number, singular: string, many = `${singular}s`): string {
	return count === 1 ? singular : many;
}

function escapeMarkdownCell(value: string): string {
	return value.replace(/\|/g, "\\|");
}

function escapeHtml(value: string): string {
	return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/** Render the inline Markdown a finding body may contain as HTML. */
function inlineHtml(text: string): string {
	let out = escapeHtml(text);
	out = out.replace(/`([^`]+)`/g, "<code>$1</code>");
	out = out.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
	out = out.replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<em>$2</em>");
	out = out.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, '<a href="$2">$1</a>');
	return out;
}

/** Pad a table so the plain text transcript stays readable. */
function padTable(headers: string[], rows: string[][]): { widths: number[]; lines: string[] } {
	const widths = headers.map((header, column) => {
		let width = header.length;
		for (const row of rows) width = Math.max(width, (row[column] ?? "").length);
		return width;
	});
	const render = (values: string[]): string =>
		values
			.map((value, column) => value.padEnd(widths[column] ?? value.length))
			.join("  ")
			.trimEnd();
	return {
		widths,
		lines: [render(headers), ...rows.map((row) => render(row.map((value) => value ?? "")))],
	};
}

function markdownTable(headers: string[], rows: string[][]): string {
	if (rows.length === 0) return "_none_";
	const { widths, lines } = padTable(
		headers.map((header) => escapeMarkdownCell(header)),
		rows.map((row) => row.map((value) => escapeMarkdownCell(value))),
	);
	const separator = `| ${widths.map((width) => "-".repeat(width)).join(" | ")} |`;
	return [`| ${lines[0]} |`, separator, ...lines.slice(1).map((line) => `| ${line} |`)].join("\n");
}

function htmlTable(headers: string[], rows: string[][]): string {
	const head = headers.map((header) => `<th>${inlineHtml(header)}</th>`).join("");
	const body = rows
		.map((row) => `<tr>${row.map((value) => `<td>${inlineHtml(value ?? "")}</td>`).join("")}</tr>`)
		.join("\n");
	return `<table>\n<thead><tr>${head}</tr></thead>\n<tbody>\n${body}\n</tbody>\n</table>`;
}

/* -------------------------------------------------------------------------- */
/* Report document                                                            */
/* -------------------------------------------------------------------------- */

type ReportBlock =
	| { kind: "heading"; level: number; text: string }
	| { kind: "paragraph"; text: string }
	| { kind: "table"; headers: string[]; rows: string[][] }
	| { kind: "list"; items: string[] }
	| { kind: "code"; text: string }
	| { kind: "rule" };

function renderMarkdown(blocks: ReportBlock[]): string {
	const parts: string[] = [];
	for (const block of blocks) {
		switch (block.kind) {
			case "heading":
				parts.push(`${"#".repeat(Math.min(6, Math.max(1, block.level)))} ${block.text}`);
				break;
			case "paragraph":
				parts.push(block.text);
				break;
			case "table":
				parts.push(markdownTable(block.headers, block.rows));
				break;
			case "list":
				parts.push(block.items.map((item) => `- ${item}`).join("\n"));
				break;
			case "code":
				parts.push("```\n" + block.text.replace(/\s+$/, "") + "\n```");
				break;
			case "rule":
				parts.push("---");
				break;
		}
	}
	return `${parts.join("\n\n")}\n`;
}

function renderHtml(blocks: ReportBlock[], title: string): string {
	const body: string[] = [];
	for (const block of blocks) {
		switch (block.kind) {
			case "heading": {
				const level = Math.min(6, Math.max(1, block.level));
				body.push(`<h${level}>${inlineHtml(block.text)}</h${level}>`);
				break;
			}
			case "paragraph":
				body.push(`<p>${inlineHtml(block.text)}</p>`);
				break;
			case "table":
				body.push(htmlTable(block.headers, block.rows));
				break;
			case "list":
				body.push(`<ul>${block.items.map((item) => `<li>${inlineHtml(item)}</li>`).join("")}</ul>`);
				break;
			case "code":
				body.push(`<pre><code>${escapeHtml(block.text.replace(/\s+$/, ""))}</code></pre>`);
				break;
			case "rule":
				body.push("<hr />");
				break;
		}
	}
	return [
		"<!doctype html>",
		'<html lang="en">',
		"<head>",
		'<meta charset="utf-8" />',
		`<title>${escapeHtml(title)}</title>`,
		"<style>",
		"body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;margin:2.5rem auto;max-width:60rem;line-height:1.55;color:#1b1f24;padding:0 1.25rem}",
		"h1{border-bottom:2px solid #1b1f24;padding-bottom:.35rem}h2{margin-top:2.25rem;border-bottom:1px solid #d8dee4;padding-bottom:.25rem}h3{margin-top:1.75rem}h4{margin-top:1.25rem;color:#3b4148}",
		"table{border-collapse:collapse;width:100%;margin:1rem 0;font-size:.94rem}th,td{border:1px solid #d8dee4;padding:.4rem .6rem;text-align:left;vertical-align:top}th{background:#f2f4f6}",
		"pre{background:#f2f4f6;border:1px solid #d8dee4;border-radius:4px;padding:.75rem;overflow-x:auto}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em}hr{border:0;border-top:1px solid #d8dee4;margin:2rem 0}",
		"</style>",
		"</head>",
		"<body>",
		body.join("\n"),
		"</body>",
		"</html>",
		"",
	].join("\n");
}

function overallRisk(findings: Finding[]): string {
	if (findings.some((finding) => finding.severity === "critical")) return "Critical";
	if (findings.some((finding) => finding.severity === "high")) return "High";
	if (findings.some((finding) => finding.severity === "medium")) return "Medium";
	if (findings.some((finding) => finding.severity === "low")) return "Low";
	return "Informational";
}

function countBySeverity(findings: Finding[]): Record<string, number> {
	const counts: Record<string, number> = {};
	for (const severity of SEVERITY_ORDER) counts[severity] = 0;
	for (const finding of findings) counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
	return counts;
}

function severityBreakdown(counts: Record<string, number>): string {
	return SEVERITY_ORDER.filter((severity) => (counts[severity] ?? 0) > 0)
		.map((severity) => `${counts[severity]} ${severity}`)
		.join(", ");
}

function findingBlocks(finding: Finding): ReportBlock[] {
	const blocks: ReportBlock[] = [];
	blocks.push({ kind: "heading", level: 3, text: `${finding.id} - ${finding.title}` });
	blocks.push({
		kind: "table",
		headers: ["Attribute", "Value"],
		rows: [
			["Severity", finding.severity],
			["CVSS", finding.cvss !== undefined ? String(finding.cvss) : "not scored"],
			["Target", cell(finding.target)],
			["Status", cell(finding.status)],
			["CVE", cell(finding.cve)],
			["CWE", cell(finding.cwe)],
			["Tags", cell(finding.tags && finding.tags.length > 0 ? finding.tags.join(", ") : undefined)],
			["Recorded", cell(finding.createdAt)],
		],
	});
	blocks.push({ kind: "heading", level: 4, text: "Description" });
	blocks.push({ kind: "paragraph", text: finding.description || "No description was recorded." });
	if (finding.impact) {
		blocks.push({ kind: "heading", level: 4, text: "Impact" });
		blocks.push({ kind: "paragraph", text: finding.impact });
	}
	if (finding.reproduction) {
		blocks.push({ kind: "heading", level: 4, text: "Reproduction" });
		blocks.push({ kind: "code", text: finding.reproduction });
	}
	if (finding.evidence && finding.evidence.length > 0) {
		blocks.push({ kind: "heading", level: 4, text: "Evidence" });
		blocks.push({ kind: "list", items: finding.evidence });
	}
	if (finding.references && finding.references.length > 0) {
		blocks.push({ kind: "heading", level: 4, text: "References" });
		blocks.push({ kind: "list", items: finding.references });
	}
	return blocks;
}

function scopeBlocks(scope: ScopeConfig | null): ReportBlock[] {
	const blocks: ReportBlock[] = [];
	blocks.push({ kind: "heading", level: 2, text: "Appendix A - Scope and Authorization" });
	if (!scope) {
		blocks.push({
			kind: "paragraph",
			text: "No scope file was present for this engagement. No targets were formally authorized.",
		});
		return blocks;
	}
	blocks.push({
		kind: "table",
		headers: ["Attribute", "Value"],
		rows: [
			["Engagement", cell(scope.engagement)],
			["Client", cell(scope.client)],
			["Authorized by", cell(scope.authorization?.authorizedBy)],
			["Authorization statement", cell(scope.authorization?.statement)],
			["Window opens", cell(scope.authorization?.start)],
			["Window closes", cell(scope.authorization?.end)],
			[
				"Technique allowlist",
				cell(scope.techniques && scope.techniques.length > 0 ? scope.techniques.join(", ") : "all techniques"),
			],
			["Self-testing allowed", scope.allowSelfTest === false ? "no" : "yes"],
		],
	});
	blocks.push({ kind: "heading", level: 3, text: "Authorized Targets" });
	blocks.push({
		kind: "table",
		headers: ["Target", "Ports", "Protocols", "Techniques", "Notes"],
		rows: scope.rules.map((rule) => [
			cell(rule.target),
			cell(rule.ports && rule.ports.length > 0 ? rule.ports.join(", ") : "any"),
			cell(rule.protocols && rule.protocols.length > 0 ? rule.protocols.join(", ") : "any"),
			cell(rule.techniques && rule.techniques.length > 0 ? rule.techniques.join(", ") : "any"),
			cell(rule.notes),
		]),
	});
	if (scope.notes) {
		blocks.push({ kind: "heading", level: 3, text: "Scope Notes" });
		blocks.push({ kind: "paragraph", text: scope.notes });
	}
	return blocks;
}

function journalBlocks(entries: JournalEntry[]): ReportBlock[] {
	const blocks: ReportBlock[] = [];
	blocks.push({ kind: "heading", level: 2, text: "Appendix B - Action Journal" });
	blocks.push({
		kind: "paragraph",
		text:
			`${entries.length} action${entries.length === 1 ? "" : "s"} were recorded during the engagement. ` +
			"The entries below are reproduced verbatim from the engagement journal, in the order they happened.",
	});
	blocks.push({
		kind: "table",
		headers: ["Timestamp", "Tool", "Action", "Target", "Summary"],
		rows: entries.map((entry) => [
			cell(entry.ts),
			cell(entry.tool),
			cell(entry.action),
			cell(entry.target),
			cell(entry.summary),
		]),
	});
	return blocks;
}

interface ReportInput {
	title: string;
	engagement: string;
	scope: ScopeConfig | null;
	findings: Finding[];
	journal: JournalEntry[];
	includeJournal: boolean;
	generatedAt: string;
}

function reportBlocks(input: ReportInput): ReportBlock[] {
	const { scope, findings, journal } = input;
	const counts = countBySeverity(findings);
	const engagement = input.engagement;
	const client = scope?.client ?? "not recorded";
	const blocks: ReportBlock[] = [];

	blocks.push({ kind: "heading", level: 1, text: input.title });
	blocks.push({
		kind: "table",
		headers: ["Field", "Value"],
		rows: [
			["Engagement", cell(engagement)],
			["Client", cell(client)],
			["Report generated", cell(input.generatedAt)],
			["Assessment type", "Authorized security assessment"],
			["Overall risk rating", overallRisk(findings)],
			["Targets in scope", cell(scope ? scope.rules.length : 0)],
			["Findings", cell(findings.length)],
			["Actions recorded", cell(journal.length)],
		],
	});

	blocks.push({ kind: "heading", level: 2, text: "Executive Summary" });
	const top = findings[0];
	const summaryLines: string[] = [];
	summaryLines.push(
		`This report presents the results of the authorized security assessment "${engagement}" performed for ${client}. ` +
			`The assessment covered ${scope ? scope.rules.length : 0} authorized ${plural(scope ? scope.rules.length : 0, "target")} ` +
			`and recorded ${journal.length} logged ${plural(journal.length, "action")}.`,
	);
	summaryLines.push(
		findings.length === 0
			? "No findings were recorded during the assessment."
			: `${findings.length} ${plural(findings.length, "finding")} ${findings.length === 1 ? "was" : "were"} recorded (${severityBreakdown(counts) || "no severities recorded"}). ` +
				`The overall risk rating for the assessed estate is ${overallRisk(findings).toLowerCase()}.`,
	);
	if (top) {
		summaryLines.push(
			`The most severe issue is ${top.id} (${top.severity}) "${top.title}"` +
				(top.target && top.target !== "unknown" ? ` on ${top.target}` : "") +
				". Remediation of the high and critical findings should be prioritised.",
		);
	}
	summaryLines.push(
		scope
			? "Every action listed in Appendix B was performed against the targets authorized in Appendix A " +
				"and was recorded in the engagement journal at the time it happened."
			: "No scope file was present for this engagement, so the actions listed in Appendix B could not be " +
				"validated against a written authorization.",
	);
	for (const line of summaryLines) blocks.push({ kind: "paragraph", text: line });

	blocks.push({ kind: "heading", level: 2, text: "Severity Breakdown" });
	blocks.push({
		kind: "table",
		headers: ["Severity", "Findings", "Finding IDs"],
		rows: SEVERITY_ORDER.map((severity) => [
			severity,
			String(counts[severity] ?? 0),
			findings
				.filter((finding) => finding.severity === severity)
				.map((finding) => finding.id)
				.join(", ") || "-",
		]),
	});

	blocks.push({ kind: "heading", level: 2, text: "Findings" });
	if (findings.length === 0) {
		blocks.push({ kind: "paragraph", text: "No findings were recorded for this engagement." });
	} else {
		for (const finding of findings) blocks.push(...findingBlocks(finding));
	}

	blocks.push(...scopeBlocks(scope));
	if (input.includeJournal) blocks.push(...journalBlocks(journal));

	blocks.push({ kind: "rule" });
	blocks.push({
		kind: "paragraph",
		text: `Generated by CyberPi on ${input.generatedAt}. Findings and the action journal are stored in the engagement directory and remain the authoritative record.`,
	});
	return blocks;
}

/* -------------------------------------------------------------------------- */
/* cyber_record_finding                                                       */
/* -------------------------------------------------------------------------- */

const recordFindingParameters = Type.Object({
	title: Type.String({ description: "Short and specific title of the finding" }),
	severity: Type.Enum(SEVERITY_VALUES, { description: "Severity rating of the finding" }),
	target: Type.Optional(Type.String({ description: "Host, URL or asset the finding applies to" })),
	description: Type.Optional(Type.String({ description: "What the finding is and how it was observed" })),
	impact: Type.Optional(Type.String({ description: "What an attacker gains from the issue" })),
	reproduction: Type.Optional(Type.String({ description: "Commands or steps that reproduce the issue" })),
	evidence: Type.Optional(Type.Array(Type.String({ description: "A single piece of evidence" }))),
	references: Type.Optional(Type.Array(Type.String({ description: "A reference URL or advisory identifier" }))),
	cvss: Type.Optional(Type.Number({ description: "CVSS base score between 0 and 10" })),
	cve: Type.Optional(Type.String({ description: "CVE identifier" })),
	cwe: Type.Optional(Type.String({ description: "CWE identifier" })),
	tags: Type.Optional(Type.Array(Type.String({ description: "A tag used to group findings" }))),
	id: Type.Optional(Type.String({ description: "Finding identifier, allocated automatically when omitted" })),
});

interface RecordFindingDetails {
	id: string;
	path: string;
	title: string;
	severity: Severity;
	target: string;
	replaced: boolean;
}

const FINDING_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

const recordFindingTool = defineCyberTool<typeof recordFindingParameters, RecordFindingDetails>({
	name: "cyber_record_finding",
	label: "Record finding",
	description:
		"Record a confirmed security finding in the engagement. The finding is written to the engagement " +
		"findings directory, journalled with its severity and returned as rendered Markdown.",
	promptSnippet: "cyber_record_finding: record a confirmed finding in the engagement record",
	action: "finding",
	technique: undefined,
	target: () => undefined,
	parameters: recordFindingParameters,
	async execute(params, ctx) {
		const cwd = ctx.cwd;
		if (!isSeverity(params.severity)) {
			return {
				summary: `Invalid severity "${params.severity}". Use one of: ${SEVERITY_VALUES.join(", ")}.`,
				isError: true,
			};
		}
		const id = (params.id ?? nextFindingId(cwd)).trim();
		if (!FINDING_ID_PATTERN.test(id)) {
			return {
				summary:
					`Invalid finding id "${id}". Use letters, digits, dots, dashes and underscores only ` +
					"(for example F-001); it becomes a file name in the engagement directory.",
				isError: true,
			};
		}
		const now = new Date().toISOString();
		const paths = engagementPaths(cwd);
		const file = path.join(paths.findings, `${id}.md`);
		const replaced = fs.existsSync(file);
		const finding: Finding = {
			id,
			title: params.title.trim(),
			severity: params.severity,
			cvss: params.cvss,
			cve: params.cve,
			cwe: params.cwe,
			target: params.target?.trim() || "unknown",
			status: "open",
			description: params.description?.trim() || "No description was recorded.",
			impact: params.impact,
			reproduction: params.reproduction,
			evidence: params.evidence && params.evidence.length > 0 ? params.evidence : undefined,
			references: params.references && params.references.length > 0 ? params.references : undefined,
			tags: params.tags && params.tags.length > 0 ? params.tags : undefined,
			createdAt: now,
			updatedAt: now,
		};
		const saved = saveFinding(cwd, finding);
		const markdown = renderFinding(finding);
		return {
			summary:
				`Recorded ${finding.id} [${finding.severity}] ${finding.title}` +
				(finding.target !== "unknown" ? ` on ${finding.target}` : ""),
			output: `Saved to: ${saved}\n\n${markdown}`,
			severity: finding.severity,
			details: {
				id: finding.id,
				path: saved,
				title: finding.title,
				severity: finding.severity,
				target: finding.target,
				replaced,
			},
		};
	},
});

/* -------------------------------------------------------------------------- */
/* cyber_report                                                               */
/* -------------------------------------------------------------------------- */

const reportParameters = Type.Object({
	format: Type.Optional(
		Type.Enum(["markdown", "html"], { description: "Document format of the generated report" }),
	),
	output_file: Type.Optional(Type.String({ description: "File name or path for the generated report" })),
	include_journal: Type.Optional(
		Type.Boolean({ description: "Append the engagement action journal as an appendix" }),
	),
	title: Type.Optional(Type.String({ description: "Report title" })),
});

interface ReportDetails {
	path: string;
	format: string;
	engagement: string;
	client: string;
	findings: number;
	bySeverity: Record<string, number>;
	journalEntries: number;
	includeJournal: boolean;
}

function resolveReportPath(cwd: string, outputFile: string | undefined, format: "markdown" | "html"): string {
	const paths = engagementPaths(cwd);
	ensureDir(paths.reports);
	const extension = format === "html" ? ".html" : ".md";
	if (!outputFile || outputFile.trim().length === 0) {
		const stamp = new Date()
			.toISOString()
			.replace(/[:.]/g, "-")
			.replace("T", "_")
			.slice(0, 19);
		return path.join(paths.reports, `report-${stamp}${extension}`);
	}
	const trimmed = outputFile.trim();
	const target = path.isAbsolute(trimmed) ? trimmed : path.join(paths.reports, trimmed);
	const withExtension = path.extname(target).length > 0 ? target : `${target}${extension}`;
	ensureDir(path.dirname(withExtension));
	return withExtension;
}

const reportTool = defineCyberTool<typeof reportParameters, ReportDetails>({
	name: "cyber_report",
	label: "Build report",
	description:
		"Build the engagement report from the recorded findings, the engagement scope and the action journal. " +
		"The document is written to the engagement reports directory.",
	promptSnippet: "cyber_report: build the engagement report from findings, scope and journal",
	action: "report",
	technique: undefined,
	target: () => undefined,
	parameters: reportParameters,
	async execute(params, ctx) {
		const cwd = ctx.cwd;
		const format = params.format === "html" ? "html" : "markdown";
		const includeJournal = params.include_journal ?? true;
		const scope = loadScope(cwd);
		const findings = listFindings(cwd);
		const journal = readJournal(cwd);
		const engagement = scope?.engagement ?? path.basename(engagementPaths(cwd).root);
		const title = params.title?.trim() || `${engagement}: Security Assessment Report`;
		const generatedAt = new Date().toISOString();

		const blocks = reportBlocks({ title, engagement, scope, findings, journal, includeJournal, generatedAt });
		const document = format === "html" ? renderHtml(blocks, title) : renderMarkdown(blocks);
		const file = resolveReportPath(cwd, params.output_file, format);
		fs.writeFileSync(file, document, "utf8");

		const counts = countBySeverity(findings);
		const breakdown = severityBreakdown(counts);
		return {
			summary: `Report written to ${file}`,
			output: [
				`Engagement: ${engagement}`,
				`Client: ${scope?.client ?? "not recorded"}`,
				`Findings: ${findings.length}${breakdown ? ` (${breakdown})` : ""}`,
				`Actions recorded: ${journal.length}`,
				`Journal appendix: ${includeJournal ? "included" : "omitted"}`,
			].join("\n"),
			severity: "info",
			details: {
				path: file,
				format,
				engagement,
				client: scope?.client ?? "not recorded",
				findings: findings.length,
				bySeverity: counts,
				journalEntries: journal.length,
				includeJournal,
			},
		};
	},
});

/* -------------------------------------------------------------------------- */
/* cyber_journal                                                              */
/* -------------------------------------------------------------------------- */

const journalParameters = Type.Object({
	limit: Type.Optional(Type.Number({ description: "Maximum number of entries to return" })),
	action: Type.Optional(Type.String({ description: "Only entries whose action matches this text" })),
	tool: Type.Optional(Type.String({ description: "Only entries whose tool matches this text" })),
	severity: Type.Optional(Type.String({ description: "Only entries with this severity" })),
	format: Type.Optional(Type.Enum(["table", "json"], { description: "Output format" })),
});

interface JournalDetails {
	total: number;
	shown: number;
	filtered: number;
	journalPath: string;
	bySeverity: Record<string, number>;
	byTool: Record<string, number>;
	first?: string;
	last?: string;
}

function matches(text: string | undefined, filter: string | undefined): boolean {
	if (!filter || filter.trim().length === 0) return true;
	const needle = filter.trim().toLowerCase();
	return (text ?? "").toLowerCase().includes(needle);
}

const journalTool = defineCyberTool<typeof journalParameters, JournalDetails>({
	name: "cyber_journal",
	label: "Engagement journal",
	description:
		"Read the engagement action journal: the chain of custody of the assessment. Entries are reproduced " +
		"exactly as they were written.",
	promptSnippet: "cyber_journal: read the engagement action journal",
	action: "journal",
	technique: undefined,
	target: () => undefined,
	parameters: journalParameters,
	async execute(params, ctx) {
		const cwd = ctx.cwd;
		const format = params.format === "json" ? "json" : "table";
		const limit = params.limit !== undefined && Number.isFinite(params.limit) && params.limit > 0 ? Math.floor(params.limit) : 50;
		const entries = readJournal(cwd);
		const stats = journalStats(cwd);

		const filtered = entries.filter(
			(entry) =>
				matches(entry.action, params.action) &&
				matches(entry.tool, params.tool) &&
				matches(entry.severity ?? "info", params.severity),
		);
		const shown = filtered.slice(Math.max(0, filtered.length - limit));
		const journalPath = engagementPaths(cwd).journal;

		if (entries.length === 0) {
			return {
				summary: `The engagement journal is empty (${journalPath})`,
				output: "No actions have been recorded yet.",
				severity: "info",
				details: {
					total: 0,
					shown: 0,
					filtered: 0,
					journalPath,
					bySeverity: stats.bySeverity,
					byTool: stats.byTool,
				},
			};
		}

		const body =
			format === "json"
				? JSON.stringify(shown, null, 2)
				: [
						`| Timestamp | Tool | Action | Target | Summary |`,
						`| --- | --- | --- | --- | --- |`,
						...shown.map(
							(entry) =>
								`| ${cell(entry.ts)} | ${cell(entry.tool)} | ${cell(entry.action)} | ${cell(entry.target)} | ${cell(entry.summary)} |`,
						),
					].join("\n");

		const filterNote = [
			params.action ? `action~${params.action}` : "",
			params.tool ? `tool~${params.tool}` : "",
			params.severity ? `severity=${params.severity}` : "",
		]
			.filter((part) => part.length > 0)
			.join(", ");

		return {
			summary:
				`Journal: showing ${shown.length} of ${entries.length} recorded action${entries.length === 1 ? "" : "s"}` +
				(filterNote ? ` (${filterNote})` : ""),
			output: `${body}\n\nJournal file: ${journalPath}`,
			severity: "info",
			details: {
				total: entries.length,
				shown: shown.length,
				filtered: filtered.length,
				journalPath,
				bySeverity: stats.bySeverity,
				byTool: stats.byTool,
				first: stats.first,
				last: stats.last,
			},
		};
	},
});

/* -------------------------------------------------------------------------- */
/* cyber_surface                                                              */
/* -------------------------------------------------------------------------- */

const surfaceParameters = Type.Object({
	host: Type.Optional(Type.String({ description: "Only show entries for this host" })),
	port: Type.Optional(Type.Number({ description: "Only show services on this port" })),
	kind: Type.Optional(
		Type.Enum(["all", "hosts", "services", "endpoints"], { description: "Which part of the index to show" }),
	),
	format: Type.Optional(Type.Enum(["table", "json"], { description: "Output format" })),
});

interface SurfaceDetails {
	hosts: number;
	services: number;
	endpoints: number;
	indexHosts: number;
	indexServices: number;
	indexEndpoints: number;
	indexPorts: number;
	updatedAt: string;
}

const surfaceTool = defineCyberTool<typeof surfaceParameters, SurfaceDetails>({
	name: "cyber_surface",
	label: "Attack surface",
	description:
		"Read the engagement attack surface index: the hosts, services and endpoints discovered during the " +
		"assessment, merged by every reconnaissance tool.",
	promptSnippet: "cyber_surface: read the recorded attack surface index",
	action: "surface",
	technique: undefined,
	target: () => undefined,
	parameters: surfaceParameters,
	async execute(params, ctx) {
		const cwd = ctx.cwd;
		const format = params.format === "json" ? "json" : "table";
		const kind = params.kind ?? "all";
		const surface = readSurface(cwd);
		const stats = surfaceStats(cwd);
		const hostFilter = params.host?.trim().toLowerCase();
		const portFilter = params.port;

		const hosts = surface.hosts.filter(
			(host) => !hostFilter || host.host.toLowerCase().includes(hostFilter),
		);
		const services = surface.services.filter(
			(service) =>
				(!hostFilter || service.host.toLowerCase().includes(hostFilter)) &&
				(portFilter === undefined || service.port === portFilter),
		);
		const endpoints = surface.endpoints.filter(
			(endpoint) => !hostFilter || endpoint.host.toLowerCase().includes(hostFilter),
		);

		const showHosts = kind === "all" || kind === "hosts";
		const showServices = kind === "all" || kind === "services";
		const showEndpoints = kind === "all" || kind === "endpoints";

		if (format === "json") {
			const payload: Record<string, unknown> = { updatedAt: surface.updatedAt, stats };
			if (showHosts) payload.hosts = hosts;
			if (showServices) payload.services = services;
			if (showEndpoints) payload.endpoints = endpoints;
			return {
				summary:
					`Surface index: ${hosts.length} ${plural(hosts.length, "host")}, ` +
					`${services.length} ${plural(services.length, "service")}, ` +
					`${endpoints.length} ${plural(endpoints.length, "endpoint")}`,
				output: JSON.stringify(payload, null, 2),
				severity: "info",
				details: {
					hosts: hosts.length,
					services: services.length,
					endpoints: endpoints.length,
					indexHosts: stats.hosts,
					indexServices: stats.services,
					indexEndpoints: stats.endpoints,
					indexPorts: stats.ports,
					updatedAt: stats.updatedAt,
				},
			};
		}

		const sections: string[] = [];
		if (showHosts) {
			sections.push(
				[
					"### Hosts",
					markdownTable(
						["Host", "Addresses", "Source", "First seen"],
						hosts.map((host) => [
							cell(host.host),
							cell(host.addresses && host.addresses.length > 0 ? host.addresses.join(", ") : undefined),
							cell(host.source),
							cell(host.firstSeen),
						]),
					),
				].join("\n"),
			);
		}
		if (showServices) {
			sections.push(
				[
					"### Services",
					markdownTable(
						["Host", "Port", "Protocol", "Service", "Version", "Source"],
						services.map((service) => [
							cell(service.host),
							cell(service.port),
							cell(service.protocol),
							cell(service.service),
							cell(service.version),
							cell(service.source),
						]),
					),
				].join("\n"),
			);
		}
		if (showEndpoints) {
			sections.push(
				[
					"### Endpoints",
					markdownTable(
						["URL", "Host", "Status", "Title", "Technology", "Source"],
						endpoints.map((endpoint) => [
							cell(endpoint.url),
							cell(endpoint.host),
							cell(endpoint.status),
							cell(endpoint.title),
							cell(endpoint.technology && endpoint.technology.length > 0 ? endpoint.technology.join(", ") : undefined),
							cell(endpoint.source),
						]),
					),
				].join("\n"),
			);
		}

		return {
			summary:
				`Surface index: ${hosts.length} ${plural(hosts.length, "host")}, ` +
				`${services.length} ${plural(services.length, "service")}, ` +
				`${endpoints.length} ${plural(endpoints.length, "endpoint")} ` +
				`(${stats.hosts} ${plural(stats.hosts, "host")}, ${stats.services} ${plural(stats.services, "service")}, ` +
				`${stats.endpoints} ${plural(stats.endpoints, "endpoint")} in the index)`,
			output: sections.join("\n\n"),
			severity: "info",
			details: {
				hosts: hosts.length,
				services: services.length,
				endpoints: endpoints.length,
				indexHosts: stats.hosts,
				indexServices: stats.services,
				indexEndpoints: stats.endpoints,
				indexPorts: stats.ports,
				updatedAt: stats.updatedAt,
			},
		};
	},
});

export const reportTools: ToolDefinition[] = [recordFindingTool, reportTool, journalTool, surfaceTool];
