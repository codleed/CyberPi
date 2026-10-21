/**
 * Findings: the structured record of what was proven during an engagement.
 *
 * Each finding is a Markdown file with YAML frontmatter in
 * `<engagement>/.cyberpi/findings/`. The report generator renders them into
 * the deliverable, so a finding captured during the session is already half
 * written.
 */

import fs from "node:fs";
import path from "node:path";
import { ensureDir, engagementPaths } from "./config.ts";
import type { Severity } from "./journal.ts";

export interface Finding {
	id: string;
	title: string;
	severity: Severity;
	cvss?: number;
	cve?: string;
	cwe?: string;
	target: string;
	status: "open" | "confirmed" | "reported";
	description: string;
	impact?: string;
	reproduction?: string;
	evidence?: string[];
	references?: string[];
	tags?: string[];
	createdAt: string;
	updatedAt: string;
}

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

function escapeYaml(value: string): string {
	return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function parseScalar(raw: string): string {
	const value = raw.trim();
	if (value.startsWith('"') && value.endsWith('"')) {
		return value
			.slice(1, -1)
			.replace(/\\"/g, '"')
			.replace(/\\\\/g, "\\");
	}
	return value;
}

function parseList(raw: string): string[] {
	const value = raw.trim();
	if (!value.startsWith("[") || !value.endsWith("]")) return [];
	const inner = value.slice(1, -1).trim();
	if (!inner) return [];
	return inner
		.split(",")
		.map((item) => parseScalar(item))
		.filter((item) => item.length > 0);
}

/** Render a finding as a Markdown document with frontmatter. */
export function renderFinding(finding: Finding): string {
	const lines: string[] = ["---"];
	lines.push(`id: ${finding.id}`);
	lines.push(`title: ${escapeYaml(finding.title)}`);
	lines.push(`severity: ${finding.severity}`);
	if (finding.cvss !== undefined) lines.push(`cvss: ${finding.cvss}`);
	if (finding.cve) lines.push(`cve: ${finding.cve}`);
	if (finding.cwe) lines.push(`cwe: ${finding.cwe}`);
	lines.push(`target: ${escapeYaml(finding.target)}`);
	lines.push(`status: ${finding.status}`);
	if (finding.tags && finding.tags.length > 0) lines.push(`tags: [${finding.tags.map(escapeYaml).join(", ")}]`);
	if (finding.references && finding.references.length > 0) {
		lines.push(`references: [${finding.references.map(escapeYaml).join(", ")}]`);
	}
	lines.push(`createdAt: ${finding.createdAt}`);
	lines.push(`updatedAt: ${finding.updatedAt}`);
	lines.push("---");
	lines.push("");
	lines.push(`# ${finding.title}`);
	lines.push("");
	lines.push("## Description");
	lines.push("");
	lines.push(finding.description);
	lines.push("");
	if (finding.impact) {
		lines.push("## Impact");
		lines.push("");
		lines.push(finding.impact);
		lines.push("");
	}
	if (finding.reproduction) {
		lines.push("## Reproduction");
		lines.push("");
		lines.push("```bash");
		lines.push(finding.reproduction);
		lines.push("```");
		lines.push("");
	}
	if (finding.evidence && finding.evidence.length > 0) {
		lines.push("## Evidence");
		lines.push("");
		for (const item of finding.evidence) lines.push(`- ${item}`);
		lines.push("");
	}
	if (finding.references && finding.references.length > 0) {
		lines.push("## References");
		lines.push("");
		for (const item of finding.references) lines.push(`- ${item}`);
		lines.push("");
	}
	return lines.join("\n");
}

/** Parse a finding document back into an object. */
export function parseFinding(raw: string): Finding {
	const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/.exec(raw);
	if (!match) throw new Error("finding document is missing frontmatter");
	const frontmatter = match[1];
	const body = match[2];
	const fields: Record<string, string> = {};
	for (const line of frontmatter.split("\n")) {
		const index = line.indexOf(":");
		if (index === -1) continue;
		fields[line.slice(0, index).trim()] = line.slice(index + 1).trim();
	}
	const severity = SEVERITIES.includes(fields.severity as Severity) ? (fields.severity as Severity) : "info";
	const sections: Record<string, string> = {};
	let current = "";
	for (const line of body.split("\n")) {
		const header = /^##\s+(.+)$/.exec(line);
		if (header) {
			current = header[1].trim().toLowerCase();
			sections[current] = "";
			continue;
		}
		if (current) sections[current] += `${line}\n`;
	}
	const clean = (value: string) =>
		value
			.split("\n")
			.map((line) => line.trim())
			.filter((line) => line.length > 0 && !line.startsWith("```"))
			.join("\n");
	return {
		id: fields.id ?? "FINDING-UNKNOWN",
		title: parseScalar(fields.title ?? "Untitled finding"),
		severity,
		cvss: fields.cvss ? Number(fields.cvss) : undefined,
		cve: fields.cve,
		cwe: fields.cwe,
		target: parseScalar(fields.target ?? "unknown"),
		status: (fields.status as Finding["status"]) ?? "open",
		description: clean(sections.description ?? ""),
		impact: sections.impact ? clean(sections.impact) : undefined,
		reproduction: sections.reproduction ? clean(sections.reproduction) : undefined,
		evidence: sections.evidence
			? sections.evidence
					.split("\n")
					.map((line) => line.replace(/^-\s*/, "").trim())
					.filter((line) => line.length > 0)
			: undefined,
		references: fields.references ? parseList(fields.references) : undefined,
		tags: fields.tags ? parseList(fields.tags) : undefined,
		createdAt: fields.createdAt ?? new Date().toISOString(),
		updatedAt: fields.updatedAt ?? new Date().toISOString(),
	};
}

/** Write a finding to the engagement. */
export function saveFinding(cwd: string, finding: Finding): string {
	const paths = engagementPaths(cwd);
	ensureDir(paths.findings);
	const file = path.join(paths.findings, `${finding.id}.md`);
	fs.writeFileSync(file, renderFinding(finding), "utf8");
	return file;
}

/** Read every finding in the engagement, sorted by severity then id. */
export function listFindings(cwd: string): Finding[] {
	const paths = engagementPaths(cwd);
	if (!fs.existsSync(paths.findings)) return [];
	const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
	const findings: Finding[] = [];
	for (const file of fs.readdirSync(paths.findings)) {
		if (!file.endsWith(".md")) continue;
		try {
			findings.push(parseFinding(fs.readFileSync(path.join(paths.findings, file), "utf8")));
		} catch {
			continue;
		}
	}
	return findings.sort((a, b) => order[a.severity] - order[b.severity] || a.id.localeCompare(b.id));
}

/** Allocate the next sequential finding id, e.g. F-003. */
export function nextFindingId(cwd: string): string {
	const findings = listFindings(cwd);
	let highest = 0;
	for (const finding of findings) {
		const match = /(\d+)$/.exec(finding.id);
		if (match) highest = Math.max(highest, Number(match[1]));
	}
	return `F-${String(highest + 1).padStart(3, "0")}`;
}
