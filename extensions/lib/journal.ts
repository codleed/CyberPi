/**
 * Engagement journal.
 *
 * Every action CyberPi takes is appended to a JSONL file so the engagement
 * has a defensible record of what was run, against what, and when. The report
 * generator and the dashboard read from the same file.
 */

import fs from "node:fs";
import path from "node:path";
import { ensureDir, engagementPaths } from "./config.ts";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface JournalEntry {
	/** ISO 8601 timestamp. */
	ts: string;
	/** Tool that produced the entry, e.g. "cyber_portscan". */
	tool: string;
	/** What happened, e.g. "scan", "exploit", "finding". */
	action: string;
	/** Target the action applied to. */
	target?: string;
	/** Command line that was executed. */
	command?: string;
	/** Exit code of the command. */
	exitCode?: number | null;
	/** Duration in milliseconds. */
	durationMs?: number;
	/** One line summary. */
	summary?: string;
	/** Severity of the outcome. */
	severity?: Severity;
	/** Artifact file produced by the action. */
	artifact?: string;
	/** Free-form tags. */
	tags?: string[];
}

function serialize(entry: JournalEntry): string {
	const ordered: Record<string, unknown> = {
		ts: entry.ts,
		tool: entry.tool,
		action: entry.action,
	};
	if (entry.target !== undefined) ordered.target = entry.target;
	if (entry.command !== undefined) ordered.command = entry.command;
	if (entry.exitCode !== undefined) ordered.exitCode = entry.exitCode;
	if (entry.durationMs !== undefined) ordered.durationMs = entry.durationMs;
	if (entry.summary !== undefined) ordered.summary = entry.summary;
	if (entry.severity !== undefined) ordered.severity = entry.severity;
	if (entry.artifact !== undefined) ordered.artifact = entry.artifact;
	if (entry.tags !== undefined) ordered.tags = entry.tags;
	return JSON.stringify(ordered);
}

/** Append an entry to the engagement journal. */
export function appendJournal(cwd: string, entry: JournalEntry): void {
	const paths = engagementPaths(cwd);
	ensureDir(paths.dir);
	fs.appendFileSync(paths.journal, `${serialize(entry)}\n`, "utf8");
}

/** Read every journal entry, oldest first. Malformed lines are skipped. */
export function readJournal(cwd: string): JournalEntry[] {
	const paths = engagementPaths(cwd);
	if (!fs.existsSync(paths.journal)) return [];
	const entries: JournalEntry[] = [];
	for (const line of fs.readFileSync(paths.journal, "utf8").split("\n")) {
		const trimmed = line.trim();
		if (!trimmed) continue;
		try {
			entries.push(JSON.parse(trimmed) as JournalEntry);
		} catch {
			continue;
		}
	}
	return entries;
}

/** Summarise the journal for display. */
export function journalStats(cwd: string): {
	total: number;
	bySeverity: Record<string, number>;
	byTool: Record<string, number>;
	first?: string;
	last?: string;
} {
	const entries = readJournal(cwd);
	const bySeverity: Record<string, number> = {};
	const byTool: Record<string, number> = {};
	for (const entry of entries) {
		const severity = entry.severity ?? "info";
		bySeverity[severity] = (bySeverity[severity] ?? 0) + 1;
		byTool[entry.tool] = (byTool[entry.tool] ?? 0) + 1;
	}
	return {
		total: entries.length,
		bySeverity,
		byTool,
		first: entries[0]?.ts,
		last: entries[entries.length - 1]?.ts,
	};
}

/** Write a file inside the engagement artifacts directory. */
export function writeArtifact(cwd: string, name: string, content: string): string {
	const paths = engagementPaths(cwd);
	ensureDir(paths.artifacts);
	const file = path.join(paths.artifacts, name);
	fs.writeFileSync(file, content, "utf8");
	return file;
}
