/**
 * Engagement journal tests.
 *
 * The journal is the defensible record of what the harness did, so appending,
 * ordering and reading back must be exact. A malformed line must never hide
 * the entries around it, and the statistics must agree with the entries.
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import {
	appendJournal,
	journalStats,
	readJournal,
	writeArtifact,
	type JournalEntry,
} from "../extensions/lib/journal.ts";

const originalEngagement = process.env.CYBERPI_ENGAGEMENT;
let tmp = "";

before(() => {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-journal-"));
	process.env.CYBERPI_ENGAGEMENT = tmp;
});

after(() => {
	if (originalEngagement === undefined) delete process.env.CYBERPI_ENGAGEMENT;
	else process.env.CYBERPI_ENGAGEMENT = originalEngagement;
	if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
});

function entry(overrides: Partial<JournalEntry> = {}): JournalEntry {
	return {
		ts: "2025-03-01T10:00:00.000Z",
		tool: "cyber_portscan",
		action: "scan",
		...overrides,
	};
}

function journalFile(): string {
	return path.join(tmp, ".cyberpi", "journal.jsonl");
}

describe("appending entries", () => {
	it("creates the journal file on the first append", () => {
		assert.equal(fs.existsSync(journalFile()), false);
		appendJournal(tmp, entry({ ts: "2025-03-01T10:00:00.000Z" }));
		assert.equal(fs.existsSync(journalFile()), true);
	});

	it("writes one JSON object per line", () => {
		appendJournal(tmp, entry({ ts: "2025-03-01T10:00:01.000Z", tool: "cyber_dns" }));
		const lines = fs.readFileSync(journalFile(), "utf8").split("\n").filter((line) => line.length > 0);
		assert.equal(lines.length, 2);
		for (const line of lines) {
			const parsed = JSON.parse(line) as JournalEntry;
			assert.equal(typeof parsed.ts, "string");
			assert.equal(typeof parsed.tool, "string");
			assert.equal(typeof parsed.action, "string");
		}
	});

	it("keeps every optional field it was given", () => {
		appendJournal(
			tmp,
			entry({
				ts: "2025-03-01T10:00:02.000Z",
				tool: "cyber_sqli",
				action: "web-testing",
				target: "https://example.com/login",
				command: "sqlmap -u https://example.com/login",
				exitCode: 0,
				durationMs: 1234,
				summary: "parameter uid is injectable",
				severity: "high",
				artifact: "artifacts/sqli.txt",
				tags: ["sqli", "web"],
			}),
		);
		const stored = readJournal(tmp).find((item) => item.tool === "cyber_sqli");
		assert.ok(stored);
		assert.equal(stored.target, "https://example.com/login");
		assert.equal(stored.command, "sqlmap -u https://example.com/login");
		assert.equal(stored.exitCode, 0);
		assert.equal(stored.durationMs, 1234);
		assert.equal(stored.summary, "parameter uid is injectable");
		assert.equal(stored.severity, "high");
		assert.equal(stored.artifact, "artifacts/sqli.txt");
		assert.deepEqual(stored.tags, ["sqli", "web"]);
	});

	it("omits optional fields that were not given", () => {
		appendJournal(tmp, entry({ ts: "2025-03-01T10:00:03.000Z", tool: "cyber_minimal" }));
		const raw = fs.readFileSync(journalFile(), "utf8").split("\n").filter((line) => line.includes("cyber_minimal"));
		assert.equal(raw.length, 1);
		const parsed = JSON.parse(raw[0]) as Record<string, unknown>;
		assert.deepEqual(Object.keys(parsed), ["ts", "tool", "action"]);
	});
});

describe("reading entries", () => {
	it("returns an empty list when the journal does not exist", () => {
		const empty = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-journal-empty-"));
		const previous = process.env.CYBERPI_ENGAGEMENT;
		try {
			process.env.CYBERPI_ENGAGEMENT = empty;
			assert.deepEqual(readJournal(empty), []);
		} finally {
			if (previous === undefined) delete process.env.CYBERPI_ENGAGEMENT;
			else process.env.CYBERPI_ENGAGEMENT = previous;
			fs.rmSync(empty, { recursive: true, force: true });
		}
	});

	it("preserves the order in which the entries were appended", () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-journal-order-"));
		const previous = process.env.CYBERPI_ENGAGEMENT;
		try {
			process.env.CYBERPI_ENGAGEMENT = dir;
			for (let index = 1; index <= 5; index++) {
				appendJournal(dir, entry({ ts: `2025-03-01T10:00:0${index}.000Z`, tool: `cyber_tool_${index}` }));
			}
			const entries = readJournal(dir);
			assert.equal(entries.length, 5);
			assert.deepEqual(
				entries.map((item) => item.tool),
				["cyber_tool_1", "cyber_tool_2", "cyber_tool_3", "cyber_tool_4", "cyber_tool_5"],
			);
			assert.deepEqual(
				entries.map((item) => item.ts),
				[
					"2025-03-01T10:00:01.000Z",
					"2025-03-01T10:00:02.000Z",
					"2025-03-01T10:00:03.000Z",
					"2025-03-01T10:00:04.000Z",
					"2025-03-01T10:00:05.000Z",
				],
			);
		} finally {
			if (previous === undefined) delete process.env.CYBERPI_ENGAGEMENT;
			else process.env.CYBERPI_ENGAGEMENT = previous;
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it("skips malformed lines but keeps the good ones", () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-journal-broken-"));
		const previous = process.env.CYBERPI_ENGAGEMENT;
		try {
			process.env.CYBERPI_ENGAGEMENT = dir;
			fs.mkdirSync(path.join(dir, ".cyberpi"), { recursive: true });
			fs.writeFileSync(
				path.join(dir, ".cyberpi", "journal.jsonl"),
				[
					JSON.stringify(entry({ ts: "2025-03-01T10:00:00.000Z", tool: "cyber_first" })),
					"{ this is not json",
					"",
					"not json at all",
					JSON.stringify(entry({ ts: "2025-03-01T10:00:02.000Z", tool: "cyber_last" })),
					"",
				].join("\n"),
				"utf8",
			);
			const entries = readJournal(dir);
			assert.equal(entries.length, 2);
			assert.equal(entries[0].tool, "cyber_first");
			assert.equal(entries[1].tool, "cyber_last");
		} finally {
			if (previous === undefined) delete process.env.CYBERPI_ENGAGEMENT;
			else process.env.CYBERPI_ENGAGEMENT = previous;
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("journal statistics", () => {
	it("counts the entries per tool and per severity", () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-journal-stats-"));
		const previous = process.env.CYBERPI_ENGAGEMENT;
		try {
			process.env.CYBERPI_ENGAGEMENT = dir;
			appendJournal(dir, entry({ ts: "2025-03-01T10:00:00.000Z", tool: "cyber_portscan", severity: "info" }));
			appendJournal(dir, entry({ ts: "2025-03-01T10:00:01.000Z", tool: "cyber_portscan", severity: "medium" }));
			appendJournal(dir, entry({ ts: "2025-03-01T10:00:02.000Z", tool: "cyber_dns", severity: "high" }));
			appendJournal(dir, entry({ ts: "2025-03-01T10:00:03.000Z", tool: "cyber_dns" }));

			const stats = journalStats(dir);
			assert.equal(stats.total, 4);
			assert.deepEqual(stats.byTool, { cyber_portscan: 2, cyber_dns: 2 });
			assert.deepEqual(stats.bySeverity, { info: 2, medium: 1, high: 1 });
			assert.equal(stats.first, "2025-03-01T10:00:00.000Z");
			assert.equal(stats.last, "2025-03-01T10:00:03.000Z");
		} finally {
			if (previous === undefined) delete process.env.CYBERPI_ENGAGEMENT;
			else process.env.CYBERPI_ENGAGEMENT = previous;
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it("counts an entry without a severity as info", () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-journal-severity-"));
		const previous = process.env.CYBERPI_ENGAGEMENT;
		try {
			process.env.CYBERPI_ENGAGEMENT = dir;
			appendJournal(dir, entry({ ts: "2025-03-01T11:00:00.000Z", tool: "cyber_nmap" }));
			const stats = journalStats(dir);
			assert.equal(stats.total, 1);
			assert.equal(stats.bySeverity.info, 1);
			assert.equal(stats.byTool.cyber_nmap, 1);
		} finally {
			if (previous === undefined) delete process.env.CYBERPI_ENGAGEMENT;
			else process.env.CYBERPI_ENGAGEMENT = previous;
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it("returns empty statistics for an empty journal", () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-journal-nostats-"));
		const previous = process.env.CYBERPI_ENGAGEMENT;
		try {
			process.env.CYBERPI_ENGAGEMENT = dir;
			const stats = journalStats(dir);
			assert.equal(stats.total, 0);
			assert.deepEqual(stats.bySeverity, {});
			assert.deepEqual(stats.byTool, {});
			assert.equal(stats.first, undefined);
			assert.equal(stats.last, undefined);
		} finally {
			if (previous === undefined) delete process.env.CYBERPI_ENGAGEMENT;
			else process.env.CYBERPI_ENGAGEMENT = previous;
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("artifacts", () => {
	it("writes a file into the engagement artifact directory", () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-journal-artifact-"));
		const previous = process.env.CYBERPI_ENGAGEMENT;
		try {
			process.env.CYBERPI_ENGAGEMENT = dir;
			const file = writeArtifact(dir, "nmap.txt", "host 10.0.0.1 is up");
			assert.equal(file, path.join(dir, ".cyberpi", "artifacts", "nmap.txt"));
			assert.equal(fs.readFileSync(file, "utf8"), "host 10.0.0.1 is up");
		} finally {
			if (previous === undefined) delete process.env.CYBERPI_ENGAGEMENT;
			else process.env.CYBERPI_ENGAGEMENT = previous;
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
