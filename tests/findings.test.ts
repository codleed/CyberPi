/**
 * Finding record tests.
 *
 * A finding is written as a Markdown file with YAML frontmatter, so the
 * renderer and the parser must be exact inverses of each other: whatever the
 * agent records is what the report generator later reads back.
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import {
	listFindings,
	nextFindingId,
	parseFinding,
	renderFinding,
	saveFinding,
	type Finding,
} from "../extensions/lib/findings.ts";

const originalEngagement = process.env.CYBERPI_ENGAGEMENT;
let tmp = "";

before(() => {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-findings-"));
	process.env.CYBERPI_ENGAGEMENT = tmp;
});

after(() => {
	if (originalEngagement === undefined) delete process.env.CYBERPI_ENGAGEMENT;
	else process.env.CYBERPI_ENGAGEMENT = originalEngagement;
	if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
});

function completeFinding(overrides: Partial<Finding> = {}): Finding {
	return {
		id: "F-001",
		title: "SQL injection in the login form",
		severity: "high",
		cvss: 8.8,
		cve: "CVE-2024-0001",
		cwe: "CWE-89",
		target: "https://example.com/login",
		status: "confirmed",
		description: "The uid parameter is concatenated into a SQL query without parameterization.",
		impact: "Any authenticated user can read the whole user table.",
		reproduction: "curl -X POST 'https://example.com/login' -d 'uid=1' -d 'pwd=x'",
		evidence: ["HTTP 500 with an SQL syntax error", "uid=1' returns a different response"],
		references: ["https://cwe.mitre.org/data/definitions/89.html"],
		tags: ["web", "sqli"],
		createdAt: "2025-03-01T10:00:00.000Z",
		updatedAt: "2025-03-01T11:30:00.000Z",
		...overrides,
	};
}

describe("rendering and parsing a finding", () => {
	it("produces a document with frontmatter", () => {
		const document = renderFinding(completeFinding());
		assert.ok(document.startsWith("---\n"));
		assert.match(document, /\n---\n/);
		assert.match(document, /^# SQL injection in the login form$/m);
		assert.match(document, /^## Description$/m);
	});

	it("parses back into an equal object", () => {
		const finding = completeFinding();
		const parsed = parseFinding(renderFinding(finding));
		assert.deepStrictEqual(parsed, finding);
	});

	it("round-trips a minimal finding", () => {
		const finding: Finding = {
			id: "F-042",
			title: "Missing security header",
			severity: "info",
			target: "example.com",
			status: "open",
			description: "The response has no X-Frame-Options header.",
			createdAt: "2025-03-02T08:00:00.000Z",
			updatedAt: "2025-03-02T08:00:00.000Z",
		};
		const parsed = parseFinding(renderFinding(finding));
		assert.equal(parsed.id, "F-042");
		assert.equal(parsed.title, "Missing security header");
		assert.equal(parsed.severity, "info");
		assert.equal(parsed.target, "example.com");
		assert.equal(parsed.status, "open");
		assert.equal(parsed.description, "The response has no X-Frame-Options header.");
		assert.equal(parsed.cvss, undefined);
		assert.equal(parsed.cve, undefined);
	});

	it("keeps quotes and backslashes inside a title", () => {
		const finding = completeFinding({ title: 'Reflected XSS in "search" \\ parameter' });
		const parsed = parseFinding(renderFinding(finding));
		assert.equal(parsed.title, 'Reflected XSS in "search" \\ parameter');
	});

	it("falls back to info for an unknown severity and open for an unknown status", () => {
		const document = [
			"---",
			"id: F-100",
			'title: "Odd"',
			"severity: apocalyptic",
			"target: example.com",
			"status: invented",
			"createdAt: 2025-03-01T10:00:00.000Z",
			"updatedAt: 2025-03-01T10:00:00.000Z",
			"---",
			"",
			"# Odd",
			"",
		].join("\n");
		const parsed = parseFinding(document);
		assert.equal(parsed.severity, "info");
		assert.equal(parsed.status, "invented");
	});

	it("rejects a document without frontmatter", () => {
		assert.throws(() => parseFinding("# just a heading\n"), /missing frontmatter/);
	});
});

describe("listing findings", () => {
	it("returns an empty list when there are none", () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-findings-empty-"));
		const previous = process.env.CYBERPI_ENGAGEMENT;
		try {
			process.env.CYBERPI_ENGAGEMENT = dir;
			assert.deepEqual(listFindings(dir), []);
		} finally {
			if (previous === undefined) delete process.env.CYBERPI_ENGAGEMENT;
			else process.env.CYBERPI_ENGAGEMENT = previous;
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it("sorts by severity, from critical to info", () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-findings-order-"));
		const previous = process.env.CYBERPI_ENGAGEMENT;
		try {
			process.env.CYBERPI_ENGAGEMENT = dir;
			saveFinding(dir, completeFinding({ id: "F-001", severity: "low" }));
			saveFinding(dir, completeFinding({ id: "F-002", severity: "critical" }));
			saveFinding(dir, completeFinding({ id: "F-003", severity: "info" }));
			saveFinding(dir, completeFinding({ id: "F-004", severity: "high" }));
			saveFinding(dir, completeFinding({ id: "F-005", severity: "medium" }));

			const findings = listFindings(dir);
			assert.deepEqual(
				findings.map((item) => `${item.id}:${item.severity}`),
				["F-002:critical", "F-004:high", "F-005:medium", "F-001:low", "F-003:info"],
			);
		} finally {
			if (previous === undefined) delete process.env.CYBERPI_ENGAGEMENT;
			else process.env.CYBERPI_ENGAGEMENT = previous;
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it("breaks a severity tie on the finding id", () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-findings-tie-"));
		const previous = process.env.CYBERPI_ENGAGEMENT;
		try {
			process.env.CYBERPI_ENGAGEMENT = dir;
			saveFinding(dir, completeFinding({ id: "F-010", severity: "high" }));
			saveFinding(dir, completeFinding({ id: "F-002", severity: "high" }));
			saveFinding(dir, completeFinding({ id: "F-007", severity: "high" }));
			const findings = listFindings(dir);
			assert.deepEqual(
				findings.map((item) => item.id),
				["F-002", "F-007", "F-010"],
			);
		} finally {
			if (previous === undefined) delete process.env.CYBERPI_ENGAGEMENT;
			else process.env.CYBERPI_ENGAGEMENT = previous;
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it("skips files that are not findings", () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-findings-junk-"));
		const previous = process.env.CYBERPI_ENGAGEMENT;
		try {
			process.env.CYBERPI_ENGAGEMENT = dir;
			saveFinding(dir, completeFinding({ id: "F-001" }));
			fs.writeFileSync(path.join(dir, ".cyberpi", "findings", "notes.txt"), "not a finding", "utf8");
			fs.writeFileSync(path.join(dir, ".cyberpi", "findings", "broken.md"), "no frontmatter here", "utf8");
			const findings = listFindings(dir);
			assert.equal(findings.length, 1);
			assert.equal(findings[0].id, "F-001");
		} finally {
			if (previous === undefined) delete process.env.CYBERPI_ENGAGEMENT;
			else process.env.CYBERPI_ENGAGEMENT = previous;
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("finding id allocation", () => {
	it("starts at F-001 in an empty engagement", () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-findings-id-"));
		const previous = process.env.CYBERPI_ENGAGEMENT;
		try {
			process.env.CYBERPI_ENGAGEMENT = dir;
			assert.equal(nextFindingId(dir), "F-001");
		} finally {
			if (previous === undefined) delete process.env.CYBERPI_ENGAGEMENT;
			else process.env.CYBERPI_ENGAGEMENT = previous;
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it("continues after the highest existing number", () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-findings-next-"));
		const previous = process.env.CYBERPI_ENGAGEMENT;
		try {
			process.env.CYBERPI_ENGAGEMENT = dir;
			assert.equal(nextFindingId(dir), "F-001");
			saveFinding(dir, completeFinding({ id: "F-001" }));
			assert.equal(nextFindingId(dir), "F-002");
			saveFinding(dir, completeFinding({ id: "F-002" }));
			assert.equal(nextFindingId(dir), "F-003");
		} finally {
			if (previous === undefined) delete process.env.CYBERPI_ENGAGEMENT;
			else process.env.CYBERPI_ENGAGEMENT = previous;
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it("does not reuse a number when a low id was deleted", () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-findings-reuse-"));
		const previous = process.env.CYBERPI_ENGAGEMENT;
		try {
			process.env.CYBERPI_ENGAGEMENT = dir;
			saveFinding(dir, completeFinding({ id: "F-001" }));
			saveFinding(dir, completeFinding({ id: "F-009" }));
			fs.rmSync(path.join(dir, ".cyberpi", "findings", "F-001.md"));
			assert.equal(nextFindingId(dir), "F-010");
		} finally {
			if (previous === undefined) delete process.env.CYBERPI_ENGAGEMENT;
			else process.env.CYBERPI_ENGAGEMENT = previous;
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
