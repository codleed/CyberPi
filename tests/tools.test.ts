/**
 * End-to-end behaviour of the CyberPi tools.
 *
 * These tests drive the real tool definitions with a mock agent context:
 * the scope gate, the technique gate, the binary gate, the finding record
 * and the report generator. They are the tests that prove the harness does
 * what it claims, not just that it compiles.
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import type { ExtensionToolContext } from "@earendil-works/pi-coding-agent";
import { engagementPaths } from "../extensions/lib/config.ts";
import { setPlatformInfoForTesting } from "../extensions/lib/platform.ts";
import { networkTools } from "../extensions/tools/network.ts";
import { reportTools } from "../extensions/tools/report.ts";

function findTool(name: string) {
	const tool = reportTools.find((item) => item.name === name);
	if (!tool) throw new Error(`tool ${name} is not registered`);
	return tool;
}

const recordFindingTool = findTool("cyber_record_finding");
const reportTool = findTool("cyber_report");

/**
 * The harness refuses to run on anything but Kali Linux. The tests exercise
 * the engagement logic, so they declare a Kali platform for the duration of
 * the run. The seam is code level, not an environment switch.
 */
setPlatformInfoForTesting({
	platform: "linux",
	arch: "x64",
	kernel: "6.6.0",
	distro: "Kali GNU/Linux Rolling",
	distroId: "kali",
	distroName: "Kali GNU/Linux Rolling",
	distroVersion: "2025.1",
	isLinux: true,
	isKali: true,
});

function mockContext(cwd: string): ExtensionToolContext {
	return {
		cwd,
		mode: "print",
		hasUI: false,
		ui: {
			notify() {},
			setStatus() {},
		},
		isIdle: () => true,
		isProjectTrusted: () => true,
		signal: undefined,
		abort() {},
		hasPendingMessages: () => false,
		shutdown() {},
		getContextUsage: () => undefined,
		compact() {},
		getSystemPrompt: () => "",
	} as unknown as ExtensionToolContext;
}

function createEngagement(scope: unknown): string {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-eng-"));
	const paths = engagementPaths(root);
	fs.mkdirSync(paths.dir, { recursive: true });
	fs.writeFileSync(paths.scope, JSON.stringify(scope, null, 2), "utf8");
	return root;
}

const baseScope = {
	engagement: "test-engagement",
	client: "Test Client",
	rules: [{ target: "10.10.0.0/24" }],
	techniques: ["recon", "port-scan"],
};

/** The same engagement with the port-scan technique taken away. */
const noPortScanScope = { ...baseScope, techniques: ["recon"] };

test("a target outside the authorized scope is refused", async () => {
	const root = createEngagement(baseScope);
	try {
		const tool = networkTools.find((item) => item.name === "cyber_portscan");
		assert.ok(tool);
		const result = await tool.execute("call-1", { target: "8.8.8.8" }, undefined, undefined, mockContext(root));
		assert.equal(result.isError, true);
		const text = (result.content[0] as { text: string }).text;
		assert.match(text, /not in the authorized scope/i);
	} finally {
		fs.rmSync(root, { recursive: true, force: true });
	}
});

test("a technique outside the allowlist is refused", async () => {
	const root = createEngagement(noPortScanScope);
	try {
		const tool = networkTools.find((item) => item.name === "cyber_portscan");
		assert.ok(tool);
		const result = await tool.execute("call-2", { target: "10.10.0.5" }, undefined, undefined, mockContext(root));
		assert.equal(result.isError, true);
		const text = (result.content[0] as { text: string }).text;
		assert.match(text, /not in the engagement technique allowlist/i);
	} finally {
		fs.rmSync(root, { recursive: true, force: true });
	}
});

test("a blocked action is written to the engagement journal", async () => {
	const root = createEngagement(baseScope);
	try {
		const tool = networkTools.find((item) => item.name === "cyber_portscan");
		assert.ok(tool);
		await tool.execute("call-3", { target: "8.8.8.8" }, undefined, undefined, mockContext(root));
		const journal = fs.readFileSync(engagementPaths(root).journal, "utf8").trim();
		assert.ok(journal.length > 0, "the journal must not be empty");
		const entry = JSON.parse(journal.split("\n")[0]) as { action: string; target?: string };
		assert.equal(entry.action, "blocked");
		assert.equal(entry.target, "8.8.8.8");
	} finally {
		fs.rmSync(root, { recursive: true, force: true });
	}
});

test("with no scope file every target action is refused", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-eng-"));
	try {
		const tool = networkTools.find((item) => item.name === "cyber_portscan");
		assert.ok(tool);
		const result = await tool.execute("call-4", { target: "10.10.0.5" }, undefined, undefined, mockContext(root));
		assert.equal(result.isError, true);
		const text = (result.content[0] as { text: string }).text;
		assert.match(text, /scope\.json/i);
	} finally {
		fs.rmSync(root, { recursive: true, force: true });
	}
});

test("a finding is recorded with an allocated id and rendered to disk", async () => {
	const root = createEngagement(baseScope);
	try {
		const result = await recordFindingTool.execute(
			"call-5",
			{
				title: "Unpatched OpenSSL on the web tier",
				severity: "high",
				target: "10.10.0.5",
				description: "The service reports a vulnerable OpenSSL version.",
				impact: "Remote code execution as the service account.",
				reproduction: "nmap -sV -p 443 10.10.0.5",
				evidence: ["OpenSSL 1.1.1k"],
				cve: "CVE-2022-0778",
				cvss: 7.5,
			},
			undefined,
			undefined,
			mockContext(root),
		);
		assert.notEqual(result.isError, true);
		const details = result.details as { id: string; path: string };
		assert.match(details.id, /^F-\d{3}$/);
		assert.ok(fs.existsSync(details.path), "the finding file must exist");
		const content = fs.readFileSync(details.path, "utf8");
		assert.match(content, /severity: high/);
		assert.match(content, /CVE-2022-0778/);
		assert.match(content, /## Impact/);
	} finally {
		fs.rmSync(root, { recursive: true, force: true });
	}
});

test("the report is generated from the findings and the journal", async () => {
	const root = createEngagement(baseScope);
	try {
		await recordFindingTool.execute(
			"call-6",
			{ title: "Weak SSH ciphers", severity: "medium", target: "10.10.0.9", description: "Legacy ciphers offered." },
			undefined,
			undefined,
			mockContext(root),
		);
		const result = await reportTool.execute(
			"call-7",
			{ format: "markdown", include_journal: true },
			undefined,
			undefined,
			mockContext(root),
		);
		assert.notEqual(result.isError, true);
		const details = result.details as { path: string; findings: number };
		assert.equal(details.findings, 1);
		const report = fs.readFileSync(details.path, "utf8");
		assert.match(report, /Weak SSH ciphers/);
		assert.match(report, /Test Client/);
		assert.match(report, /Appendix/i);
	} finally {
		fs.rmSync(root, { recursive: true, force: true });
	}
});
