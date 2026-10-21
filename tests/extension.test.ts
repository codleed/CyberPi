/**
 * Integration test for the CyberPi extension runtime.
 *
 * Loads the main extension against a mock ExtensionAPI and checks that the
 * harness wires itself up correctly: every tool is registered once, the
 * tools are well formed, the dashboard command exists and the engagement
 * context reaches the system prompt.
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import cyberPi, { cyberTools } from "../extensions/index.ts";

interface RecordedTool {
	name: string;
	label?: string;
	description?: string;
	parameters?: unknown;
	execute?: unknown;
}

function createMockApi() {
	const tools: RecordedTool[] = [];
	const commands: string[] = [];
	const handlers = new Map<string, Array<(event: unknown, ctx: unknown) => unknown>>();
	const api = {
		registerTool(tool: RecordedTool) {
			tools.push(tool);
		},
		registerCommand(name: string) {
			commands.push(name);
		},
		on(event: string, handler: (event: unknown, ctx: unknown) => unknown) {
			const list = handlers.get(event) ?? [];
			list.push(handler);
			handlers.set(event, list);
			return () => {};
		},
	} as unknown as ExtensionAPI;
	return { api, tools, commands, handlers };
}

test("the extension registers every CyberPi tool exactly once", () => {
	const { api, tools } = createMockApi();
	cyberPi(api);
	assert.equal(tools.length, cyberTools.length);
	const names = tools.map((tool) => tool.name);
	assert.equal(new Set(names).size, names.length, "tool names must be unique");
	for (const name of names) {
		assert.match(name, /^cyber_[a-z0-9_]+$/, `${name} must use the cyber_ prefix and snake_case`);
	}
});

test("every registered tool is well formed", () => {
	const { api, tools } = createMockApi();
	cyberPi(api);
	for (const tool of tools) {
		assert.ok(tool.description && tool.description.length > 20, `${tool.name} needs a description`);
		assert.ok(tool.parameters, `${tool.name} needs a parameter schema`);
		assert.equal(typeof tool.execute, "function", `${tool.name} needs an execute function`);
	}
});

test("the dashboard command is registered", () => {
	const { api, commands } = createMockApi();
	cyberPi(api);
	assert.ok(commands.includes("cyber"));
});

test("the engagement context is injected into the system prompt", () => {
	const { api, handlers } = createMockApi();
	cyberPi(api);
	const handler = handlers.get("before_agent_start")?.[0];
	assert.ok(handler, "before_agent_start handler must be registered");

	const root = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-ctx-"));
	try {
		const event = { systemPromptOptions: { sections: {} as Record<string, string> } };
		handler(event, { cwd: root });
		const section = event.systemPromptOptions.sections.engagement;
		assert.ok(section, "the engagement section must be set");
		assert.match(section, /Engagement:/);
		assert.match(section, /Scope/);
	} finally {
		fs.rmSync(root, { recursive: true, force: true });
	}
});
