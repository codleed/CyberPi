/**
 * Load the CyberPi package with Pi's own resource loader.
 *
 * This is the closest thing to starting Pi without a model: the real loader
 * discovers the extensions, skills, prompt templates and themes exactly the
 * way Pi does at startup, so a resource that Pi would reject fails here.
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { DefaultResourceLoader } from "@earendil-works/pi-coding-agent";

const ROOT = path.resolve(import.meta.dirname, "..");

function createLoader() {
	const agentDir = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-loader-"));
	const loader = new DefaultResourceLoader({
		cwd: ROOT,
		agentDir,
		additionalExtensionPaths: [path.join(ROOT, "extensions", "index.ts")],
		additionalSkillPaths: [path.join(ROOT, "skills")],
		additionalPromptTemplatePaths: [path.join(ROOT, "prompts")],
		additionalThemePaths: [path.join(ROOT, "themes", "cyber.json")],
	});
	return { loader, agentDir };
}

test("the CyberPi extension loads without errors", async () => {
	const { loader, agentDir } = createLoader();
	try {
		await loader.reload();
		const result = loader.getExtensions();
		assert.deepEqual(result.errors, [], "the extension must load without errors");
		assert.ok(result.extensions.length >= 1, "the extension must be discovered");
	} finally {
		fs.rmSync(agentDir, { recursive: true, force: true });
	}
});

test("the CyberPi skills are discovered and valid", async () => {
	const { loader, agentDir } = createLoader();
	try {
		await loader.reload();
		const { skills, diagnostics } = loader.getSkills();
		const ours = skills.filter((skill) => skill.baseDir.startsWith(path.join(ROOT, "skills")));
		assert.equal(ours.length, 17, `expected 17 CyberPi skills, found ${ours.length}`);
		const errors = diagnostics.filter((diagnostic) => (diagnostic.path ?? "").startsWith(path.join(ROOT, "skills")));
		assert.deepEqual(errors, [], "no skill may produce a diagnostic");
	} finally {
		fs.rmSync(agentDir, { recursive: true, force: true });
	}
});

test("the CyberPi prompt templates are discovered and valid", async () => {
	const { loader, agentDir } = createLoader();
	try {
		await loader.reload();
		const { prompts, diagnostics } = loader.getPrompts();
		const ours = prompts.filter((prompt) => prompt.filePath.startsWith(path.join(ROOT, "prompts")));
		assert.equal(ours.length, 12, `expected 12 prompt templates, found ${ours.length}`);
		const errors = diagnostics.filter((diagnostic) => (diagnostic.path ?? "").startsWith(path.join(ROOT, "prompts")));
		assert.deepEqual(errors, [], "no prompt template may produce a diagnostic");
	} finally {
		fs.rmSync(agentDir, { recursive: true, force: true });
	}
});

test("the cyber theme is accepted by Pi", async () => {
	const { loader, agentDir } = createLoader();
	try {
		await loader.reload();
		const { themes, diagnostics } = loader.getThemes();
		assert.deepEqual(diagnostics, [], "the theme must not produce a diagnostic");
		const cyber = themes.find((theme) => theme.name === "cyber");
		assert.ok(cyber, "the cyber theme must be loaded");
	} finally {
		fs.rmSync(agentDir, { recursive: true, force: true });
	}
});
