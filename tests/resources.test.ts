/**
 * Resource validation.
 *
 * Pi discovers skills, prompt templates, themes and package resources from the
 * filesystem. A malformed file is skipped with a warning at startup, so these
 * checks guard against a resource that silently never loads.
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

const ROOT = path.resolve(import.meta.dirname, "..");

function readFrontmatter(file: string): { name?: string; description?: string; body: string } {
	const raw = fs.readFileSync(file, "utf8");
	const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/.exec(raw);
	assert.ok(match, `${file} must start with YAML frontmatter`);
	const fields: Record<string, string> = {};
	for (const line of match[1].split("\n")) {
		const index = line.indexOf(":");
		if (index === -1) continue;
		fields[line.slice(0, index).trim()] = line.slice(index + 1).trim();
	}
	return { name: fields.name, description: fields.description, body: match[2] };
}

test("every skill has valid frontmatter and a body", () => {
	const skillsDir = path.join(ROOT, "skills");
	const directories = fs
		.readdirSync(skillsDir, { withFileTypes: true })
		.filter((entry) => entry.isDirectory())
		.map((entry) => entry.name);
	assert.ok(directories.length >= 15, "the harness must ship the full skill set");
	for (const directory of directories) {
		const file = path.join(skillsDir, directory, "SKILL.md");
		assert.ok(fs.existsSync(file), `${directory} must contain SKILL.md`);
		const { name, description, body } = readFrontmatter(file);
		assert.equal(name, directory, `${directory}: the skill name must match its directory`);
		assert.match(name ?? "", /^[a-z0-9]+(-[a-z0-9]+)*$/, `${directory}: invalid skill name`);
		assert.ok(description && description.length > 40, `${directory}: the description must explain when to use it`);
		assert.ok(body.trim().length > 200, `${directory}: the skill body is too short to be useful`);
	}
});

test("every skill references the tools it can use", () => {
	const skillsDir = path.join(ROOT, "skills");
	for (const directory of fs.readdirSync(skillsDir)) {
		const file = path.join(skillsDir, directory, "SKILL.md");
		if (!fs.existsSync(file)) continue;
		const raw = fs.readFileSync(file, "utf8");
		assert.match(raw, /cyber_[a-z0-9_]+/, `${directory}: the skill must name the tools it uses`);
	}
});

test("every prompt template has a description", () => {
	const promptsDir = path.join(ROOT, "prompts");
	const files = fs.readdirSync(promptsDir).filter((file) => file.endsWith(".md"));
	assert.ok(files.length >= 10, "the harness must ship the prompt set");
	for (const file of files) {
		const { description, body } = readFrontmatter(path.join(promptsDir, file));
		assert.ok(description && description.length > 10, `${file}: the description must be present`);
		assert.ok(body.trim().length > 20, `${file}: the template body is too short`);
	}
});

test("the cyber theme is valid", () => {
	const themePath = path.join(ROOT, "themes", "cyber.json");
	assert.ok(fs.existsSync(themePath));
	const theme = JSON.parse(fs.readFileSync(themePath, "utf8")) as {
		name?: string;
		appearance?: string;
		colors?: Record<string, string>;
		vars?: Record<string, string>;
	};
	assert.equal(theme.name, "cyber");
	assert.equal(theme.appearance, "dark");
	assert.ok(theme.colors, "the theme needs colors");
	for (const role of ["accent", "text", "muted", "success", "error", "warning", "border"]) {
		assert.ok(theme.colors[role], `the theme needs the ${role} color`);
	}
});

function listFiles(dir: string, prefix = ""): string[] {
	const entries: string[] = [];
	for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
		if (entry.name === "node_modules" || entry.name.startsWith(".")) continue;
		const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
		if (entry.isDirectory()) entries.push(...listFiles(path.join(dir, entry.name), relative));
		else entries.push(relative);
	}
	return entries;
}

test("the package manifest points at resources that exist", () => {
	const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8")) as {
		pi?: { extensions?: string[]; skills?: string[]; prompts?: string[]; themes?: string[] };
	};
	const pi = manifest.pi;
	assert.ok(pi, "the package needs a pi manifest");
	assert.deepEqual(pi.extensions, ["./extensions/**/*.ts"], "the manifest must load the whole extension tree");
	assert.deepEqual(pi.skills, ["./skills"], "the manifest must load the skills directory");
	assert.deepEqual(pi.prompts, ["./prompts/*.md"], "the manifest must load the prompt templates");
	assert.deepEqual(pi.themes, ["./themes/*.json"], "the manifest must load the themes");

	const files = listFiles(ROOT);
	const extensionFiles = files.filter((file) => file.startsWith("extensions/") && file.endsWith(".ts"));
	assert.ok(extensionFiles.length >= 20, `expected the extension tree, found ${extensionFiles.length} files`);
	assert.ok(extensionFiles.includes("extensions/index.ts"), "the main extension must be in the tree");
	assert.ok(
		extensionFiles.some((file) => file.startsWith("extensions/tools/")),
		"the tool modules must be in the tree",
	);

	const promptFiles = files.filter((file) => file.startsWith("prompts/") && file.endsWith(".md"));
	assert.ok(promptFiles.length >= 10, `expected the prompt set, found ${promptFiles.length} files`);

	const themeFiles = files.filter((file) => file.startsWith("themes/") && file.endsWith(".json"));
	assert.ok(themeFiles.includes("themes/cyber.json"), "the cyber theme must be in the tree");
});

test("the documentation set is complete", () => {
	for (const file of [
		"README.md",
		"docs/PLAN.md",
		"docs/INSTALL.md",
		"docs/USAGE.md",
		"docs/TROUBLESHOOTING.md",
		"docs/TOOLING.md",
		"docs/TOOL-REGISTRY.md",
		"docs/ARCHITECTURE.md",
		"docs/DEVELOPMENT.md",
		"docs/SECURITY.md",
		"docs/ENGAGEMENT.md",
	]) {
		const full = path.join(ROOT, file);
		assert.ok(fs.existsSync(full), `${file} is missing`);
		assert.ok(fs.statSync(full).size > 500, `${file} is too short to be useful`);
	}
});
