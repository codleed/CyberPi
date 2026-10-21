/**
 * Resource verification against the real Pi resource loader.
 *
 * Loads the CyberPi package the way Pi does - extensions, skills, prompt
 * templates and themes - and reports every diagnostic. A diagnostic here is a
 * resource that Pi would silently skip at startup.
 *
 * Usage: node scripts/verify-resources.mjs
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DefaultResourceLoader } from "@earendil-works/pi-coding-agent";

const root = path.resolve(import.meta.dirname, "..");
const agentDir = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-agent-"));

const loader = new DefaultResourceLoader({
	cwd: root,
	agentDir,
	additionalExtensionPaths: [path.join(root, "extensions", "index.ts")],
	additionalSkillPaths: [path.join(root, "skills")],
	additionalPromptTemplatePaths: [path.join(root, "prompts")],
	additionalThemePaths: [path.join(root, "themes")],
});

await loader.reload();

const extensions = loader.getExtensions();
const skills = loader.getSkills();
const prompts = loader.getPrompts();
const themes = loader.getThemes();

let failures = 0;

function report(label, diagnostics) {
	const real = diagnostics.filter((diagnostic) => diagnostic.severity === "error" || diagnostic.severity === "warning");
	if (real.length === 0) {
		console.log(`ok    ${label}`);
		return;
	}
	failures += real.length;
	for (const diagnostic of real) {
		console.log(`${diagnostic.severity === "error" ? "FAIL" : "warn"}  ${label}: ${diagnostic.message}`);
	}
}

console.log(`extensions loaded: ${extensions.extensions.length}`);
console.log(`skills loaded:     ${skills.skills.length}`);
console.log(`prompts loaded:    ${prompts.prompts.length}`);
console.log(`themes loaded:     ${themes.themes.map((theme) => theme.name).join(", ")}`);
console.log("");

for (const error of extensions.errors ?? []) {
	failures++;
	console.log(`FAIL  extension: ${error.path}: ${error.error}`);
}
for (const warning of extensions.warnings ?? []) {
	console.log(`warn  extension: ${warning.path}: ${warning.warning}`);
}
if ((extensions.errors ?? []).length === 0) {
	console.log("ok    extensions");
}

report("skills", skills.diagnostics);
report("prompts", prompts.diagnostics);
report("themes", themes.diagnostics);

const toolNames = extensions.extensions.flatMap((extension) => [...extension.tools.keys()]);
if (toolNames.length > 0) {
	console.log(`\ntools registered by the extension: ${toolNames.length}`);
}

fs.rmSync(agentDir, { recursive: true, force: true });

if (failures > 0) {
	console.log(`\n${failures} diagnostic(s) need attention`);
	process.exit(1);
}
console.log("\nall resources load cleanly");
