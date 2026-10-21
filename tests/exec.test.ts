/**
 * Command execution tests.
 *
 * The runner is what every tool depends on, so it is tested against real
 * processes: a real exit code, real stderr, a real timeout and a real
 * truncation. Nothing here is mocked.
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import {
	DEFAULT_MAX_BYTES,
	formatCommand,
	missingBinaries,
	run,
	truncateOutput,
	which,
} from "../extensions/lib/exec.ts";

let tmp = "";

before(() => {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-exec-"));
});

after(() => {
	if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
});

describe("running a command", () => {
	it("captures stdout of a short command", async () => {
		const result = await run(process.execPath, ["-e", "process.stdout.write('ok')"]);
		assert.equal(result.stdout, "ok");
		assert.equal(result.stderr, "");
		assert.equal(result.code, 0);
		assert.equal(result.signal, null);
		assert.equal(result.timedOut, false);
		assert.equal(result.truncated, false);
	});

	it("captures stderr and the exit code", async () => {
		const result = await run(process.execPath, [
			"-e",
			"process.stderr.write('boom'); process.exit(3);",
		]);
		assert.equal(result.code, 3);
		assert.equal(result.stderr, "boom");
		assert.equal(result.stdout, "");
		assert.equal(result.timedOut, false);
	});

	it("reports a command that does not exist instead of throwing", async () => {
		const result = await run("cyberpi-no-such-binary-9f2a", ["--version"]);
		assert.equal(result.code, null);
		assert.match(result.stderr, /command not found/);
	});

	it("records the command line it ran", async () => {
		const result = await run(process.execPath, ["-e", "process.stdout.write('x')"]);
		assert.equal(result.bin, process.execPath);
		assert.deepEqual(result.args, ["-e", "process.stdout.write('x')"]);
		assert.match(result.cmd, /-e/);
	});

	it("keeps the full output in the artifact file", async () => {
		const artifactDir = path.join(tmp, "artifacts");
		const result = await run(process.execPath, ["-e", "process.stdout.write('artifact-body')"], {
			artifactDir,
			artifactName: "sample.txt",
		});
		assert.ok(result.artifact);
		assert.equal(result.artifact, path.join(artifactDir, "sample.txt"));
		assert.equal(fs.readFileSync(result.artifact, "utf8"), "artifact-body");
	});
});

describe("timeouts", () => {
	it("kills a command that runs past the timeout", async () => {
		const result = await run(process.execPath, ["-e", "setTimeout(() => {}, 30000)"], { timeoutMs: 300 });
		assert.equal(result.timedOut, true);
		assert.notEqual(result.code, 0);
		assert.ok(result.durationMs < 20_000, `expected a prompt kill, took ${result.durationMs}ms`);
	});

	it("does not time out a command that finishes in time", async () => {
		const result = await run(process.execPath, ["-e", "process.stdout.write('quick')"], { timeoutMs: 10_000 });
		assert.equal(result.timedOut, false);
		assert.equal(result.stdout, "quick");
	});
});

describe("truncation", () => {
	it("cuts the output down to the byte budget", async () => {
		const result = await run(process.execPath, ["-e", "process.stdout.write('x'.repeat(5000))"], {
			maxBytes: 1000,
		});
		assert.equal(result.truncated, true);
		assert.ok(result.stdout.length < 5000, `expected a shortened output, got ${result.stdout.length} chars`);
		assert.match(result.stdout, /bytes omitted/);
	});

	it("keeps the head and the tail of a truncated output", () => {
		const text = `${"a".repeat(400)}${"b".repeat(400)}`;
		const truncated = truncateOutput(text, 200);
		assert.equal(truncated.truncated, true);
		assert.ok(truncated.text.startsWith("a"));
		assert.ok(truncated.text.endsWith("b"));
		assert.match(truncated.text, /bytes omitted/);
	});

	it("leaves an output that fits untouched", () => {
		const truncated = truncateOutput("short output", 1000);
		assert.equal(truncated.truncated, false);
		assert.equal(truncated.text, "short output");
	});

	it("uses a default byte budget", () => {
		assert.equal(typeof DEFAULT_MAX_BYTES, "number");
		assert.ok(DEFAULT_MAX_BYTES > 0);
		const truncated = truncateOutput("y".repeat(DEFAULT_MAX_BYTES + 100));
		assert.equal(truncated.truncated, true);
	});
});

describe("locating binaries", () => {
	const binName = "cyberpi-test-bin";
	let binDir = "";
	let previousPath: string | undefined;

	before(() => {
		binDir = path.join(tmp, "bin");
		fs.mkdirSync(binDir, { recursive: true });
		fs.writeFileSync(path.join(binDir, binName), "#!/bin/sh\nexit 0\n", {
			encoding: "utf8",
			mode: 0o755,
		});
		previousPath = process.env.PATH;
		process.env.PATH = [
			binDir,
			path.dirname(process.execPath),
			previousPath ?? "",
		].join(path.delimiter);
	});

	after(() => {
		if (previousPath === undefined) delete process.env.PATH;
		else process.env.PATH = previousPath;
	});

	it("finds a real binary on PATH", () => {
		const found = which(binName);
		assert.ok(found, "expected the test binary to be found on PATH");
		assert.equal(path.resolve(found), path.resolve(path.join(binDir, binName)));
	});

	it("finds the node binary that is running the tests", () => {
		const found = which(path.basename(process.execPath));
		assert.ok(found, "expected the node binary to be found on PATH");
		assert.ok(fs.existsSync(found), `expected ${found} to exist`);
	});

	it("returns null for a binary that is not installed", () => {
		assert.equal(which("cyberpi-no-such-binary-9f2a"), null);
	});

	it("reports the missing binaries of a list", () => {
		const missing = missingBinaries([binName, "cyberpi-no-such-binary-9f2a"]);
		assert.deepEqual(missing, ["cyberpi-no-such-binary-9f2a"]);
	});

	it("reports nothing missing when every binary is installed", () => {
		assert.deepEqual(missingBinaries([binName]), []);
	});
});

describe("command formatting", () => {
	it("quotes arguments that contain shell metacharacters", () => {
		assert.equal(formatCommand("nmap", ["-sS", "10.0.0.1"]), "nmap -sS 10.0.0.1");
		assert.equal(formatCommand("nmap", ["-oN", "scan results.txt"]), "nmap -oN 'scan results.txt'");
		assert.equal(formatCommand("sh", ["-c", "echo hi"]), "sh -c 'echo hi'");
	});
});
