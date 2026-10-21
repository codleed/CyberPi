/**
 * Command execution helpers.
 *
 * Commands are spawned without a shell so that target names and wordlists can
 * never be interpreted as shell syntax. Output is captured, truncated and
 * (optionally) written to the engagement artifact directory.
 */

import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { ensureDir, engagementPaths } from "./config.ts";

export interface RunOptions {
	cwd?: string;
	timeoutMs?: number;
	env?: Record<string, string>;
	stdin?: string;
	/** Maximum bytes of stdout+stderr kept in memory. */
	maxBytes?: number;
	signal?: AbortSignal;
	/** Engagement directory to write the full output to. */
	artifactDir?: string;
	/** Base name for the artifact file. */
	artifactName?: string;
}

export interface RunResult {
	/** Human readable command line, for display and journal entries. */
	cmd: string;
	bin: string;
	args: string[];
	code: number | null;
	signal: NodeJS.Signals | null;
	stdout: string;
	stderr: string;
	/** True when output was cut down to `maxBytes`. */
	truncated: boolean;
	durationMs: number;
	timedOut: boolean;
	/** Absolute path of the full output file, when one was written. */
	artifact?: string;
}

export const DEFAULT_TIMEOUT_MS = 120_000;
export const DEFAULT_MAX_BYTES = 32_000;

function quoteArg(arg: string): string {
	return /[\s"'$`\\]/.test(arg) ? `'${arg.replace(/'/g, "'\\''")}'` : arg;
}

/** Render a command for display without executing it. */
export function formatCommand(bin: string, args: string[]): string {
	return [bin, ...args].map(quoteArg).join(" ");
}

/** Locate a binary on PATH. */
export function which(bin: string): string | null {
	const delimiter = process.platform === "win32" ? ";" : ":";
	const dirs = (process.env.PATH ?? "").split(delimiter);
	for (const dir of dirs) {
		if (!dir) continue;
		const candidate = path.join(dir, bin);
		try {
			fs.accessSync(candidate, fs.constants.X_OK);
			return candidate;
		} catch {
			continue;
		}
	}
	return null;
}

/** Report which of the given binaries are missing. */
export function missingBinaries(bins: string[]): string[] {
	return bins.filter((bin) => which(bin) === null);
}

/** Truncate text to a byte budget, keeping the head and the tail. */
export function truncateOutput(text: string, maxBytes = DEFAULT_MAX_BYTES): { text: string; truncated: boolean } {
	const buffer = Buffer.from(text, "utf8");
	if (buffer.byteLength <= maxBytes) return { text, truncated: false };
	const head = buffer.subarray(0, Math.floor(maxBytes * 0.7)).toString("utf8");
	const tail = buffer.subarray(buffer.byteLength - Math.floor(maxBytes * 0.25)).toString("utf8");
	const omitted = buffer.byteLength - head.length - tail.length;
	return {
		text: `${head}\n\n[... ${omitted} bytes omitted ...]\n\n${tail}`,
		truncated: true,
	};
}

/**
 * Run a command and capture its output.
 *
 * Never rejects on a non-zero exit: the result carries the exit code so the
 * caller can decide whether the failure matters.
 */
export function run(bin: string, args: string[], options: RunOptions = {}): Promise<RunResult> {
	const started = Date.now();
	const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	return new Promise<RunResult>((resolve) => {
		const child = spawn(bin, args, {
			cwd: options.cwd,
			env: options.env ? { ...process.env, ...options.env } : process.env,
			stdio: ["pipe", "pipe", "pipe"],
		});

		const stdoutChunks: Buffer[] = [];
		const stderrChunks: Buffer[] = [];
		let settled = false;
		let timedOut = false;

		const timer = setTimeout(() => {
			timedOut = true;
			child.kill("SIGKILL");
		}, timeoutMs);

		const onAbort = () => {
			child.kill("SIGKILL");
		};
		options.signal?.addEventListener("abort", onAbort, { once: true });

		child.stdout.on("data", (chunk: Buffer) => stdoutChunks.push(chunk));
		child.stderr.on("data", (chunk: Buffer) => stderrChunks.push(chunk));

		const finish = (code: number | null, signal: NodeJS.Signals | null) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			options.signal?.removeEventListener("abort", onAbort);
			const rawStdout = Buffer.concat(stdoutChunks).toString("utf8");
			const rawStderr = Buffer.concat(stderrChunks).toString("utf8");
			const combined = `${rawStdout}${rawStderr}`;
			let artifact: string | undefined;
			if (options.artifactDir && options.artifactName) {
				ensureDir(options.artifactDir);
				artifact = path.join(options.artifactDir, options.artifactName);
				try {
					fs.writeFileSync(artifact, combined, "utf8");
				} catch {
					artifact = undefined;
				}
			}
			const trimmed = truncateOutput(rawStdout, maxBytes);
			const trimmedErr = truncateOutput(rawStderr, Math.min(maxBytes, 8_000));
			resolve({
				cmd: formatCommand(bin, args),
				bin,
				args,
				code,
				signal,
				stdout: trimmed.text,
				stderr: trimmedErr.text,
				truncated: trimmed.truncated || trimmedErr.truncated,
				durationMs: Date.now() - started,
				timedOut,
				artifact,
			});
		};

		child.on("error", (error: NodeJS.ErrnoException) => {
			const stderr = Buffer.concat(stderrChunks).toString("utf8");
			const message = error.code === "ENOENT" ? `${bin}: command not found` : error.message;
			resolve({
				cmd: formatCommand(bin, args),
				bin,
				args,
				code: null,
				signal: null,
				stdout: "",
				stderr: stderr ? `${stderr}\n${message}` : message,
				truncated: false,
				durationMs: Date.now() - started,
				timedOut,
			});
		});

		child.on("close", (code, signal) => finish(code, signal));

		if (options.stdin !== undefined) {
			child.stdin.write(options.stdin);
		}
		child.stdin.end();
	});
}

/** A single command to execute as part of a parallel batch. */
export interface RunPlan {
	bin: string;
	args: string[];
	cwd?: string;
	timeoutMs?: number;
	env?: Record<string, string>;
	/** Journal label and artifact name stem. */
	label?: string;
	/** Scope target this plan operates on. */
	target?: string;
}

/** Run several commands concurrently. */
export async function runMany(plans: RunPlan[], options: RunOptions = {}): Promise<RunResult[]> {
	return Promise.all(
		plans.map((plan) =>
			run(plan.bin, plan.args, {
				cwd: plan.cwd ?? options.cwd,
				timeoutMs: plan.timeoutMs ?? options.timeoutMs,
				env: plan.env ?? options.env,
				maxBytes: options.maxBytes,
				signal: options.signal,
				artifactDir: options.artifactDir,
				artifactName: plan.label ? `${plan.label}.txt` : undefined,
			}),
		),
	);
}

/** Default artifact directory for a working directory. */
export function defaultArtifactDir(cwd: string = process.cwd()): string {
	return engagementPaths(cwd).artifacts;
}
