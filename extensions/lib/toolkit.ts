/**
 * Toolkit: the shared wrapper every CyberPi tool is built from.
 *
 * It centralises the behaviour that must be identical for all tools:
 * authorization checks, binary checks, timeouts, output truncation, artifact
 * capture, result caching and journalling. A tool only has to describe what
 * command to run and how to summarise it.
 */

import type { ToolAnnotations, ToolExposure } from "@earendil-works/pi-coding-agent";
import { defineTool, type ExtensionToolContext } from "@earendil-works/pi-coding-agent";
import type { Static, TSchema } from "typebox";
import { cacheGet, cacheKey, cacheSet } from "./cache.ts";
import { engagementPaths } from "./config.ts";
import { type RunPlan, type RunResult, missingBinaries, runMany } from "./exec.ts";
import { appendJournal, type Severity } from "./journal.ts";
import { checkTarget, loadScope, type ScopeConfig } from "./scope.ts";
import { checkPlatform, currentPlatform } from "./platform.ts";


export interface CyberToolOutcome<TDetails = unknown> {
	/** One line shown first. */
	summary: string;
	/** Structured result for the UI and for programmatic callers. */
	details?: TDetails;
	/** Severity of the outcome, used for journal and dashboard colouring. */
	severity?: Severity;
	/** Extra body text appended after the summary. */
	output?: string;
	/** Mark the result as a failure without throwing. */
	isError?: boolean;
}

export interface CyberToolSummary<TDetails = unknown> extends CyberToolOutcome<TDetails> {
	/** Data merged into the surface index after a successful run. */
	surface?: {
		hosts?: Array<{ host: string; addresses?: string[]; source?: string }>;
		services?: Array<{
			host: string;
			port: number;
			protocol?: string;
			service?: string;
			version?: string;
			details?: Record<string, string>;
			source?: string;
		}>;
		endpoints?: Array<{ url: string; host: string; status?: number; title?: string; technology?: string[]; source?: string }>;
	};
}

export interface CyberToolSpec<TParams extends TSchema = TSchema, TDetails = unknown> {
	name: string;
	label: string;
	description: string;
	/** One line shown in the system prompt tool list. */
	promptSnippet?: string;
	/** Bullets appended to the system prompt guidelines. */
	promptGuidelines?: string[];
	parameters: TParams;
	outputSchema?: TSchema;
	exposure?: ToolExposure;
	annotations?: ToolAnnotations;
	/** Technique identifier, checked against the scope allowlist. */
	technique?: string;
	/** Binaries that must be installed for the tool to work. */
	requires?: string[];
	/** Extra hint shown when a required binary is missing. */
	installHint?: string;
	/** Extract the scope target from the parameters. */
	target?: (params: Static<TParams>) => string | undefined;
	/** Extract the target port from the parameters. */
	port?: (params: Static<TParams>) => number | undefined;
	/** Extract the target protocol from the parameters. */
	protocol?: (params: Static<TParams>) => string | undefined;
	/** Build the command(s) to run. */
	build?: (
		params: Static<TParams>,
		ctx: ExtensionToolContext,
	) => RunPlan | RunPlan[] | Promise<RunPlan | RunPlan[]>;
	/** Custom execution for tools that are not a single command. */
	execute?: (params: Static<TParams>, ctx: ExtensionToolContext) => Promise<CyberToolOutcome<TDetails>>;
	/** Summarise the run results. */
	summarize?: (results: RunResult[], params: Static<TParams>) => CyberToolSummary<TDetails>;
	/** Cache identical calls for this long. */
	cacheTtlMs?: number;
	/** Store the raw output in the engagement artifact directory. */
	artifacts?: boolean;
	/** Command timeout. */
	timeoutMs?: number;
	/** Journal label. Defaults to the tool name. */
	action?: string;
}

/** Error result helper. */
export function toolError(summary: string, details?: unknown): {
	content: Array<{ type: "text"; text: string }>;
	details: unknown;
	isError: true;
} {
	return {
		content: [{ type: "text", text: summary }],
		details,
		isError: true,
	};
}

const TARGET_KEYS = ["target", "host", "hostname", "url", "domain", "ip", "address"];

/** Find a scope target in the parameters when the spec does not name one. */
export function resolveTarget<TParams extends TSchema>(params: Static<TParams>, spec: CyberToolSpec<TParams>): string | undefined {
	if (spec.target) return spec.target(params);
	const record = params as Record<string, unknown>;
	for (const key of TARGET_KEYS) {
		const value = record[key];
		if (typeof value === "string" && value.trim().length > 0) return value;
	}
	return undefined;
}

/** Find a port in the parameters when the spec does not name one. */
export function resolvePort<TParams extends TSchema>(params: Static<TParams>, spec: CyberToolSpec<TParams>): number | undefined {
	if (spec.port) return spec.port(params);
	const record = params as Record<string, unknown>;
	const value = record.port;
	return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

/** Check a technique against the engagement allowlist. */
export function checkTechnique(scope: ScopeConfig | null, technique: string | undefined): { allowed: boolean; reason: string } {
	if (!technique || !scope?.techniques || scope.techniques.length === 0) return { allowed: true, reason: "authorized" };
	if (scope.techniques.some((item) => item.toLowerCase() === technique.toLowerCase())) {
		return { allowed: true, reason: "authorized" };
	}
	return {
		allowed: false,
		reason: `technique "${technique}" is not in the engagement technique allowlist (${scope.techniques.join(", ")})`,
	};
}

/** Build a CyberPi tool from a declarative spec. */
export function defineCyberTool<TParams extends TSchema, TDetails = unknown>(
	spec: CyberToolSpec<TParams, TDetails>,
) {
	return defineTool<TParams, TDetails>({
		name: spec.name,
		label: spec.label,
		description: spec.description,
		promptSnippet: spec.promptSnippet,
		promptGuidelines: spec.promptGuidelines,
		parameters: spec.parameters,
		outputSchema: spec.outputSchema,
		exposure: spec.exposure,
		annotations: spec.annotations,
		async execute(toolCallId, params, signal, _onUpdate, ctx) {
			const fail = (summary: string, details?: unknown) => ({
				content: [{ type: "text" as const, text: summary }],
				details: details as TDetails,
				isError: true,
			});
			const cwd = ctx.cwd;
			const platform = checkPlatform(currentPlatform());
			if (!platform.ok) {
				return fail(`CyberPi cannot run here: ${platform.message}`, { platform: true, reason: platform.message });
			}
			const scope = loadScope(cwd);
			const action = spec.action ?? spec.name;

			const techniqueVerdict = checkTechnique(scope, spec.technique);
			if (!techniqueVerdict.allowed) {
				appendJournal(cwd, {
					ts: new Date().toISOString(),
					tool: spec.name,
					action: "blocked",
					summary: techniqueVerdict.reason,
					severity: "info",
				});
				return fail(`Blocked: ${techniqueVerdict.reason}`, { blocked: true, reason: techniqueVerdict.reason });
			}

			const target = resolveTarget(params, spec);
			if (target) {
				const decision = checkTarget(scope, target, {
					port: resolvePort(params, spec),
					protocol: spec.protocol ? spec.protocol(params) : undefined,
					technique: spec.technique,
				});
				if (!decision.allowed) {
					appendJournal(cwd, {
						ts: new Date().toISOString(),
						tool: spec.name,
						action: "blocked",
						target,
						summary: decision.reason,
						severity: "info",
					});
					return fail(
						`Blocked by engagement scope: ${decision.reason}\n\n` +
							"Add the target to .cyberpi/scope.json if the client authorized it, then retry.",
						{ blocked: true, reason: decision.reason, target },
					);
				}
			}

			if (spec.requires && spec.requires.length > 0) {
				const missing = missingBinaries(spec.requires);
				if (missing.length > 0) {
					const hint =
						spec.installHint ??
						`Install the missing tools on Kali with: sudo apt install -y ${missing.join(" ")}`;
					return fail(`Missing required tool(s): ${missing.join(", ")}. ${hint}`, {
						missing,
						hint,
					});
				}
			}

			if (spec.execute) {
				const outcome = await spec.execute(params, ctx);
				appendJournal(cwd, {
					ts: new Date().toISOString(),
					tool: spec.name,
					action,
					target,
					summary: outcome.summary,
					severity: outcome.severity ?? "info",
				});
				const body = outcome.output ? `${outcome.summary}\n\n${outcome.output}` : outcome.summary;
				return {
					content: [{ type: "text", text: body }],
					details: outcome.details as TDetails,
					isError: outcome.isError ?? false,
				};
			}

			if (!spec.build) {
				return fail(`Tool ${spec.name} defines neither build nor execute.`, { configuration: true });
			}

			const cacheEnabled = spec.cacheTtlMs !== undefined && spec.cacheTtlMs > 0;
			const key = cacheKey(spec.name, params as unknown);
			if (cacheEnabled) {
				const cached = cacheGet<CyberToolOutcome<TDetails>>(cwd, key);
				if (cached) {
					return {
						content: [{ type: "text", text: cached.output ?? cached.summary }],
						details: { ...(cached.details as object), cached: true } as TDetails,
					};
				}
			}

			const plan = await spec.build(params, ctx);
			const plans = Array.isArray(plan) ? plan : [plan];
			const paths = engagementPaths(cwd);
			const results = await runMany(plans, {
				cwd,
				timeoutMs: spec.timeoutMs,
				signal,
				artifactDir: spec.artifacts === false ? undefined : paths.artifacts,
			});

			for (const [index, result] of results.entries()) {
				const planForResult = plans[index];
				appendJournal(cwd, {
					ts: new Date().toISOString(),
					tool: spec.name,
					action,
					target: planForResult?.target ?? target,
					command: result.cmd,
					exitCode: result.code,
					durationMs: result.durationMs,
					summary: result.timedOut ? "command timed out" : `exit ${result.code}`,
					severity: "info",
					artifact: result.artifact,
				});
			}

			const summary = spec.summarize ? spec.summarize(results, params) : defaultSummary(results);
			if (cacheEnabled) {
				cacheSet(cwd, key, { ...summary, output: summary.output }, spec.cacheTtlMs);
			}
			return {
				content: [{ type: "text", text: summary.output ? `${summary.summary}\n\n${summary.output}` : summary.summary }],
				details: summary.details as TDetails,
				isError: summary.isError ?? false,
			};
		},
	});
}

/** Default summary when a tool does not provide one. */
export function defaultSummary(results: RunResult[]): CyberToolSummary {
	if (results.length === 0) return { summary: "no commands were run" };
	if (results.length === 1) {
		const result = results[0];
		const output = result.stdout.trim() || result.stderr.trim() || "(no output)";
		return {
			summary: `${result.bin} exited with code ${result.code} in ${result.durationMs}ms`,
			output,
			severity: result.code === 0 ? "info" : "medium",
		};
	}
	const failures = results.filter((result) => result.code !== 0).length;
	return {
		summary: `${results.length} commands executed, ${failures} failed`,
		output: results.map((result) => `### ${result.cmd}\nexit ${result.code}\n${result.stdout.trim() || result.stderr.trim()}`).join("\n\n"),
		severity: failures > 0 ? "medium" : "info",
	};
}

/** Split text into non-empty trimmed lines. */
export function lines(text: string): string[] {
	return text
		.split("\n")
		.map((line) => line.trim())
		.filter((line) => line.length > 0);
}

/** Parse `key=value` style output lines (nmap, httpx and friends). */
export function parseKeyValues(text: string, separator = "="): Record<string, string> {
	const result: Record<string, string> = {};
	for (const line of lines(text)) {
		const index = line.indexOf(separator);
		if (index <= 0) continue;
		result[line.slice(0, index).trim()] = line.slice(index + 1).trim();
	}
	return result;
}

/** Parse JSON lines, skipping malformed entries. */
export function parseJsonLines<T>(text: string): T[] {
	const result: T[] = [];
	for (const line of lines(text)) {
		if (!line.startsWith("{") && !line.startsWith("[")) continue;
		try {
			result.push(JSON.parse(line) as T);
		} catch {
			continue;
		}
	}
	return result;
}

/** Parse a JSON document, returning undefined when it does not parse. */
export function parseJson<T>(text: string): T | undefined {
	try {
		return JSON.parse(text) as T;
	} catch {
		return undefined;
	}
}
