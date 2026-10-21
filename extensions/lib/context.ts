/**
 * Engagement context.
 *
 * A single snapshot of the engagement state, shared by the system prompt
 * injection and the dashboard. Building it once keeps the two consistent and
 * keeps the prompt section short enough to be free.
 */

import { which } from "./exec.ts";
import { listFindings } from "./findings.ts";
import { journalStats } from "./journal.ts";
import { loadScope, type ScopeConfig } from "./scope.ts";
import { surfaceStats } from "./surface.ts";

export interface EngagementSnapshot {
	/** False when no scope file exists yet. */
	configured: boolean;
	engagement: string;
	client?: string;
	/** Authorization statement from the scope file. */
	authorization?: string;
	scopeTargets: string[];
	techniques: string[];
	hosts: number;
	services: number;
	endpoints: number;
	findingTotal: number;
	findingsBySeverity: Record<string, number>;
	journalTotal: number;
	lastAction?: string;
	/** Core Kali binaries that are not on PATH. */
	missingTools: string[];
}

/** Core binaries whose absence most limits the harness. */
export const CORE_BINARIES = [
	"nmap",
	"naabu",
	"httpx",
	"nuclei",
	"ffuf",
	"subfinder",
	"sqlmap",
	"hashcat",
	"msfconsole",
	"searchsploit",
	"dig",
	"curl",
];

/** Read the current engagement state. */
export function snapshot(cwd: string): EngagementSnapshot {
	const scope = loadScope(cwd);
	const surface = surfaceStats(cwd);
	const journal = journalStats(cwd);
	const findings = listFindings(cwd);
	const findingsBySeverity: Record<string, number> = {};
	for (const finding of findings) {
		findingsBySeverity[finding.severity] = (findingsBySeverity[finding.severity] ?? 0) + 1;
	}
	return {
		configured: scope !== null,
		engagement: scope?.engagement ?? "unconfigured engagement",
		client: scope?.client,
		authorization: scope?.authorization?.statement,
		scopeTargets: scope?.rules.map((rule) => rule.target) ?? [],
		techniques: scope?.techniques ?? [],
		hosts: surface.hosts,
		services: surface.services,
		endpoints: surface.endpoints,
		findingTotal: findings.length,
		findingsBySeverity,
		journalTotal: journal.total,
		lastAction: journal.last,
		missingTools: CORE_BINARIES.filter((bin) => which(bin) === null),
	};
}

/**
 * The system prompt section.
 *
 * Deliberately compact: the model needs the engagement identity, the scope,
 * the current state and the operating rules, not the full inventory.
 */
export function renderContext(state: EngagementSnapshot): string {
	const lines: string[] = [];
	lines.push(`Engagement: ${state.engagement}${state.client ? ` (client: ${state.client})` : ""}`);
	if (!state.configured) {
		lines.push(
			"Scope: NOT CONFIGURED. No .cyberpi/scope.json was found, so every tool that touches a target will be refused. " +
				"Ask the operator to create the scope file before running any scan.",
		);
	} else {
		lines.push(`Authorized targets: ${state.scopeTargets.length > 0 ? state.scopeTargets.join(", ") : "none"}`);
		lines.push(
			`Allowed techniques: ${state.techniques.length > 0 ? state.techniques.join(", ") : "all techniques within the authorized targets"}`,
		);
	}
	lines.push(
		`Surface so far: ${state.hosts} hosts, ${state.services} services, ${state.endpoints} endpoints. ` +
			`Findings: ${state.findingTotal}. Journal entries: ${state.journalTotal}.`,
	);
	lines.push(
		"Rules: use the cyber_* tools for security work, record every confirmed issue with cyber_record_finding, " +
			"and keep evidence in the engagement artifacts. Targets outside the authorized scope are refused by the harness; " +
			"ask the operator to extend the scope instead of working around it.",
	);
	return lines.join("\n");
}

/** A one line status summary for the footer. */
export function renderStatus(state: EngagementSnapshot): string {
	const scopeMark = state.configured ? "scope:ok" : "scope:none";
	const findings = state.findingTotal > 0 ? `${state.findingTotal}f` : "0f";
	return `${state.engagement} · ${state.hosts}h ${state.services}s ${state.endpoints}u · ${findings} · ${scopeMark}`;
}
