/**
 * The CyberPi dashboard.
 *
 * `/cyber` shows the state of the engagement: the scope, the discovered
 * surface, the findings, the journal and the tooling gaps. The same state
 * feeds the footer status line, so the operator always knows where they are.
 */

import type { ExtensionAPI, ExtensionContext, Theme } from "@earendil-works/pi-coding-agent";
import { type EngagementSnapshot, renderStatus, snapshot } from "./lib/context.ts";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

function severityColor(severity: string): "error" | "warning" | "accent" | "muted" {
	if (severity === "critical" || severity === "high") return "error";
	if (severity === "medium") return "warning";
	if (severity === "low") return "accent";
	return "muted";
}

/** Build the dashboard lines for the current engagement. */
export function buildDashboard(state: EngagementSnapshot, theme: Theme): string[] {
	const lines: string[] = [];
	const heading = (text: string) => `  ${theme.fg("accent", text)}`;
	const label = (text: string) => `  ${theme.fg("muted", text.padEnd(10))}`;

	lines.push("");
	lines.push(`  ${theme.fg("accent", theme.bold("CYBERPI"))} ${theme.fg("text", state.engagement)}`);
	if (state.client) lines.push(`${label("client")}${theme.fg("text", state.client)}`);

	if (!state.configured) {
		lines.push(`${label("scope")}${theme.fg("error", "not configured - every target will be refused")}`);
	} else {
		lines.push(`${label("scope")}${theme.fg("text", state.scopeTargets.length > 0 ? state.scopeTargets.join(", ") : "no targets")}`);
		const techniques = state.techniques.length > 0 ? state.techniques.join(", ") : "all";
		lines.push(`${label("tech")}${theme.fg("dim", techniques)}`);
	}
	if (state.authorization) {
		lines.push(`${label("auth")}${theme.fg("dim", state.authorization)}`);
	}

	lines.push("");
	lines.push(heading("SURFACE"));
	lines.push(
		`    ${theme.fg("text", String(state.hosts))} ${theme.fg("muted", "hosts")}   ` +
			`${theme.fg("text", String(state.services))} ${theme.fg("muted", "services")}   ` +
			`${theme.fg("text", String(state.endpoints))} ${theme.fg("muted", "endpoints")}`,
	);

	lines.push(heading("FINDINGS"));
	lines.push(
		`    ${SEVERITIES.map((severity) => {
			const count = state.findingsBySeverity[severity] ?? 0;
			const painted = count > 0 ? theme.fg(severityColor(severity), String(count)) : theme.fg("dim", "0");
			return `${painted} ${theme.fg("muted", severity)}`;
		}).join("   ")}`,
	);

	lines.push(heading("JOURNAL"));
	lines.push(
		`    ${theme.fg("text", String(state.journalTotal))} ${theme.fg("muted", "actions")}` +
			(state.lastAction ? `   ${theme.fg("dim", `last ${state.lastAction}`)}` : ""),
	);

	if (state.missingTools.length > 0) {
		lines.push(heading("TOOLING"));
		lines.push(`    ${theme.fg("warning", "missing")} ${theme.fg("muted", state.missingTools.join(", "))}`);
	}

	lines.push("");
	lines.push(`  ${theme.fg("dim", "/cyber - dashboard   /help - skills and commands   /report - build the report")}`);
	lines.push("");
	return lines;
}

/** Plain text version for the non-interactive modes. */
export function buildPlainDashboard(state: EngagementSnapshot): string {
	return [
		`CYBERPI - ${state.engagement}`,
		state.client ? `client: ${state.client}` : "",
		state.configured ? `scope: ${state.scopeTargets.join(", ") || "no targets"}` : "scope: NOT CONFIGURED",
		`surface: ${state.hosts} hosts, ${state.services} services, ${state.endpoints} endpoints`,
		`findings: ${state.findingTotal} (${SEVERITIES.map((severity) => `${severity} ${state.findingsBySeverity[severity] ?? 0}`).join(", ")})`,
		`journal: ${state.journalTotal} actions`,
		state.missingTools.length > 0 ? `missing tools: ${state.missingTools.join(", ")}` : "",
	]
		.filter((line) => line.length > 0)
		.join("\n");
}

/** Register the dashboard command and the footer status. */
export function registerDashboard(pi: ExtensionAPI): void {
	const refreshStatus = (ctx: ExtensionContext) => {
		if (!ctx.hasUI) return;
		const state = snapshot(ctx.cwd);
		ctx.ui.setStatus("cyberpi", ctx.ui.theme.fg("accent", `◈ ${renderStatus(state)}`));
	};

	pi.on("session_start", async (_event, ctx) => {
		refreshStatus(ctx);
	});

	pi.on("tool_result", async (event, ctx) => {
		if (!event.toolName.startsWith("cyber_")) return;
		refreshStatus(ctx);
	});

	pi.registerCommand("cyber", {
		description: "CyberPi dashboard: scope, surface, findings and journal",
		handler: async (_args, ctx) => {
			const state = snapshot(ctx.cwd);
			if (ctx.mode !== "tui") {
				ctx.ui.notify(buildPlainDashboard(state), "info");
				return;
			}
			const theme = ctx.ui.theme;
			const lines = buildDashboard(state, theme);
			await ctx.ui.custom((_tui, panelTheme, _keybindings, done) => {
				void panelTheme;
				return {
					render(_width: number): string[] {
						return lines;
					},
					invalidate(): void {},
					handleInput(data: string): void {
						if (data === "q" || data === "\x1b") {
							done(undefined);
						}
					},
				};
			});
		},
	});
}
