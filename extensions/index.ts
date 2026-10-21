/**
 * CyberPi - a Kali Linux security engagement harness for the Pi agent.
 *
 * This extension wires the harness together:
 *
 * - registers the 35 CyberPi tools,
 * - injects the engagement state into the system prompt so the model always
 *   knows the scope it is working inside,
 * - enforces the Linux/Kali platform gate,
 * - shows the engagement dashboard and the footer status line.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { registerDashboard } from "./dashboard.ts";
import { renderContext, snapshot } from "./lib/context.ts";
import { checkPlatform, detectPlatform } from "./lib/platform.ts";
import { adTools } from "./tools/ad.ts";
import { credsTools } from "./tools/creds.ts";
import { cveTools } from "./tools/cve.ts";
import { exploitTools } from "./tools/exploit.ts";
import { infraTools } from "./tools/infra.ts";
import { iotTools } from "./tools/iot.ts";
import { networkTools } from "./tools/network.ts";
import { reconTools } from "./tools/recon.ts";
import { reportTools } from "./tools/report.ts";
import { vulnTools } from "./tools/vuln.ts";
import { webTools } from "./tools/web.ts";
import { wirelessTools } from "./tools/wireless.ts";

/** Every tool the harness exposes, in the order the model sees them. */
export const cyberTools = [
	...reconTools,
	...networkTools,
	...webTools,
	...vulnTools,
	...exploitTools,
	...credsTools,
	...adTools,
	...wirelessTools,
	...iotTools,
	...infraTools,
	...cveTools,
	...reportTools,
];

export default function cyberPi(pi: ExtensionAPI): void {
	for (const tool of cyberTools) {
		pi.registerTool(tool);
	}

	registerDashboard(pi);

	// Platform gate: CyberPi targets Kali Linux and cannot run on Windows or macOS.
	pi.on("session_start", async (_event, ctx) => {
		const verdict = checkPlatform(detectPlatform());
		if (!verdict.ok) {
			ctx.ui.setStatus("cyberpi", ctx.ui.theme.fg("error", "unsupported platform"));
			ctx.ui.notify(`CyberPi: ${verdict.message}`, "error");
			return;
		}
		if (verdict.unsupportedDistro) {
			ctx.ui.notify(`CyberPi: ${verdict.message}`, "warning");
		}
		const state = snapshot(ctx.cwd);
		if (!state.configured) {
			ctx.ui.notify(
				"CyberPi: no .cyberpi/scope.json found. Create it before running any target action, " +
					"or use /cyber to check the engagement state.",
				"warning",
			);
		}
	});

	// Keep the model informed about the engagement it is working inside.
	pi.on("before_agent_start", async (event, ctx) => {
		const state = snapshot(ctx.cwd);
		event.systemPromptOptions.sections.engagement = renderContext(state);
	});
}
