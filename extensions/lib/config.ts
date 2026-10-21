/**
 * Filesystem layout and environment configuration for CyberPi.
 *
 * An engagement is a directory that contains a `.cyberpi/` folder. Every tool
 * reads and writes inside it so that an assessment is self-contained and
 * reproducible.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** Root of the CyberPi installation (the pi package directory). */
export const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

/** User-level CyberPi state (tool cache, CVE database, global config). */
export const CYBERPI_HOME = process.env.CYBERPI_HOME ?? path.join(os.homedir(), ".cyberpi");

/** Name of the per-engagement state directory. */
export const ENGAGEMENT_DIRNAME = ".cyberpi";

export interface EngagementPaths {
	/** Engagement root directory (parent of `.cyberpi`). */
	root: string;
	/** The `.cyberpi` state directory. */
	dir: string;
	/** Authorization scope definition. */
	scope: string;
	/** Append-only action journal. */
	journal: string;
	/** Structured surface index. */
	surface: string;
	/** Raw tool output artifacts. */
	artifacts: string;
	/** Recorded findings. */
	findings: string;
	/** Free-form notes. */
	notes: string;
	/** Generated reports. */
	reports: string;
	/** Cached recon results. */
	cache: string;
}

/** Resolve the engagement root for a working directory. */
export function engagementRoot(cwd: string = process.cwd()): string {
	return process.env.CYBERPI_ENGAGEMENT ? path.resolve(process.env.CYBERPI_ENGAGEMENT) : cwd;
}

/** Describe every path CyberPi uses inside an engagement. */
export function engagementPaths(cwd: string = process.cwd()): EngagementPaths {
	const root = engagementRoot(cwd);
	const dir = path.join(root, ENGAGEMENT_DIRNAME);
	return {
		root,
		dir,
		scope: path.join(dir, "scope.json"),
		journal: path.join(dir, "journal.jsonl"),
		surface: path.join(dir, "surface.json"),
		artifacts: path.join(dir, "artifacts"),
		findings: path.join(dir, "findings"),
		notes: path.join(dir, "notes"),
		reports: path.join(dir, "reports"),
		cache: path.join(dir, "cache"),
	};
}

/** Create a directory (and parents) if it does not exist. */
export function ensureDir(dir: string): string {
	fs.mkdirSync(dir, { recursive: true });
	return dir;
}

/** Create every engagement subdirectory. */
export function ensureEngagement(cwd: string = process.cwd()): EngagementPaths {
	const paths = engagementPaths(cwd);
	ensureDir(paths.dir);
	ensureDir(paths.artifacts);
	ensureDir(paths.findings);
	ensureDir(paths.notes);
	ensureDir(paths.reports);
	ensureDir(paths.cache);
	return paths;
}

/** Resolve a path inside the CyberPi package (scripts, wordlists, templates). */
export function packagePath(...segments: string[]): string {
	return path.join(PACKAGE_ROOT, ...segments);
}

/** Location of the bundled CVE database tooling. */
export const CVEDB_SCRIPT = packagePath("tools", "cvedb", "cvedb.py");

/** Location of the bundled CVE database file. */
export function cveDatabasePath(): string {
	return process.env.CYBERPI_CVE_DB ?? path.join(CYBERPI_HOME, "cve.db");
}
