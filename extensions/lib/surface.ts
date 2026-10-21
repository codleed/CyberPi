/**
 * Attack surface index.
 *
 * Reconnaissance results are merged into one JSON index per engagement so the
 * agent can answer questions about the target in milliseconds instead of
 * re-running scanners. Every discovery carries a source so the dashboard can
 * show where a piece of knowledge came from.
 */

import fs from "node:fs";
import path from "node:path";
import { ensureDir, engagementPaths } from "./config.ts";

export interface SurfaceHost {
	host: string;
	/** IPs the host resolved to. */
	addresses?: string[];
	/** Source that discovered the host, e.g. "subfinder". */
	source?: string;
	firstSeen: string;
}

export interface SurfaceService {
	host: string;
	port: number;
	protocol?: string;
	/** Service banner or product version. */
	service?: string;
	version?: string;
	/** Extra key=value details from the scanner. */
	details?: Record<string, string>;
	source?: string;
	firstSeen: string;
}

export interface SurfaceEndpoint {
	url: string;
	host: string;
	status?: number;
	title?: string;
	technology?: string[];
	source?: string;
	firstSeen: string;
}

export interface SurfaceData {
	hosts: SurfaceHost[];
	services: SurfaceService[];
	endpoints: SurfaceEndpoint[];
	updatedAt: string;
}

function emptySurface(): SurfaceData {
	return { hosts: [], services: [], endpoints: [], updatedAt: new Date().toISOString() };
}

/** Read the surface index. */
export function readSurface(cwd: string = process.cwd()): SurfaceData {
	const file = engagementPaths(cwd).surface;
	if (!fs.existsSync(file)) return emptySurface();
	try {
		const parsed = JSON.parse(fs.readFileSync(file, "utf8")) as Partial<SurfaceData>;
		return {
			hosts: parsed.hosts ?? [],
			services: parsed.services ?? [],
			endpoints: parsed.endpoints ?? [],
			updatedAt: parsed.updatedAt ?? new Date().toISOString(),
		};
	} catch {
		return emptySurface();
	}
}

/** Write the surface index atomically. */
export function writeSurface(cwd: string, surface: SurfaceData): void {
	const paths = engagementPaths(cwd);
	ensureDir(paths.dir);
	const temp = `${paths.surface}.tmp`;
	surface.updatedAt = new Date().toISOString();
	fs.writeFileSync(temp, JSON.stringify(surface, null, 2), "utf8");
	fs.renameSync(temp, paths.surface);
}

function mergeBy<T extends Record<string, unknown>>(existing: T[], incoming: T[], key: (item: T) => string): T[] {
	const map = new Map<string, T>();
	for (const item of existing) map.set(key(item), item);
	for (const item of incoming) {
		const id = key(item);
		const previous = map.get(id);
		map.set(id, previous ? { ...previous, ...item } : item);
	}
	return [...map.values()];
}

/** Merge hosts into the index. */
export function addHosts(cwd: string, hosts: Array<{ host: string; addresses?: string[]; source?: string }>): void {
	const surface = readSurface(cwd);
	const now = new Date().toISOString();
	const entries = hosts.map((host) => ({ ...host, host: host.host.toLowerCase(), firstSeen: now }));
	surface.hosts = mergeBy(surface.hosts, entries, (item) => item.host);
	writeSurface(cwd, surface);
}

/** Merge services into the index. */
export function addServices(
	cwd: string,
	services: Array<{
		host: string;
		port: number;
		protocol?: string;
		service?: string;
		version?: string;
		details?: Record<string, string>;
		source?: string;
	}>,
): void {
	const surface = readSurface(cwd);
	const now = new Date().toISOString();
	const entries = services.map((service) => ({ ...service, host: service.host.toLowerCase(), firstSeen: now }));
	surface.services = mergeBy(
		surface.services,
		entries,
		(item) => `${item.host}:${item.port}/${item.protocol ?? "tcp"}`,
	);
	writeSurface(cwd, surface);
}

/** Merge endpoints into the index. */
export function addEndpoints(
	cwd: string,
	endpoints: Array<{ url: string; host: string; status?: number; title?: string; technology?: string[]; source?: string }>,
): void {
	const surface = readSurface(cwd);
	const now = new Date().toISOString();
	const entries = endpoints.map((endpoint) => ({ ...endpoint, firstSeen: now }));
	surface.endpoints = mergeBy(surface.endpoints, entries, (item) => item.url);
	writeSurface(cwd, surface);
}

/** Counts for the dashboard. */
export function surfaceStats(cwd: string): {
	hosts: number;
	services: number;
	endpoints: number;
	ports: number;
	updatedAt: string;
} {
	const surface = readSurface(cwd);
	return {
		hosts: surface.hosts.length,
		services: surface.services.length,
		endpoints: surface.endpoints.length,
		ports: new Set(surface.services.map((service) => service.port)).size,
		updatedAt: surface.updatedAt,
	};
}
