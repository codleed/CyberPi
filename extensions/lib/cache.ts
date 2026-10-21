/**
 * Result cache.
 *
 * Scans are slow and often repeated while the agent iterates. Caching the raw
 * result of a scan keyed by its inputs keeps the loop tight: a repeated
 * request for the same target returns in milliseconds.
 */

import fs from "node:fs";
import path from "node:path";
import { ensureDir, engagementPaths } from "./config.ts";

interface CacheEntry {
	key: string;
	createdAt: number;
	expiresAt: number;
	value: unknown;
}

interface CacheFile {
	entries: CacheEntry[];
}

function cacheFile(cwd: string): string {
	return path.join(engagementPaths(cwd).cache, "results.json");
}

function readCache(cwd: string): CacheFile {
	const file = cacheFile(cwd);
	if (!fs.existsSync(file)) return { entries: [] };
	try {
		const parsed = JSON.parse(fs.readFileSync(file, "utf8")) as CacheFile;
		return { entries: parsed.entries ?? [] };
	} catch {
		return { entries: [] };
	}
}

/** Build a stable cache key from a namespace and arbitrary parameters. */
export function cacheKey(namespace: string, params: unknown): string {
	const payload = JSON.stringify(params, Object.keys(params ?? {}).sort());
	let hash = 5381;
	const material = `${namespace}:${payload}`;
	for (let i = 0; i < material.length; i++) {
		hash = ((hash << 5) + hash + material.charCodeAt(i)) | 0;
	}
	return `${namespace}:${(hash >>> 0).toString(36)}`;
}

/** Read a cached value, or undefined when missing or expired. */
export function cacheGet<T>(cwd: string, key: string): T | undefined {
	const now = Date.now();
	const file = readCache(cwd);
	const entry = file.entries.find((item) => item.key === key);
	if (!entry) return undefined;
	if (entry.expiresAt <= now) {
		const remaining = file.entries.filter((item) => item.key !== key);
		writeCache(cwd, { entries: remaining });
		return undefined;
	}
	return entry.value as T;
}

/** Store a value in the cache. */
export function cacheSet(cwd: string, key: string, value: unknown, ttlMs = 3_600_000): void {
	const file = readCache(cwd);
	const now = Date.now();
	const entries = file.entries.filter((item) => item.key !== key);
	entries.push({ key, createdAt: now, expiresAt: now + ttlMs, value });
	writeCache(cwd, { entries });
}

function writeCache(cwd: string, cache: CacheFile): void {
	const file = cacheFile(cwd);
	ensureDir(path.dirname(file));
	fs.writeFileSync(file, JSON.stringify(cache), "utf8");
}

/** Drop every cached entry. */
export function cacheClear(cwd: string): void {
	const file = cacheFile(cwd);
	if (fs.existsSync(file)) fs.rmSync(file);
}
