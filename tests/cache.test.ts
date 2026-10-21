/**
 * Result cache tests.
 *
 * The cache exists so that a repeated scan does not cost another scan. It
 * must return the value that was stored, forget the value once the time to
 * live has passed, and drop everything on request.
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import { cacheClear, cacheGet, cacheKey, cacheSet } from "../extensions/lib/cache.ts";

const originalEngagement = process.env.CYBERPI_ENGAGEMENT;
let tmp = "";

before(() => {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-cache-"));
	process.env.CYBERPI_ENGAGEMENT = tmp;
});

after(() => {
	if (originalEngagement === undefined) delete process.env.CYBERPI_ENGAGEMENT;
	else process.env.CYBERPI_ENGAGEMENT = originalEngagement;
	if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
});

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

function cacheFile(): string {
	return path.join(tmp, ".cyberpi", "cache", "results.json");
}

describe("storing and reading values", () => {
	it("returns undefined for a key that was never stored", () => {
		assert.equal(cacheGet(tmp, "cyber_missing"), undefined);
	});

	it("returns the value that was stored", () => {
		cacheSet(tmp, "cyber_portscan", { hosts: 3, ports: [22, 80] });
		const value = cacheGet<{ hosts: number; ports: number[] }>(tmp, "cyber_portscan");
		assert.ok(value);
		assert.equal(value.hosts, 3);
		assert.deepEqual(value.ports, [22, 80]);
	});

	it("stores several values side by side", () => {
		cacheSet(tmp, "cyber_dns", "dns-result");
		cacheSet(tmp, "cyber_httpx", "httpx-result");
		assert.equal(cacheGet(tmp, "cyber_dns"), "dns-result");
		assert.equal(cacheGet(tmp, "cyber_httpx"), "httpx-result");
	});

	it("overwrites a value stored under the same key", () => {
		cacheSet(tmp, "cyber_dns", "first");
		cacheSet(tmp, "cyber_dns", "second");
		assert.equal(cacheGet(tmp, "cyber_dns"), "second");
	});

	it("writes the cache file inside the engagement", () => {
		assert.equal(fs.existsSync(cacheFile()), true);
		const parsed = JSON.parse(fs.readFileSync(cacheFile(), "utf8")) as {
			entries: Array<{ key: string; value: unknown }>;
		};
		assert.ok(Array.isArray(parsed.entries));
		assert.ok(parsed.entries.some((entry) => entry.key === "cyber_httpx"));
	});
});

describe("expiry", () => {
	it("keeps a value that has not expired yet", () => {
		cacheSet(tmp, "cyber_long", "value", 60_000);
		assert.equal(cacheGet(tmp, "cyber_long"), "value");
	});

	it("forgets a value once its time to live has passed", async () => {
		cacheSet(tmp, "cyber_short", "value", 50);
		await sleep(150);
		assert.equal(cacheGet(tmp, "cyber_short"), undefined);
	});

	it("drops the expired entry from the cache file", async () => {
		cacheSet(tmp, "cyber_dropped", "value", 50);
		await sleep(150);
		cacheGet(tmp, "cyber_dropped");
		const parsed = JSON.parse(fs.readFileSync(cacheFile(), "utf8")) as {
			entries: Array<{ key: string }>;
		};
		assert.equal(parsed.entries.some((entry) => entry.key === "cyber_dropped"), false);
	});
});

describe("clearing the cache", () => {
	it("forgets every stored value", () => {
		cacheSet(tmp, "cyber_one", "one");
		cacheSet(tmp, "cyber_two", "two");
		cacheClear(tmp);
		assert.equal(cacheGet(tmp, "cyber_one"), undefined);
		assert.equal(cacheGet(tmp, "cyber_two"), undefined);
	});

	it("removes the cache file", () => {
		cacheSet(tmp, "cyber_three", "three");
		assert.equal(fs.existsSync(cacheFile()), true);
		cacheClear(tmp);
		assert.equal(fs.existsSync(cacheFile()), false);
	});

	it("is harmless when there is nothing to clear", () => {
		cacheClear(tmp);
		cacheClear(tmp);
		assert.equal(fs.existsSync(cacheFile()), false);
	});
});

describe("cache keys", () => {
	it("is stable for the same parameters", () => {
		assert.equal(cacheKey("cyber_portscan", { target: "10.0.0.1", ports: "1-1024" }), cacheKey("cyber_portscan", { target: "10.0.0.1", ports: "1-1024" }));
	});

	it("does not depend on the order of the parameters", () => {
		assert.equal(
			cacheKey("cyber_portscan", { target: "10.0.0.1", ports: "1-1024" }),
			cacheKey("cyber_portscan", { ports: "1-1024", target: "10.0.0.1" }),
		);
	});

	it("changes when the parameters change", () => {
		assert.notEqual(
			cacheKey("cyber_portscan", { target: "10.0.0.1" }),
			cacheKey("cyber_portscan", { target: "10.0.0.2" }),
		);
	});

	it("changes with the namespace", () => {
		assert.notEqual(
			cacheKey("cyber_portscan", { target: "10.0.0.1" }),
			cacheKey("cyber_service_scan", { target: "10.0.0.1" }),
		);
	});
});
