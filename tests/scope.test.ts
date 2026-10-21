/**
 * Authorization engine tests.
 *
 * The scope engine is the part of CyberPi where a silent bug is dangerous:
 * a target that is allowed when it should be refused, or the other way
 * around, invalidates the engagement record. These tests exercise the real
 * matching code against the real parsing code.
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import {
	checkTarget,
	ipInCidr,
	isIpLiteral,
	loadScope,
	parseIp,
	parseScope,
	parseTarget,
	ruleAllows,
	ruleMatchesHost,
	scopeSummary,
	selfTargets,
	stripJsonComments,
	type ScopeConfig,
	type ScopeRule,
	type ScopeTarget,
} from "../extensions/lib/scope.ts";

const originalEngagement = process.env.CYBERPI_ENGAGEMENT;
let tmp = "";

before(() => {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-scope-"));
	process.env.CYBERPI_ENGAGEMENT = tmp;
});

after(() => {
	if (originalEngagement === undefined) delete process.env.CYBERPI_ENGAGEMENT;
	else process.env.CYBERPI_ENGAGEMENT = originalEngagement;
	if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
});

function scopeOf(rules: ScopeRule[], overrides: Partial<ScopeConfig> = {}): ScopeConfig {
	return {
		engagement: "acme-web-2025-03",
		rules,
		techniques: [],
		allowSelfTest: true,
		...overrides,
	};
}

function target(host: string, extra: Partial<ScopeTarget> = {}): ScopeTarget {
	return { host, isIp: isIpLiteral(host), ...extra };
}

describe("CIDR matching (IPv4)", () => {
	it("matches addresses inside the network", () => {
		assert.equal(ipInCidr("10.2.3.4", "10.0.0.0/8"), true);
		assert.equal(ipInCidr("192.168.1.10", "192.168.1.0/24"), true);
		assert.equal(ipInCidr("172.16.5.5", "172.16.0.0/12"), true);
	});

	it("rejects addresses outside the network", () => {
		assert.equal(ipInCidr("11.2.3.4", "10.0.0.0/8"), false);
		assert.equal(ipInCidr("192.168.2.10", "192.168.1.0/24"), false);
		assert.equal(ipInCidr("172.32.5.5", "172.16.0.0/12"), false);
	});

	it("treats the network and broadcast addresses as inside the block", () => {
		assert.equal(ipInCidr("192.168.1.0", "192.168.1.0/24"), true);
		assert.equal(ipInCidr("192.168.1.255", "192.168.1.0/24"), true);
	});

	it("honours non byte-aligned prefix lengths", () => {
		assert.equal(ipInCidr("10.0.0.0", "10.0.0.0/12"), true);
		assert.equal(ipInCidr("10.15.255.255", "10.0.0.0/12"), true);
		assert.equal(ipInCidr("10.16.0.0", "10.0.0.0/12"), false);
	});

	it("handles the degenerate prefix lengths", () => {
		assert.equal(ipInCidr("203.0.113.9", "0.0.0.0/0"), true);
		assert.equal(ipInCidr("203.0.113.9", "203.0.113.9/32"), true);
		assert.equal(ipInCidr("203.0.113.10", "203.0.113.9/32"), false);
	});

	it("rejects malformed networks and addresses", () => {
		assert.equal(ipInCidr("10.0.0.1", "10.0.0.0/33"), false);
		assert.equal(ipInCidr("10.0.0.1", "10.0.0.0/-1"), false);
		assert.equal(ipInCidr("10.0.0.256", "10.0.0.0/8"), false);
		assert.equal(ipInCidr("not-an-ip", "10.0.0.0/8"), false);
		assert.equal(ipInCidr("10.0.0.1", "nonsense"), false);
	});
});

describe("CIDR matching (IPv6)", () => {
	it("matches addresses inside the network", () => {
		assert.equal(ipInCidr("2001:db8::1", "2001:db8::/32"), true);
		assert.equal(ipInCidr("2001:db8:abcd:1234::1", "2001:db8::/32"), true);
		assert.equal(ipInCidr("fe80::1", "fe80::/10"), true);
	});

	it("rejects addresses outside the network", () => {
		assert.equal(ipInCidr("2001:db9::1", "2001:db8::/32"), false);
		assert.equal(ipInCidr("2001:7::1", "2001:db8::/32"), false);
	});

	it("handles the degenerate prefix lengths", () => {
		assert.equal(ipInCidr("::1", "::/0"), true);
		assert.equal(ipInCidr("2001:db8::1", "2001:db8::1/128"), true);
		assert.equal(ipInCidr("2001:db8::2", "2001:db8::1/128"), false);
	});

	it("does not mix address families", () => {
		assert.equal(ipInCidr("10.0.0.1", "2001:db8::/32"), false);
		assert.equal(ipInCidr("2001:db8::1", "10.0.0.0/8"), false);
	});
});

describe("IP literal parsing", () => {
	it("parses IPv4 literals", () => {
		assert.deepEqual(Array.from(parseIp("192.168.1.10") ?? []), [192, 168, 1, 10]);
		assert.equal(isIpLiteral("0.0.0.0"), true);
		assert.equal(isIpLiteral("255.255.255.255"), true);
	});

	it("parses IPv6 literals, including the compressed form", () => {
		assert.equal((parseIp("2001:db8::1")?.length ?? 0), 16);
		assert.equal(isIpLiteral("::1"), true);
		assert.equal(isIpLiteral("fe80::0202:b3ff:fe1e:8329"), true);
	});

	it("rejects non-literals", () => {
		assert.equal(isIpLiteral("example.com"), false);
		assert.equal(isIpLiteral("192.168.1"), false);
		assert.equal(isIpLiteral("192.168.1.1.1"), false);
		assert.equal(isIpLiteral("192.168.1.300"), false);
		assert.equal(isIpLiteral("gggg::1"), false);
	});
});

describe("target specifications", () => {
	it("matches a wildcard domain against its subdomains only", () => {
		const rule: ScopeRule = { target: "*.example.com" };
		assert.equal(ruleMatchesHost(rule, "api.example.com"), true);
		assert.equal(ruleMatchesHost(rule, "a.b.example.com"), true);
		assert.equal(ruleMatchesHost(rule, "example.com"), false);
		assert.equal(ruleMatchesHost(rule, "notexample.com"), false);
		assert.equal(ruleMatchesHost(rule, "example.com.evil.net"), false);
	});

	it("matches an exact-prefix rule against the host alone", () => {
		const rule: ScopeRule = { target: "exact:example.com" };
		assert.equal(ruleMatchesHost(rule, "example.com"), true);
		assert.equal(ruleMatchesHost(rule, "api.example.com"), false);
		assert.equal(ruleMatchesHost(rule, "example.com.evil.net"), false);
	});

	it("matches a bare domain and its subdomains", () => {
		const rule: ScopeRule = { target: "example.com" };
		assert.equal(ruleMatchesHost(rule, "example.com"), true);
		assert.equal(ruleMatchesHost(rule, "api.example.com"), true);
		assert.equal(ruleMatchesHost(rule, "example.org"), false);
	});

	it("matches a CIDR target and a single IP target", () => {
		assert.equal(ruleMatchesHost({ target: "10.0.0.0/8" }, "10.1.2.3"), true);
		assert.equal(ruleMatchesHost({ target: "10.0.0.0/8" }, "11.1.2.3"), false);
		assert.equal(ruleMatchesHost({ target: "192.168.1.10" }, "192.168.1.10"), true);
		assert.equal(ruleMatchesHost({ target: "192.168.1.10" }, "192.168.1.11"), false);
	});

	it("ignores case", () => {
		assert.equal(ruleMatchesHost({ target: "*.Example.COM" }, "API.example.com"), true);
		assert.equal(ruleMatchesHost({ target: "exact:Example.com" }, "example.COM"), true);
	});
});

describe("port, protocol and technique restrictions", () => {
	it("allows a port that the rule lists", () => {
		const rule: ScopeRule = { target: "example.com", ports: [80, 443] };
		assert.equal(ruleAllows(rule, target("example.com"), { port: 443 }).allowed, true);
	});

	it("refuses a port the rule does not list", () => {
		const rule: ScopeRule = { target: "example.com", ports: [80, 443] };
		const verdict = ruleAllows(rule, target("example.com"), { port: 22 });
		assert.equal(verdict.allowed, false);
		assert.match(verdict.reason, /port 22 is not in the allowed ports/);
	});

	it("refuses when the rule is port limited and no port is known", () => {
		const rule: ScopeRule = { target: "example.com", ports: [80] };
		const verdict = ruleAllows(rule, target("example.com"), {});
		assert.equal(verdict.allowed, false);
		assert.match(verdict.reason, /limited to ports 80/);
	});

	it("takes the port from the target when the caller does not supply one", () => {
		const rule: ScopeRule = { target: "example.com", ports: [8080] };
		assert.equal(ruleAllows(rule, target("example.com", { port: 8080 }), {}).allowed, true);
		assert.equal(ruleAllows(rule, target("example.com", { port: 9090 }), {}).allowed, false);
	});

	it("restricts protocols", () => {
		const rule: ScopeRule = { target: "example.com", protocols: ["tcp"] };
		assert.equal(ruleAllows(rule, target("example.com"), { protocol: "tcp" }).allowed, true);
		assert.equal(ruleAllows(rule, target("example.com"), { protocol: "TCP" }).allowed, true);
		assert.equal(ruleAllows(rule, target("example.com"), { protocol: "udp" }).allowed, false);
		const unknown = ruleAllows(rule, target("example.com"), {});
		assert.equal(unknown.allowed, false);
		assert.match(unknown.reason, /protocol unknown is not in the allowed protocols/);
	});

	it("restricts techniques", () => {
		const rule: ScopeRule = { target: "example.com", techniques: ["recon", "web-testing"] };
		assert.equal(ruleAllows(rule, target("example.com"), { technique: "recon" }).allowed, true);
		assert.equal(ruleAllows(rule, target("example.com"), { technique: "exploit" }).allowed, false);
		const missing = ruleAllows(rule, target("example.com"), {});
		assert.equal(missing.allowed, false);
		assert.match(missing.reason, /technique unknown is not allowed/);
	});

	it("refuses a host that the rule does not cover", () => {
		const rule: ScopeRule = { target: "example.com" };
		const verdict = ruleAllows(rule, target("other.net"), {});
		assert.equal(verdict.allowed, false);
		assert.match(verdict.reason, /does not match rule target/);
	});
});

describe("engagement level decisions", () => {
	it("fails closed when no scope file exists", () => {
		const decision = checkTarget(null, "example.com");
		assert.equal(decision.allowed, false);
		assert.match(decision.reason, /no scope\.json found/);
	});

	it("fails closed when the scope has no rules", () => {
		const decision = checkTarget(scopeOf([]), "example.com");
		assert.equal(decision.allowed, false);
		assert.match(decision.reason, /is not in the authorized scope of engagement "acme-web-2025-03"/);
	});

	it("allows a target covered by a rule and reports the rule", () => {
		const scope = scopeOf([{ target: "example.com" }]);
		const decision = checkTarget(scope, "api.example.com");
		assert.equal(decision.allowed, true);
		assert.equal(decision.rule?.target, "example.com");
	});

	it("refuses a target outside every rule", () => {
		const scope = scopeOf([{ target: "example.com" }]);
		const decision = checkTarget(scope, "victim.net");
		assert.equal(decision.allowed, false);
		assert.match(decision.reason, /Add it to \.cyberpi\/scope\.json/);
	});

	it("enforces the engagement level technique allowlist", () => {
		const scope = scopeOf([{ target: "example.com" }], { techniques: ["recon"] });
		assert.equal(checkTarget(scope, "example.com", { technique: "recon" }).allowed, true);
		const blocked = checkTarget(scope, "example.com", { technique: "exploit" });
		assert.equal(blocked.allowed, false);
		assert.match(blocked.reason, /not in the engagement technique allowlist/);
	});

	it("applies port restrictions to the full decision", () => {
		const scope = scopeOf([{ target: "example.com", ports: [443] }]);
		assert.equal(checkTarget(scope, "https://example.com", { port: 443 }).allowed, true);
		assert.equal(checkTarget(scope, "https://example.com:8080").allowed, false);
	});
});

describe("self-test allowance", () => {
	it("allows loopback targets on the local machine", () => {
		for (const host of ["127.0.0.1", "::1", "localhost"]) {
			const decision = checkTarget(null, host);
			assert.equal(decision.allowed, true, `${host} should be allowed for self-testing`);
			assert.equal(decision.selfTest, true);
		}
	});

	it("includes the local interface addresses", () => {
		const targets = selfTargets();
		const addresses = Object.values(os.networkInterfaces())
			.flat()
			.map((entry) => entry?.address.toLowerCase() ?? "")
			.filter((address) => address.length > 0);
		for (const address of addresses) {
			assert.ok(targets.has(address), `expected ${address} to be a self-test target`);
		}
	});

	it("allows a local interface address even without a scope file", () => {
		const addresses = Object.values(os.networkInterfaces())
			.flat()
			.map((entry) => entry?.address)
			.filter((address): address is string => typeof address === "string" && !address.includes(":"));
		if (addresses.length === 0) return;
		const decision = checkTarget(null, addresses[0]);
		assert.equal(decision.allowed, true);
		assert.equal(decision.selfTest, true);
	});

	it("refuses self-test targets when self-testing is disabled", () => {
		const scope = scopeOf([], { allowSelfTest: false });
		const decision = checkTarget(scope, "127.0.0.1");
		assert.equal(decision.allowed, false);
		assert.equal(decision.selfTest, undefined);
	});
});

describe("target parser", () => {
	it("parses a URL", () => {
		assert.deepEqual(parseTarget("https://example.com/path?q=1#frag"), {
			host: "example.com",
			port: undefined,
			scheme: "https",
			isIp: false,
		});
	});

	it("parses a host and port", () => {
		assert.deepEqual(parseTarget("example.com:8080"), {
			host: "example.com",
			port: 8080,
			scheme: undefined,
			isIp: false,
		});
	});

	it("parses an IPv4 host and port", () => {
		assert.deepEqual(parseTarget("192.168.1.10:22"), {
			host: "192.168.1.10",
			port: 22,
			scheme: undefined,
			isIp: true,
		});
	});

	it("parses a bracketed IPv6 host with a port", () => {
		assert.deepEqual(parseTarget("[2001:db8::1]:443"), {
			host: "2001:db8::1",
			port: 443,
			scheme: undefined,
			isIp: true,
		});
	});

	it("parses a bracketed IPv6 host without a port", () => {
		assert.deepEqual(parseTarget("[2001:db8::1]"), {
			host: "2001:db8::1",
			port: undefined,
			scheme: undefined,
			isIp: true,
		});
	});

	it("parses a bare IPv6 host without mistaking it for a port", () => {
		assert.deepEqual(parseTarget("2001:db8::1"), {
			host: "2001:db8::1",
			port: undefined,
			scheme: undefined,
			isIp: true,
		});
	});

	it("strips credentials", () => {
		assert.equal(parseTarget("user:pass@example.com").host, "example.com");
		assert.equal(parseTarget("https://user:pass@example.com").host, "example.com");
	});

	it("lower-cases host names but keeps IP literals as written", () => {
		assert.equal(parseTarget("EXAMPLE.COM").host, "example.com");
		assert.equal(parseTarget("192.168.1.10").host, "192.168.1.10");
	});

	it("rejects empty and malformed targets", () => {
		assert.throws(() => parseTarget(""), /target is empty/);
		assert.throws(() => parseTarget("   "), /target is empty/);
		assert.throws(() => parseTarget("[2001:db8::1"), /malformed IPv6 target/);
	});
});

describe("JSONC comment stripper", () => {
	it("removes line comments", () => {
		const stripped = stripJsonComments('{\n\t// a comment\n\t"a": 1\n}');
		assert.ok(!stripped.includes("a comment"));
		assert.deepEqual(JSON.parse(stripped), { a: 1 });
	});

	it("removes block comments", () => {
		const stripped = stripJsonComments('{ /* one\ntwo */ "a": 1 }');
		assert.ok(!stripped.includes("two"));
		assert.deepEqual(JSON.parse(stripped), { a: 1 });
	});

	it("keeps comment-like text inside strings", () => {
		const stripped = stripJsonComments('{ "url": "https://example.com/a//b", "glob": "/*x*/" }');
		assert.deepEqual(JSON.parse(stripped), { url: "https://example.com/a//b", glob: "/*x*/" });
	});

	it("keeps escaped quotes inside strings", () => {
		const stripped = stripJsonComments('{ "a": "say \\"hi\\" // not a comment" }');
		assert.deepEqual(JSON.parse(stripped), { a: 'say "hi" // not a comment' });
	});

	it("leaves plain JSON untouched", () => {
		const source = '{ "engagement": "acme", "rules": [] }';
		assert.equal(stripJsonComments(source), source);
	});
});

describe("scope document parsing", () => {
	it("parses a scope with comments and applies the defaults", () => {
		const parsed = parseScope(`{
			// the engagement this file authorizes
			"engagement": "acme-web",
			"rules": [{ "target": "example.com" }]
		}`);
		assert.equal(parsed.engagement, "acme-web");
		assert.equal(parsed.rules.length, 1);
		assert.deepEqual(parsed.techniques, []);
		assert.equal(parsed.allowSelfTest, true);
	});

	it("rejects malformed documents", () => {
		assert.throws(() => parseScope("{ not json"), /not valid JSON/);
		assert.throws(() => parseScope('"just a string"'), /must contain a JSON object/);
		assert.throws(() => parseScope('{"rules":[]}'), /must define a non-empty "engagement" name/);
		assert.throws(() => parseScope('{"engagement":"x"}'), /must define a "rules" array/);
		assert.throws(() => parseScope('{"engagement":"x","rules":[{}]}'), /rule #1 is missing a "target"/);
	});
});

describe("scope loading", () => {
	it("returns null when the scope file does not exist", () => {
		const empty = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-scope-empty-"));
		const previous = process.env.CYBERPI_ENGAGEMENT;
		try {
			process.env.CYBERPI_ENGAGEMENT = empty;
			assert.equal(loadScope(empty), null);
		} finally {
			if (previous === undefined) delete process.env.CYBERPI_ENGAGEMENT;
			else process.env.CYBERPI_ENGAGEMENT = previous;
			fs.rmSync(empty, { recursive: true, force: true });
		}
	});

	it("loads and parses the scope file of an engagement", () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cyberpi-scope-file-"));
		const previous = process.env.CYBERPI_ENGAGEMENT;
		try {
			process.env.CYBERPI_ENGAGEMENT = dir;
			fs.mkdirSync(path.join(dir, ".cyberpi"), { recursive: true });
			fs.writeFileSync(
				path.join(dir, ".cyberpi", "scope.json"),
				'{ "engagement": "acme", "rules": [{ "target": "example.com" }] }',
				"utf8",
			);
			const loaded = loadScope(dir);
			assert.ok(loaded);
			assert.equal(loaded.engagement, "acme");
			assert.equal(loaded.rules[0].target, "example.com");
			assert.match(scopeSummary(loaded), /acme \| targets: example\.com \| techniques: all/);
		} finally {
			if (previous === undefined) delete process.env.CYBERPI_ENGAGEMENT;
			else process.env.CYBERPI_ENGAGEMENT = previous;
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("scope summary", () => {
	it("describes a missing scope", () => {
		assert.equal(scopeSummary(null), "no scope configured");
	});
});
