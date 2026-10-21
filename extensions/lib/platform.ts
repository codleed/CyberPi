/**
 * Platform detection and the Linux/Kali support gate.
 *
 * CyberPi is a Kali Linux harness. Running it on Windows or macOS is
 * unsupported because the toolchain it drives (nmap, impacket, aircrack-ng,
 * metasploit, ...) is Linux-only and the sandboxing assumptions differ.
 */

import fs from "node:fs";
import os from "node:os";

export interface PlatformInfo {
	/** `linux`, `darwin`, `win32`, ... */
	platform: NodeJS.Platform;
	arch: string;
	kernel: string;
	/** Distribution name from /etc/os-release, e.g. "Kali GNU/Linux Rolling". */
	distro: string;
	/** Distribution id, e.g. "kali", "debian", "ubuntu". */
	distroId: string;
	/** `NAME` field of /etc/os-release. */
	distroName: string;
	/** `VERSION_ID` field of /etc/os-release. */
	distroVersion: string;
	isLinux: boolean;
	isKali: boolean;
}

interface OsRelease {
	ID?: string;
	NAME?: string;
	VERSION?: string;
	VERSION_ID?: string;
	ID_LIKE?: string;
}

function readOsRelease(): OsRelease {
	try {
		const raw = fs.readFileSync("/etc/os-release", "utf8");
		const parsed: OsRelease = {};
		for (const line of raw.split("\n")) {
			const index = line.indexOf("=");
			if (index === -1) continue;
			const key = line.slice(0, index).trim();
			const value = line
				.slice(index + 1)
				.trim()
				.replace(/^["']/, "")
				.replace(/["']$/, "");
			parsed[key as keyof OsRelease] = value;
		}
		return parsed;
	} catch {
		return {};
	}
}

/** Inspect the running system. */
export function detectPlatform(): PlatformInfo {
	const osRelease = readOsRelease();
	const distroId = (osRelease.ID ?? "").toLowerCase();
	const idLike = (osRelease.ID_LIKE ?? "").toLowerCase();
	const isLinux = process.platform === "linux";
	const isKali = isLinux && (distroId === "kali" || idLike.includes("kali"));
	return {
		platform: process.platform,
		arch: os.arch(),
		kernel: os.release(),
		distro: osRelease.NAME ?? (isLinux ? "Linux" : ""),
		distroId,
		distroName: osRelease.NAME ?? "",
		distroVersion: osRelease.VERSION_ID ?? "",
		isLinux,
		isKali,
	};
}

let platformOverride: PlatformInfo | undefined;

/**
 * Replace the detected platform for the lifetime of the process.
 *
 * This exists so the harness logic can be exercised on a development machine
 * that is not Kali. It is a code-level seam, not a user-facing switch: the
 * shipped behaviour on a real host is unchanged.
 */
export function setPlatformInfoForTesting(info: PlatformInfo | undefined): void {
	platformOverride = info;
}

/** The platform the harness believes it is running on. */
export function currentPlatform(): PlatformInfo {
	return platformOverride ?? detectPlatform();
}

export interface PlatformVerdict {
	ok: boolean;
	/** True when the platform can run CyberPi but is not the recommended distribution. */
	unsupportedDistro: boolean;
	message: string;
}

/**
 * Decide whether CyberPi may run here.
 *
 * Non-Linux is always refused. Linux distributions other than Kali run in a
 * degraded mode unless `CYBERPI_STRICT_KALI=1` is set, which turns the
 * warning into a refusal.
 */
export function checkPlatform(info: PlatformInfo = detectPlatform()): PlatformVerdict {
	if (!info.isLinux) {
		return {
			ok: false,
			unsupportedDistro: false,
			message:
				`CyberPi targets Kali Linux and is not supported on ${info.platform}. ` +
				"Run it inside Kali Linux (bare metal, a VM, or a container).",
		};
	}
	if (!info.isKali) {
		const distro = info.distroName || info.distroId || "this Linux distribution";
		if (process.env.CYBERPI_STRICT_KALI === "1") {
			return {
				ok: false,
				unsupportedDistro: true,
				message: `CyberPi requires Kali Linux; ${distro} was detected and CYBERPI_STRICT_KALI=1 is set.`,
			};
		}
		return {
			ok: true,
			unsupportedDistro: true,
			message:
				`CyberPi is running on ${distro}, not Kali Linux. Most tools still work, ` +
				"but some are packaged differently. Set CYBERPI_STRICT_KALI=1 to refuse non-Kali hosts.",
		};
	}
	return { ok: true, unsupportedDistro: false, message: `Kali Linux ${info.distroVersion} detected.` };
}

/** True when the current process may execute a given binary. */
export function canRun(bin: string): boolean {
	if (bin.includes("/")) {
		try {
			fs.accessSync(bin, fs.constants.X_OK);
			return true;
		} catch {
			return false;
		}
	}
	const searchPath = (process.env.PATH ?? "").split(path_delimiter());
	for (const dir of searchPath) {
		if (!dir) continue;
		const candidate = `${dir}/${bin}`;
		try {
			fs.accessSync(candidate, fs.constants.X_OK);
			return true;
		} catch {
			continue;
		}
	}
	return false;
}

function path_delimiter(): string {
	return process.platform === "win32" ? ";" : ":";
}
