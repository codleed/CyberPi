#!/usr/bin/env bash
#
# uninstall.sh - remove CyberPi from a host.
#
# The uninstaller removes the commands, the theme and the package declaration.
# The data directory is only removed with an explicit --purge and a
# confirmation. Engagement directories are never touched.
#
# Usage:
#   sudo bash uninstall.sh [options]
#
# Options:
#   --purge           Also delete the CyberPi data directory (the CVE database)
#   --keep-package    Keep the installed package payload in the library directory
#   --yes             Do not ask for confirmation
#   --help            Show this help
#
set -euo pipefail

readonly PROGRAM_NAME="uninstall.sh"
readonly INSTALL_PREFIX="${CYBERPI_INSTALL_PREFIX:-/usr/local}"
readonly LIB_DIR="$INSTALL_PREFIX/lib/cyberpi"
readonly BIN_DIR="$INSTALL_PREFIX/bin"

PURGE=0
KEEP_PACKAGE=0
ASSUME_YES=0
PAYLOAD_STATUS="kept"
DATA_STATUS="kept"

if [[ -t 1 && -z "${NO_COLOR:-}" && "${CYBERPI_NO_COLOR:-}" != "1" ]]; then
	C_RESET=$'\033[0m'
	C_BOLD=$'\033[1m'
	C_OK=$'\033[32m'
	C_WARN=$'\033[33m'
	C_FAIL=$'\033[31m'
else
	C_RESET=""
	C_BOLD=""
	C_OK=""
	C_WARN=""
	C_FAIL=""
fi

info() { printf '%s\n' "$*"; }
step() { printf '%s==>%s %s\n' "$C_BOLD" "$C_RESET" "$*"; }
ok() { printf '%s  ok%s %s\n' "$C_OK" "$C_RESET" "$*"; }
warn() { printf '%swarning:%s %s\n' "$C_WARN" "$C_RESET" "$*" >&2; }
fail() { printf '%serror:%s %s\n' "$C_FAIL" "$C_RESET" "$*" >&2; }

usage() {
	cat <<'USAGE'
uninstall.sh - remove CyberPi from a host.

Usage:
  sudo bash uninstall.sh [options]

Options:
  --purge           Also delete the CyberPi data directory (the CVE database)
  --keep-package    Keep the installed package payload in the library directory
  --yes             Do not ask for confirmation
  --help            Show this help

Engagement directories and their .cyberpi state are never deleted.
USAGE
}

ORIGINAL_ARGS=("$@")
while [[ $# -gt 0 ]]; do
	case "$1" in
	--purge)
		PURGE=1
		;;
	--keep-package)
		KEEP_PACKAGE=1
		;;
	--yes | -y)
		ASSUME_YES=1
		;;
	--help | -h)
		usage
		exit 0
		;;
	*)
		fail "unknown option: $1"
		usage >&2
		exit 2
		;;
	esac
	shift
done

TARGET_USER="${CYBERPI_TARGET_USER:-${SUDO_USER:-$(id -un)}}"
TARGET_HOME="${CYBERPI_TARGET_HOME:-${SUDO_HOME:-$HOME}}"

if [[ "$(id -u)" -ne 0 ]]; then
	if command -v sudo >/dev/null 2>&1; then
		step "elevating privileges with sudo"
		exec sudo env \
			CYBERPI_TARGET_USER="$TARGET_USER" \
			CYBERPI_TARGET_HOME="$TARGET_HOME" \
			CYBERPI_HOME="${CYBERPI_HOME:-}" \
			CYBERPI_INSTALL_PREFIX="$INSTALL_PREFIX" \
			"$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")" "${ORIGINAL_ARGS[@]}"
	fi
	fail "this uninstaller needs root privileges, run it with sudo."
	exit 1
fi

PI_AGENT_DIR="${PI_CODING_AGENT_DIR:-$TARGET_HOME/.pi/agent}"
SETTINGS_FILE="$PI_AGENT_DIR/settings.json"
THEME_DIR="$PI_AGENT_DIR/themes"
THEME_FILE="$THEME_DIR/cyber.json"
CYBERPI_HOME_DIR="${CYBERPI_HOME:-$TARGET_HOME/.cyberpi}"
USER_PATH="$TARGET_HOME/.pi/agent/bin:$TARGET_HOME/.local/bin:$TARGET_HOME/bin:$PATH"

as_user() {
	if [[ "$(id -un)" == "$TARGET_USER" ]]; then
		env HOME="$TARGET_HOME" PATH="$USER_PATH" CYBERPI_HOME="$CYBERPI_HOME_DIR" "$@"
		return
	fi
	if command -v runuser >/dev/null 2>&1; then
		runuser -u "$TARGET_USER" -- env HOME="$TARGET_HOME" PATH="$USER_PATH" CYBERPI_HOME="$CYBERPI_HOME_DIR" "$@"
		return
	fi
	su -s /bin/bash "$TARGET_USER" -c "HOME='$TARGET_HOME' PATH='$USER_PATH' CYBERPI_HOME='$CYBERPI_HOME_DIR' $(printf '%q ' "$@")"
}

confirm() {
	local question=$1
	if [[ $ASSUME_YES -eq 1 ]]; then
		return 0
	fi
	if [[ ! -t 0 ]]; then
		return 1
	fi
	local answer
	printf '%s [y/N] ' "$question"
	read -r answer || answer=""
	case "$answer" in
	y | Y | yes | YES) return 0 ;;
	*) return 1 ;;
	esac
}

# --------------------------------------------------------------------------
# Removal steps
# --------------------------------------------------------------------------

remove_commands() {
	step "removing the commands from $BIN_DIR"
	local name target
	for name in cyberpi cyberpi-doctor cyberpi-report; do
		target="$BIN_DIR/$name"
		if [[ ! -f "$target" ]]; then
			continue
		fi
		if ! grep -q "CYBERPI_PACKAGE_ROOT" "$target" 2>/dev/null; then
			warn "$target was not installed by CyberPi, it was left in place"
			continue
		fi
		if rm -f "$target"; then
			ok "removed $target"
		else
			warn "could not remove $target"
		fi
	done
}

remove_theme() {
	step "removing the cyber theme"
	if [[ ! -f "$THEME_FILE" ]]; then
		info "  no theme at $THEME_FILE"
		return 0
	fi
	if grep -q '"cyber"' "$THEME_FILE" 2>/dev/null; then
		rm -f "$THEME_FILE" && ok "removed $THEME_FILE"
	else
		warn "$THEME_FILE does not look like the CyberPi theme, it was left in place"
	fi
	if command -v node >/dev/null 2>&1 && [[ -f "$SETTINGS_FILE" ]]; then
		node -e '
			const fs = require("node:fs");
			const file = process.argv[1];
			let data;
			try { data = JSON.parse(fs.readFileSync(file, "utf8")); } catch { process.exit(0); }
			if (typeof data === "object" && data !== null && data.theme === "cyber") {
				delete data.theme;
				fs.writeFileSync(file, JSON.stringify(data, null, 2) + "\n", "utf8");
				console.log("theme setting removed");
			}
		' "$SETTINGS_FILE" 2>/dev/null || true
	fi
}

remove_package_declaration() {
	step "removing the package declaration"
	if ! command -v pi >/dev/null 2>&1; then
		warn "pi is not on PATH, the package declaration was removed from $SETTINGS_FILE directly"
	else
		if as_user pi remove "$LIB_DIR"; then
			ok "pi removed $LIB_DIR"
		else
			warn "pi remove failed, the declaration was removed from $SETTINGS_FILE directly"
		fi
	fi
	if command -v node >/dev/null 2>&1 && [[ -f "$SETTINGS_FILE" ]]; then
		node -e '
			const fs = require("node:fs");
			const file = process.argv[1];
			const target = process.argv[2];
			let data;
			try { data = JSON.parse(fs.readFileSync(file, "utf8")); } catch { process.exit(0); }
			if (!data || !Array.isArray(data.packages)) process.exit(0);
			const before = data.packages.length;
			data.packages = data.packages.filter((entry) => {
				const source = typeof entry === "string" ? entry : (entry && typeof entry.source === "string" ? entry.source : "");
				return source !== target;
			});
			if (data.packages.length !== before) {
				fs.writeFileSync(file, JSON.stringify(data, null, 2) + "\n", "utf8");
				console.log("package entry removed");
			}
		' "$SETTINGS_FILE" "$LIB_DIR" 2>/dev/null || true
	fi
}

remove_payload() {
	if [[ $KEEP_PACKAGE -eq 1 ]]; then
		PAYLOAD_STATUS="kept"
		info "  the package payload in $LIB_DIR was kept"
		return 0
	fi
	if [[ ! -d "$LIB_DIR" ]]; then
		PAYLOAD_STATUS="absent"
		return 0
	fi
	if [[ ! -f "$LIB_DIR/.cyberpi-install" ]]; then
		PAYLOAD_STATUS="kept"
		warn "$LIB_DIR was not installed by CyberPi, it was left in place"
		return 0
	fi
	step "removing the package payload from $LIB_DIR"
	if rm -rf "$LIB_DIR"; then
		PAYLOAD_STATUS="removed"
		ok "removed $LIB_DIR"
	else
		PAYLOAD_STATUS="kept"
		warn "could not remove $LIB_DIR"
	fi
}

purge_data() {
	step "removing the data directory $CYBERPI_HOME_DIR"
	if [[ ! -d "$CYBERPI_HOME_DIR" ]]; then
		DATA_STATUS="absent"
		info "  nothing to remove"
		return 0
	fi
	if ! confirm "Delete $CYBERPI_HOME_DIR and the CVE database?"; then
		DATA_STATUS="kept"
		info "  kept"
		return 0
	fi
	if rm -rf "$CYBERPI_HOME_DIR"; then
		DATA_STATUS="purged"
		ok "removed $CYBERPI_HOME_DIR"
	else
		DATA_STATUS="kept"
		warn "could not remove $CYBERPI_HOME_DIR"
	fi
}

print_summary() {
	cat <<SUMMARY

${C_BOLD}CyberPi was removed.${C_RESET}

  commands          removed from $BIN_DIR
  theme             removed from $THEME_DIR
  package           removed from the Pi settings
  payload           $LIB_DIR ($PAYLOAD_STATUS)
  data directory    $CYBERPI_HOME_DIR ($DATA_STATUS)

  Engagement directories and their .cyberpi state were not touched.

SUMMARY
}

remove_commands
remove_theme
remove_package_declaration
remove_payload
if [[ $PURGE -eq 1 ]]; then
	purge_data
fi
print_summary
