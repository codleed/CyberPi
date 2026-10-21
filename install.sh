#!/usr/bin/env bash
#
# install.sh - install CyberPi on a Kali Linux host.
#
# The installer prepares the host: it checks the runtime, installs Pi, installs
# the Kali tool groups, registers the CyberPi package with Pi, installs the
# cyber theme, creates the cyberpi commands and seeds the CVE database.
#
# Usage:
#   sudo bash install.sh [options]
#
# Options:
#   --core             Install the core tool group only (default)
#   --full             Install every tool group
#   --groups <list>    Install the given groups (comma separated)
#   --no-apt           Do not install any Kali package
#   --uninstall        Remove CyberPi instead of installing it
#   --yes              Do not ask for confirmation
#   --help             Show this help
#
set -euo pipefail

readonly PROGRAM_NAME="install.sh"
readonly NODE_MIN_VERSION="22.19"
readonly PYTHON_MIN_VERSION="3.11"
readonly PI_INSTALLER_URL="https://pi.dev/install.sh"
readonly INSTALL_PREFIX="${CYBERPI_INSTALL_PREFIX:-/usr/local}"
readonly LIB_DIR="$INSTALL_PREFIX/lib/cyberpi"
readonly BIN_DIR="$INSTALL_PREFIX/bin"

INSTALL_MODE="core"
INSTALL_APT=1
ASSUME_YES=0
GROUPS=""

if [[ -t 1 && -z "${NO_COLOR:-}" && "${CYBERPI_NO_COLOR:-}" != "1" ]]; then
	C_RESET=$'\033[0m'
	C_BOLD=$'\033[1m'
	C_DIM=$'\033[2m'
	C_OK=$'\033[32m'
	C_WARN=$'\033[33m'
	C_FAIL=$'\033[31m'
else
	C_RESET=""
	C_BOLD=""
	C_DIM=""
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
install.sh - install CyberPi on a Kali Linux host.

Usage:
  sudo bash install.sh [options]

Options:
  --core             Install the core tool group only (default)
  --full             Install every tool group
  --groups <list>    Install the given groups (comma separated)
  --no-apt           Do not install any Kali package
  --uninstall        Remove CyberPi instead of installing it
  --yes              Do not ask for confirmation
  --help             Show this help

Tool groups: core, web, creds, exploit, ad, wireless, iot, network, cloud
USAGE
}

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
SOURCE_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"

# --------------------------------------------------------------------------
# Arguments
# --------------------------------------------------------------------------

UNINSTALL=0
ORIGINAL_ARGS=("$@")
while [[ $# -gt 0 ]]; do
	case "$1" in
	--core)
		INSTALL_MODE="core"
		;;
	--full)
		INSTALL_MODE="full"
		;;
	--groups)
		[[ $# -ge 2 ]] || { fail "--groups needs a list"; exit 2; }
		INSTALL_MODE="groups"
		GROUPS=$2
		shift
		;;
	--groups=*)
		INSTALL_MODE="groups"
		GROUPS=${1#*=}
		;;
	--no-apt)
		INSTALL_APT=0
		;;
	--uninstall)
		UNINSTALL=1
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

if [[ $UNINSTALL -eq 1 ]]; then
	if [[ -f "$SOURCE_DIR/uninstall.sh" ]]; then
		uninstall_args=()
		[[ $ASSUME_YES -eq 1 ]] && uninstall_args+=(--yes)
		exec bash "$SOURCE_DIR/uninstall.sh" "${uninstall_args[@]}"
	fi
	fail "uninstall.sh was not found next to install.sh."
	exit 1
fi

# --------------------------------------------------------------------------
# Platform gate
# --------------------------------------------------------------------------

if [[ "$(uname -s)" != "Linux" ]]; then
	fail "CyberPi targets Kali Linux and can only be installed on a Linux host (this host is $(uname -s))."
	exit 1
fi

DISTRO_ID=$(sed -n 's/^ID="\{0,1\}\(.*\)"\{0,1\}$/\1/p' /etc/os-release 2>/dev/null | head -n 1 || true)
DISTRO_NAME=$(sed -n 's/^NAME="\{0,1\}\(.*\)"\{0,1\}$/\1/p' /etc/os-release 2>/dev/null | head -n 1 || true)
DISTRO_LIKE=$(sed -n 's/^ID_LIKE="\{0,1\}\(.*\)"\{0,1\}$/\1/p' /etc/os-release 2>/dev/null | head -n 1 || true)
if [[ "$DISTRO_ID" != "kali" && "$DISTRO_LIKE" != *kali* ]]; then
	if [[ "${CYBERPI_STRICT_KALI:-}" == "1" ]]; then
		fail "CyberPi requires Kali Linux, ${DISTRO_NAME:-this distribution} was detected and CYBERPI_STRICT_KALI=1 is set."
		exit 1
	fi
	warn "${DISTRO_NAME:-this distribution} detected, not Kali Linux. The installer continues, but some packages are packaged differently."
fi

# --------------------------------------------------------------------------
# Privilege handling
# --------------------------------------------------------------------------

TARGET_USER="${CYBERPI_TARGET_USER:-${SUDO_USER:-$(id -un)}}"
TARGET_HOME="${CYBERPI_TARGET_HOME:-${SUDO_HOME:-$HOME}}"

if [[ "$(id -u)" -ne 0 ]]; then
	if command -v sudo >/dev/null 2>&1; then
		step "elevating privileges with sudo"
		exec sudo env \
			CYBERPI_TARGET_USER="$TARGET_USER" \
			CYBERPI_TARGET_HOME="$TARGET_HOME" \
			CYBERPI_STRICT_KALI="${CYBERPI_STRICT_KALI:-}" \
			CYBERPI_PACKAGE_SOURCE="${CYBERPI_PACKAGE_SOURCE:-}" \
			CYBERPI_HOME="${CYBERPI_HOME:-}" \
			CYBERPI_INSTALL_PREFIX="$INSTALL_PREFIX" \
			"$SCRIPT_PATH" "${ORIGINAL_ARGS[@]}"
	fi
	fail "this installer needs root privileges, run it with sudo."
	exit 1
fi

PI_AGENT_DIR="${PI_CODING_AGENT_DIR:-$TARGET_HOME/.pi/agent}"
SETTINGS_FILE="$PI_AGENT_DIR/settings.json"
THEME_DIR="$PI_AGENT_DIR/themes"
CYBERPI_HOME_DIR="${CYBERPI_HOME:-$TARGET_HOME/.cyberpi}"
CVE_DB_PATH="${CYBERPI_CVE_DB:-$CYBERPI_HOME_DIR/cve.db}"
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
# Runtime
# --------------------------------------------------------------------------

version_ge() {
	local left=${1#v} right=${2#v}
	local -a left_parts=() right_parts=()
	IFS='.' read -r -a left_parts <<<"$left"
	IFS='.' read -r -a right_parts <<<"$right"
	local index lv rv
	for index in 0 1 2; do
		lv=$(printf '%s' "${left_parts[$index]:-0}" | tr -cd '0-9')
		rv=$(printf '%s' "${right_parts[$index]:-0}" | tr -cd '0-9')
		lv=${lv:-0}
		rv=${rv:-0}
		lv=$((10#$lv))
		rv=$((10#$rv))
		if ((lv > rv)); then return 0; fi
		if ((lv < rv)); then return 1; fi
	done
	return 0
}

pi_installed() {
	command -v pi >/dev/null 2>&1 && return 0
	[[ -x "$TARGET_HOME/.pi/agent/bin/pi" ]] && return 0
	[[ -x "$TARGET_HOME/.local/bin/pi" ]] && return 0
	return 1
}

install_pi() {
	step "installing the Pi coding agent with the official installer"
	if ! command -v curl >/dev/null 2>&1; then
		fail "curl is required to install Pi."
		exit 1
	fi
	as_user bash -c "curl -fsSL '$PI_INSTALLER_URL' | sh" || {
		warn "the Pi installer failed, install Pi manually with: curl -fsSL $PI_INSTALLER_URL | sh"
		return 1
	}
	return 0
}

check_runtime() {
	local node_version
	if command -v node >/dev/null 2>&1; then
		node_version=$(node -v 2>/dev/null || echo "unknown")
		if version_ge "$node_version" "$NODE_MIN_VERSION"; then
			ok "node $node_version"
		else
			warn "node $node_version is older than $NODE_MIN_VERSION, the Pi installer will be used to upgrade it"
			install_pi || true
		fi
	else
		warn "node was not found, the Pi installer will install it"
		install_pi || true
	fi

	local python_version
	if command -v python3 >/dev/null 2>&1; then
		python_version=$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null || echo "unknown")
		if version_ge "$python_version" "$PYTHON_MIN_VERSION"; then
			ok "python3 $python_version"
		else
			warn "python3 $python_version is older than $PYTHON_MIN_VERSION"
		fi
	else
		warn "python3 was not found; the CVE database needs it (apt install python3)"
	fi

	if pi_installed; then
		ok "pi $(pi --version 2>/dev/null | head -n 1 | tr -d '\r' || echo installed)"
	else
		if install_pi; then
			export PATH="$TARGET_HOME/.pi/agent/bin:$TARGET_HOME/.local/bin:$PATH"
			ok "pi installed"
		else
			fail "Pi could not be installed, the CyberPi commands need it."
			exit 1
		fi
	fi
	export PATH="$TARGET_HOME/.pi/agent/bin:$TARGET_HOME/.local/bin:$PATH"
}

# --------------------------------------------------------------------------
# Kali packages
# --------------------------------------------------------------------------

group_description() {
	case "$1" in
	core) echo "reconnaissance, port scanning, service enumeration and web probing" ;;
	web) echo "web application testing: injection, XSS, directories, TLS and fingerprints" ;;
	creds) echo "credential work: hash cracking, password auditing and secret scanning" ;;
	exploit) echo "exploit research and the Metasploit framework" ;;
	ad) echo "Active Directory enumeration and relay tooling" ;;
	wireless) echo "wireless capture, cracking and radio tooling" ;;
	iot) echo "firmware analysis, reverse engineering and hardware attacks" ;;
	network) echo "packet capture, traffic analysis, tunnels and proxies" ;;
	cloud) echo "cloud enumeration for AWS, Azure and Google Cloud" ;;
	*) echo "unknown group" ;;
	esac
}

group_is_heavy() {
	case "$1" in
	exploit | ad | wireless | iot | network | cloud) return 0 ;;
	*) return 1 ;;
	esac
}

group_packages() {
	case "$1" in
	core) printf '%s\n' nmap naabu "httpx-toolkit|httpx" katana ffuf nuclei subfinder dnsutils whois iproute2 net-tools ;;
	web) printf '%s\n' sqlmap dalfox nikto gobuster wafw00f sslscan testssl.sh feroxbuster ;;
	creds) printf '%s\n' hashcat john hydra trufflehog ;;
	exploit) printf '%s\n' metasploit-framework exploitdb ;;
	ad) printf '%s\n' impacket-scripts responder bloodhound ldapdomaindump ;;
	wireless) printf '%s\n' aircrack-ng wifite hcxtools bettercap ;;
	iot) printf '%s\n' binwalk radare2 hidrd python3-serial cutter ;;
	network) printf '%s\n' tcpdump tshark wireshark chisel proxychains4 socat ;;
	cloud) printf '%s\n' awscli azure-cli google-cloud-cli ;;
	*) return 1 ;;
	esac
}

package_is_installed() {
	dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "ok installed"
}

resolve_package() {
	local entry=$1
	local -a candidates=()
	IFS='|' read -r -a candidates <<<"$entry"
	local candidate
	for candidate in "${candidates[@]}"; do
		if package_is_installed "$candidate"; then
			printf '%s\n' "$candidate"
			return 0
		fi
	done
	for candidate in "${candidates[@]}"; do
		if apt-cache show "$candidate" >/dev/null 2>&1; then
			printf '%s\n' "$candidate"
			return 0
		fi
	done
	printf '%s\n' "${candidates[0]}"
}

install_group() {
	local group=$1
	local entry resolved
	local -a wanted=()
	local -a missing=()
	while IFS= read -r entry; do
		[[ -z "$entry" ]] && continue
		resolved=$(resolve_package "$entry")
		if package_is_installed "$resolved"; then
			continue
		fi
		wanted+=("$resolved")
	done < <(group_packages "$group")
	if [[ ${#wanted[@]} -eq 0 ]]; then
		ok "group $group: every package is already installed"
		return 0
	fi
	info "  packages: ${wanted[*]}"
	if ! DEBIAN_FRONTEND=noninteractive apt-get install -y "${wanted[@]}"; then
		warn "some packages of the group $group could not be installed"
		missing+=("${wanted[@]}")
		return 1
	fi
	ok "group $group installed"
	return 0
}

install_tool_groups() {
	local -a groups=()
	case "$INSTALL_MODE" in
	core) groups=(core) ;;
	full) groups=(core web creds exploit ad wireless iot network cloud) ;;
	groups)
		IFS=',' read -r -a groups <<<"$GROUPS"
		;;
	esac
	local group
	for group in "${groups[@]}"; do
		group=${group// /}
		[[ -z "$group" ]] && continue
		if ! group_packages "$group" >/dev/null; then
			warn "unknown tool group: $group"
			continue
		fi
		step "group $group: $(group_description "$group")"
		if group_is_heavy "$group"; then
			info "  this group installs a lot of data and can take a long time."
			if ! confirm "Install the group $group?"; then
				info "  skipped, install it later with: sudo apt install -y $(group_packages "$group" | tr '\n' ' ')"
				continue
			fi
		fi
		install_group "$group" || true
	done
}

install_apt_packages() {
	if [[ $INSTALL_APT -eq 0 ]]; then
		warn "--no-apt was given, no Kali package was installed."
		return 0
	fi
	if ! command -v apt-get >/dev/null 2>&1; then
		warn "apt-get was not found, the Kali toolchain was not installed."
		return 0
	fi
	step "updating the package index"
	if ! DEBIAN_FRONTEND=noninteractive apt-get update; then
		warn "the package index could not be updated, continuing with the cached index"
	fi
	install_tool_groups
}

# --------------------------------------------------------------------------
# CyberPi payload, theme, package and commands
# --------------------------------------------------------------------------

copy_payload() {
	step "installing the CyberPi package into $LIB_DIR"
	mkdir -p "$LIB_DIR"
	(
		cd "$SOURCE_DIR" || exit 1
		tar -cf - --exclude=node_modules --exclude=.git --exclude=.artifacts --exclude=.ref .
	) | (cd "$LIB_DIR" && tar -xf -)
	printf 'source=%s\ninstalled=%s\n' "$SOURCE_DIR" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$LIB_DIR/.cyberpi-install"
	chmod -R a+rX "$LIB_DIR"
	chmod 755 "$LIB_DIR/bin/cyberpi" "$LIB_DIR/bin/cyberpi-doctor" "$LIB_DIR/bin/cyberpi-report" 2>/dev/null || true
	ok "package payload installed in $LIB_DIR"
}

install_theme() {
	local source_theme="$LIB_DIR/themes/cyber.json"
	if [[ ! -f "$source_theme" ]]; then
		warn "the theme file themes/cyber.json is not in the package, the theme was not installed"
		return 0
	fi
	mkdir -p "$THEME_DIR"
	install -m 644 "$source_theme" "$THEME_DIR/cyber.json"
	chown -R "$TARGET_USER" "$THEME_DIR" 2>/dev/null || true
	ok "cyber theme installed in $THEME_DIR/cyber.json"
}

package_is_registered() {
	local source
	while IFS= read -r source; do
		[[ -z "$source" ]] && continue
		case "$source" in
		~*) source="${source/#\~/$HOME}" ;;
		esac
		if [[ "$source" == "$LIB_DIR" ]]; then
			return 0
		fi
	done < <(settings_package_sources)
	return 1
}

settings_package_sources() {
	if ! command -v node >/dev/null 2>&1; then return 0; fi
	node -e '
		const fs = require("node:fs");
		const file = process.argv[1];
		if (!fs.existsSync(file)) process.exit(0);
		let data;
		try { data = JSON.parse(fs.readFileSync(file, "utf8")); } catch { process.exit(0); }
		const list = Array.isArray(data.packages) ? data.packages : [];
		for (const entry of list) {
			if (typeof entry === "string") console.log(entry);
			else if (entry && typeof entry.source === "string") console.log(entry.source);
		}
	' "$SETTINGS_FILE" 2>/dev/null || true
}

install_package_into_pi() {
	local source=""
	if [[ -n "${CYBERPI_PACKAGE_SOURCE:-}" ]]; then
		source=$CYBERPI_PACKAGE_SOURCE
	else
		source=$LIB_DIR
	fi
	step "registering the CyberPi package with Pi from $source"
	if ! pi_installed; then
		warn "pi is not on PATH, the package was not registered. Run 'pi install $source' as $TARGET_USER."
		return 0
	fi
	if package_is_registered; then
		ok "the CyberPi package is already registered in $SETTINGS_FILE"
		return 0
	fi
	if as_user pi install "$source"; then
		ok "the CyberPi package was registered in $SETTINGS_FILE"
	else
		warn "pi install failed, register it manually with: pi install $source"
	fi
}

install_commands() {
	step "creating the cyberpi commands in $BIN_DIR"
	mkdir -p "$BIN_DIR"
	local name
	for name in cyberpi cyberpi-doctor cyberpi-report; do
		cat >"$BIN_DIR/$name" <<COMMAND
#!/usr/bin/env bash
#
# $name - CyberPi command installed by install.sh
#
set -euo pipefail
export CYBERPI_PACKAGE_ROOT="$LIB_DIR"
exec "$LIB_DIR/bin/$name" "\$@"
COMMAND
		chmod 755 "$BIN_DIR/$name"
		ok "$BIN_DIR/$name"
	done
}

create_home() {
	step "preparing $CYBERPI_HOME_DIR"
	mkdir -p "$CYBERPI_HOME_DIR"
	chmod 700 "$CYBERPI_HOME_DIR"
	chown -R "$TARGET_USER" "$CYBERPI_HOME_DIR" 2>/dev/null || true
	ok "$CYBERPI_HOME_DIR (permissions 700)"
}

seed_cve_database() {
	local script="$LIB_DIR/tools/cvedb/cvedb.py"
	if [[ ! -f "$script" ]]; then
		warn "tools/cvedb/cvedb.py is not in the package, the CVE database was not seeded"
		return 0
	fi
	if ! command -v python3 >/dev/null 2>&1; then
		warn "python3 is not available, the CVE database was not seeded"
		return 0
	fi
	if [[ -f "$CVE_DB_PATH" ]]; then
		ok "the CVE database already exists at $CVE_DB_PATH"
		return 0
	fi
	step "seeding the CVE database"
	info "  the first sync downloads the NVD, the CISA KEV catalog and the EPSS scores, it can take a few minutes."
	if ! confirm "Sync the CVE database now?"; then
		info "  skipped, run it later with: python3 $script sync"
		return 0
	fi
	if as_user python3 "$script" sync; then
		ok "the CVE database was seeded at $CVE_DB_PATH"
	else
		warn "the CVE database sync failed, run it later with: python3 $script sync"
	fi
}

print_summary() {
	cat <<SUMMARY

${C_BOLD}CyberPi is installed.${C_RESET}

  package payload   $LIB_DIR
  commands          $BIN_DIR/cyberpi, $BIN_DIR/cyberpi-doctor, $BIN_DIR/cyberpi-report
  Pi settings       $SETTINGS_FILE
  theme             $THEME_DIR/cyber.json
  CyberPi home      $CYBERPI_HOME_DIR
  CVE database      $CVE_DB_PATH

${C_BOLD}Next steps${C_RESET}

  1. Check the installation:      cyberpi-doctor
  2. Create an engagement:        cyberpi new acme-web-2025-03
  3. Authorize the targets:       nano <engagement>/.cyberpi/scope.json
  4. Start the harness:           cd <engagement> && cyberpi
  5. Render the report:           cyberpi-report --format markdown --output report.md

  Inside the agent: /cyber for the dashboard, /recon, /scan, /exploit, /report

SUMMARY
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

main() {
	info "CyberPi installer"
	info "  source      $SOURCE_DIR"
	info "  target      $LIB_DIR"
	info "  user        $TARGET_USER ($TARGET_HOME)"
	info ""

	check_runtime
	if [[ $INSTALL_APT -eq 1 ]]; then
		install_apt_packages
	fi
	create_home
	copy_payload
	install_theme
	install_package_into_pi
	install_commands
	seed_cve_database
	print_summary
}

main "$@"
