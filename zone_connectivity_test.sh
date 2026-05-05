#!/usr/bin/env bash
# =============================================================================
#  ICS Network Zone Connectivity Test Script
#  Run this on any zone device to validate firewall rules and zone isolation.
#
#  Zones:
#    Area Zone     (10.0.0.0/24)  — HMI, PLC
#    Operator Zone (10.10.0.0/24) — Maintenance Laptop
#    Server Zone   (10.20.0.0/24) — Historian
#    Enterprise    (10.30.0.0/24) — Cloud System
#
#  Usage:
#    chmod +x zone_connectivity_test.sh
#    ./zone_connectivity_test.sh [--device <name>] [--report <file>]
#
#    --device   Force device identity. One of:
#               plc | hmi | laptop | historian | cloud
#    --report   Write a copy of the output to a file (optional)
#
#  If --device is omitted the script auto-detects based on your IP address.
# =============================================================================
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1 — DEVICE IP CONFIGURATION
#   Edit the values below to match your actual device addresses.
# ─────────────────────────────────────────────────────────────────────────────

# Area Zone — 10.0.0.0/24
IP_PLC="10.0.0.10"
IP_HMI="10.0.0.11"

# Operator Zone — 10.10.0.0/24
IP_LAPTOP="10.10.0.10"

# Server Zone — 10.20.0.0/24
IP_HISTORIAN="10.20.0.10"

# Enterprise Zone — 10.30.0.0/24
IP_CLOUD="10.30.0.10"

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2 — SERVICE PORT CONFIGURATION
#   Used for TCP-level reachability tests in addition to ICMP ping.
#   Set to 0 to skip TCP tests for a given device.
# ─────────────────────────────────────────────────────────────────────────────

PORT_PLC=502          # Modbus TCP (common for PLCs)
PORT_HMI=80           # HTTP (HMI web interface / VNC-over-HTTP)
PORT_LAPTOP=22        # SSH (maintenance laptop)
PORT_HISTORIAN=8080   # Historian API / web UI
PORT_CLOUD=443        # HTTPS (cloud system)

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3 — INTERNET REACHABILITY PROBES
#   Used to verify that OT/IT devices are (or are not) internet-connected.
# ─────────────────────────────────────────────────────────────────────────────

INTERNET_IP="8.8.8.8"          # Google DNS — reliable public IP
INTERNET_HOST="www.google.com"  # DNS resolution + HTTP probe
TIMEOUT=4                        # Seconds before a probe is declared failed

# =============================================================================
# ── INTERNALS — Do not edit below this line ──────────────────────────────────
# =============================================================================

# ─── Colour codes (disabled automatically if not a TTY) ─────────────────────
if [ -t 1 ]; then
    C_RESET='\033[0m'; C_BOLD='\033[1m'
    C_RED='\033[0;31m';    C_GREEN='\033[0;32m'
    C_YELLOW='\033[1;33m'; C_BLUE='\033[0;34m'
    C_CYAN='\033[0;36m';   C_MAGENTA='\033[0;35m'
    C_GRAY='\033[0;90m'
else
    C_RESET=''; C_BOLD=''
    C_RED=''; C_GREEN=''
    C_YELLOW=''; C_BLUE=''
    C_CYAN=''; C_MAGENTA=''
    C_GRAY=''
fi

# ─── Counters ────────────────────────────────────────────────────────────────
PASS=0; FAIL=0; WARN=0
REPORT_FILE=""
FORCED_DEVICE=""

# ─── Argument parsing ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --device) FORCED_DEVICE="$2"; shift 2 ;;
        --report) REPORT_FILE="$2";   shift 2 ;;
        -h|--help)
            grep '^#  ' "$0" | sed 's/^#  //'
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ─── Output helpers ───────────────────────────────────────────────────────────
_log() { echo -e "$*"; }

_header() {
    _log ""
    _log "${C_BLUE}${C_BOLD}╔══════════════════════════════════════════════════════════════╗${C_RESET}"
    _log "${C_BLUE}${C_BOLD}║  $1${C_RESET}"
    _log "${C_BLUE}${C_BOLD}╚══════════════════════════════════════════════════════════════╝${C_RESET}"
}

_section() {
    _log ""
    _log "${C_YELLOW}${C_BOLD}▸ $1${C_RESET}"
    _log "${C_GRAY}  ──────────────────────────────────────────────────────────${C_RESET}"
}

_info() {
    _log "  ${C_CYAN}ℹ  $1${C_RESET}"
}

# ─── Core probe functions ─────────────────────────────────────────────────────

# Returns 0 if host responds to ICMP ping, 1 otherwise.
_ping() {
    ping -c 2 -W "$TIMEOUT" "$1" &>/dev/null
}

# Returns 0 if TCP connection to host:port succeeds, 1 otherwise.
# Requires nc (netcat). Falls back silently if nc is absent.
_tcp() {
    local host="$1" port="$2"
    if command -v nc &>/dev/null; then
        nc -zw "$TIMEOUT" "$host" "$port" &>/dev/null
    else
        return 1  # treat as unreachable; ICMP result will be used
    fi
}

# Returns 0 if the host is reachable via ICMP or TCP (either is enough).
# _reachable <ip> [port]
_reachable() {
    local host="$1" port="${2:-0}"
    if _ping "$host"; then
        return 0
    fi
    if [[ "$port" -gt 0 ]]; then
        _tcp "$host" "$port" && return 0
    fi
    return 1
}

# Returns 0 if internet is accessible (IP probe + optional DNS).
_internet_reachable() {
    if _ping "$INTERNET_IP"; then
        return 0
    fi
    # Fallback: try DNS-based TCP probe on port 443
    if command -v nc &>/dev/null; then
        nc -zw "$TIMEOUT" "$INTERNET_HOST" 443 &>/dev/null && return 0
    fi
    return 1
}

# ─── Test runner ─────────────────────────────────────────────────────────────
#
# run_test <rule_id> <description> <expectation: ALLOW|DENY> <host> [port]
#
#   ALLOW → we expect the connection to SUCCEED.  Failure = misconfiguration.
#   DENY  → we expect the connection to FAIL.     Success = security violation!
#
run_test() {
    local rule_id="$1"
    local desc="$2"
    local expect="$3"
    local host="$4"
    local port="${5:-0}"

    # Perform probe
    local reached=1
    if [[ "$host" == "INTERNET" ]]; then
        _internet_reachable && reached=0
    else
        _reachable "$host" "$port" && reached=0
    fi

    # Evaluate
    if [[ "$expect" == "ALLOW" ]]; then
        if [[ $reached -eq 0 ]]; then
            _log "  ${C_GREEN}[PASS]${C_RESET} ${C_BOLD}[$rule_id]${C_RESET} $desc"
            (( PASS++ )) || true
        else
            _log "  ${C_RED}[FAIL]${C_RESET} ${C_BOLD}[$rule_id]${C_RESET} $desc"
            _log "        ${C_RED}↳ Expected: reachable — Got: unreachable (connectivity broken)${C_RESET}"
            (( FAIL++ )) || true
        fi
    else   # DENY
        if [[ $reached -ne 0 ]]; then
            _log "  ${C_GREEN}[PASS]${C_RESET} ${C_BOLD}[$rule_id]${C_RESET} $desc"
            (( PASS++ )) || true
        else
            _log "  ${C_RED}[FAIL]${C_RESET} ${C_BOLD}[$rule_id]${C_RESET} $desc"
            _log "        ${C_RED}↳ Expected: blocked — Got: reachable (⚠ SECURITY VIOLATION)${C_RESET}"
            (( FAIL++ )) || true
        fi
    fi
}

# ─── Warn about skipped tests ─────────────────────────────────────────────────
_skip() {
    local rule_id="$1"; local reason="$2"
    _log "  ${C_MAGENTA}[SKIP]${C_RESET} ${C_BOLD}[$rule_id]${C_RESET} $reason"
    (( WARN++ )) || true
}

# =============================================================================
# ── DEVICE AUTO-DETECTION ────────────────────────────────────────────────────
# =============================================================================

_detect_device() {
    # Gather all local IPs
    local my_ips
    my_ips=$(hostname -I 2>/dev/null || ip addr show 2>/dev/null \
        | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' || echo "")

    for ip in $my_ips; do
        case "$ip" in
            "$IP_PLC")       echo "plc";       return ;;
            "$IP_HMI")       echo "hmi";       return ;;
            "$IP_LAPTOP")    echo "laptop";    return ;;
            "$IP_HISTORIAN") echo "historian"; return ;;
            "$IP_CLOUD")     echo "cloud";     return ;;
        esac
    done
    echo "unknown"
}

_pick_device() {
    if [[ -n "$FORCED_DEVICE" ]]; then
        echo "$FORCED_DEVICE"
        return
    fi
    _detect_device
}

# =============================================================================
# ── PER-DEVICE TEST SUITES ───────────────────────────────────────────────────
# =============================================================================

# ─────────────────────────────────────────────────────────────────────────────
# PLC  (Area Zone)
#   ALLOW  → Historian (Server Zone)          — data storage
#   DENY   → Maintenance Laptop (Operator)    — cannot accept inbound from Operator
#             [Operator initiates to Area, Area cannot initiate to Operator]
#   DENY   → Cloud System (Enterprise Zone)   — OT never reaches Enterprise
#   DENY   → Internet                         — OT is air-gapped from internet
#   INTRA  → HMI (same Area Zone)             — direct OT coupling, expected ALLOW
# ─────────────────────────────────────────────────────────────────────────────
run_tests_plc() {
    _section "ALLOWED connections (PLC should reach these)"

    run_test "PLC-A1" \
        "PLC → Historian [Server Zone] — data storage path" \
        ALLOW "$IP_HISTORIAN" "$PORT_HISTORIAN"

    run_test "PLC-A2" \
        "PLC → HMI [Area Zone] — direct intra-zone OT coupling" \
        ALLOW "$IP_HMI" "$PORT_HMI"

    _section "DENIED connections (PLC must NOT reach these)"

    run_test "PLC-D1" \
        "PLC → Maintenance Laptop [Operator Zone] — Area cannot initiate into Operator Zone" \
        DENY "$IP_LAPTOP" "$PORT_LAPTOP"

    run_test "PLC-D2" \
        "PLC → Cloud System [Enterprise Zone] — OT must never reach Enterprise" \
        DENY "$IP_CLOUD" "$PORT_CLOUD"

    run_test "PLC-D3" \
        "PLC → Internet ($INTERNET_IP) — OT devices must be internet-isolated" \
        DENY INTERNET
}

# ─────────────────────────────────────────────────────────────────────────────
# HMI  (Area Zone)
#   Symmetric rules to the PLC — same zone, same firewall posture.
# ─────────────────────────────────────────────────────────────────────────────
run_tests_hmi() {
    _section "ALLOWED connections (HMI should reach these)"

    run_test "HMI-A1" \
        "HMI → Historian [Server Zone] — data storage path" \
        ALLOW "$IP_HISTORIAN" "$PORT_HISTORIAN"

    run_test "HMI-A2" \
        "HMI → PLC [Area Zone] — direct intra-zone OT coupling" \
        ALLOW "$IP_PLC" "$PORT_PLC"

    _section "DENIED connections (HMI must NOT reach these)"

    run_test "HMI-D1" \
        "HMI → Maintenance Laptop [Operator Zone] — Area cannot initiate into Operator Zone" \
        DENY "$IP_LAPTOP" "$PORT_LAPTOP"

    run_test "HMI-D2" \
        "HMI → Cloud System [Enterprise Zone] — OT must never reach Enterprise" \
        DENY "$IP_CLOUD" "$PORT_CLOUD"

    run_test "HMI-D3" \
        "HMI → Internet ($INTERNET_IP) — OT devices must be internet-isolated" \
        DENY INTERNET
}

# ─────────────────────────────────────────────────────────────────────────────
# MAINTENANCE LAPTOP  (Operator Zone)
#   ALLOW  → Historian (Server Zone)
#   ALLOW  → PLC       (Area Zone)
#   ALLOW  → HMI       (Area Zone)
#   DENY   → Cloud System (Enterprise Zone) — lateral movement prevention
#   DENY   → Internet                       — OT maintenance tool, air-gapped
# ─────────────────────────────────────────────────────────────────────────────
run_tests_laptop() {
    _section "ALLOWED connections (Maintenance Laptop should reach these)"

    run_test "LAP-A1" \
        "Laptop → Historian [Server Zone] — ICS maintenance access" \
        ALLOW "$IP_HISTORIAN" "$PORT_HISTORIAN"

    run_test "LAP-A2" \
        "Laptop → PLC [Area Zone] — ICS maintenance access" \
        ALLOW "$IP_PLC" "$PORT_PLC"

    run_test "LAP-A3" \
        "Laptop → HMI [Area Zone] — ICS maintenance access" \
        ALLOW "$IP_HMI" "$PORT_HMI"

    _section "DENIED connections (Maintenance Laptop must NOT reach these)"

    run_test "LAP-D1" \
        "Laptop → Cloud System [Enterprise Zone] — prevents cross-zone lateral movement" \
        DENY "$IP_CLOUD" "$PORT_CLOUD"

    run_test "LAP-D2" \
        "Laptop → Internet ($INTERNET_IP) — OT maintenance device must be internet-isolated" \
        DENY INTERNET
}

# ─────────────────────────────────────────────────────────────────────────────
# HISTORIAN  (Server Zone)
#   ALLOW  → Cloud System (Enterprise Zone) — the ONE allowed enterprise path
#   DENY   → Maintenance Laptop (Operator Zone) — Server cannot initiate to Operator
#   DENY   → PLC (Area Zone)                    — Server cannot initiate to Area
#   DENY   → HMI (Area Zone)                    — Server cannot initiate to Area
#   DENY   → Internet                           — OT device, must be air-gapped
# ─────────────────────────────────────────────────────────────────────────────
run_tests_historian() {
    _section "ALLOWED connections (Historian should reach these)"

    run_test "HIS-A1" \
        "Historian → Cloud System [Enterprise Zone] — authorised data upload path" \
        ALLOW "$IP_CLOUD" "$PORT_CLOUD"

    _section "DENIED connections (Historian must NOT reach these)"

    run_test "HIS-D1" \
        "Historian → Maintenance Laptop [Operator Zone] — Server Zone cannot initiate into Operator Zone" \
        DENY "$IP_LAPTOP" "$PORT_LAPTOP"

    run_test "HIS-D2" \
        "Historian → PLC [Area Zone] — Server Zone cannot initiate into Area Zone" \
        DENY "$IP_PLC" "$PORT_PLC"

    run_test "HIS-D3" \
        "Historian → HMI [Area Zone] — Server Zone cannot initiate into Area Zone" \
        DENY "$IP_HMI" "$PORT_HMI"

    run_test "HIS-D4" \
        "Historian → Internet ($INTERNET_IP) — Historian must be internet-isolated (only Cloud System reaches internet)" \
        DENY INTERNET
}

# ─────────────────────────────────────────────────────────────────────────────
# CLOUD SYSTEM  (Enterprise Zone)
#   ALLOW  → Internet                           — Cloud System is the internet gateway
#   DENY   → Historian (Server Zone)            — Enterprise cannot initiate into OT
#   DENY   → Maintenance Laptop (Operator Zone) — Enterprise cannot initiate into OT
#   DENY   → PLC (Area Zone)                    — Enterprise cannot initiate into OT
#   DENY   → HMI (Area Zone)                    — Enterprise cannot initiate into OT
# ─────────────────────────────────────────────────────────────────────────────
run_tests_cloud() {
    _section "ALLOWED connections (Cloud System should reach these)"

    run_test "CLD-A1" \
        "Cloud System → Internet ($INTERNET_IP) — Enterprise Zone is the intended internet-facing system" \
        ALLOW INTERNET

    _section "DENIED connections (Cloud System must NOT reach these)"

    run_test "CLD-D1" \
        "Cloud System → Historian [Server Zone] — Enterprise must not initiate into OT network" \
        DENY "$IP_HISTORIAN" "$PORT_HISTORIAN"

    run_test "CLD-D2" \
        "Cloud System → Maintenance Laptop [Operator Zone] — Enterprise must not initiate into OT network" \
        DENY "$IP_LAPTOP" "$PORT_LAPTOP"

    run_test "CLD-D3" \
        "Cloud System → PLC [Area Zone] — Enterprise must not initiate into OT network" \
        DENY "$IP_PLC" "$PORT_PLC"

    run_test "CLD-D4" \
        "Cloud System → HMI [Area Zone] — Enterprise must not initiate into OT network" \
        DENY "$IP_HMI" "$PORT_HMI"
}

# =============================================================================
# ── MAIN ─────────────────────────────────────────────────────────────────────
# =============================================================================
main() {
    # Optionally tee output to a report file
    if [[ -n "$REPORT_FILE" ]]; then
        exec > >(tee -a "$REPORT_FILE") 2>&1
    fi

    local device
    device=$(_pick_device)

    _header "ICS Network Zone Connectivity Test"
    _log ""
    _log "  ${C_BOLD}Timestamp :${C_RESET} $(date '+%Y-%m-%d %H:%M:%S %Z')"
    _log "  ${C_BOLD}Hostname  :${C_RESET} $(hostname 2>/dev/null || echo 'unknown')"
    _log "  ${C_BOLD}Local IPs :${C_RESET} $(hostname -I 2>/dev/null | tr ' ' ',' | sed 's/,$//' || echo 'unknown')"
    _log "  ${C_BOLD}Device ID :${C_RESET} ${device}"
    _log ""
    _log "  ${C_GRAY}Target IPs configured in this script:${C_RESET}"
    _log "  ${C_GRAY}  PLC            $IP_PLC${C_RESET}"
    _log "  ${C_GRAY}  HMI            $IP_HMI${C_RESET}"
    _log "  ${C_GRAY}  Laptop         $IP_LAPTOP${C_RESET}"
    _log "  ${C_GRAY}  Historian      $IP_HISTORIAN${C_RESET}"
    _log "  ${C_GRAY}  Cloud System   $IP_CLOUD${C_RESET}"
    _log "  ${C_GRAY}  Internet probe $INTERNET_IP${C_RESET}"
    _log ""
    _log "  ${C_GRAY}Probe method: ICMP ping (${TIMEOUT}s timeout) + TCP port check where applicable.${C_RESET}"
    _log "  ${C_GRAY}A DENY test that succeeds is reported as a ⚠ SECURITY VIOLATION.${C_RESET}"

    case "$device" in
        plc)
            _header "Running as: PLC  |  Zone: Area (10.0.0.0/24)"
            run_tests_plc
            ;;
        hmi)
            _header "Running as: HMI  |  Zone: Area (10.0.0.0/24)"
            run_tests_hmi
            ;;
        laptop)
            _header "Running as: Maintenance Laptop  |  Zone: Operator (10.10.0.0/24)"
            run_tests_laptop
            ;;
        historian)
            _header "Running as: Historian  |  Zone: Server (10.20.0.0/24)"
            run_tests_historian
            ;;
        cloud)
            _header "Running as: Cloud System  |  Zone: Enterprise (10.30.0.0/24)"
            run_tests_cloud
            ;;
        *)
            _log ""
            _log "${C_RED}${C_BOLD}ERROR: Could not auto-detect device identity.${C_RESET}"
            _log ""
            _log "  None of the configured device IPs matched a local interface."
            _log "  Run the script with an explicit identity flag, e.g.:"
            _log ""
            _log "    ${C_BOLD}./zone_connectivity_test.sh --device plc${C_RESET}"
            _log "    ${C_BOLD}./zone_connectivity_test.sh --device hmi${C_RESET}"
            _log "    ${C_BOLD}./zone_connectivity_test.sh --device laptop${C_RESET}"
            _log "    ${C_BOLD}./zone_connectivity_test.sh --device historian${C_RESET}"
            _log "    ${C_BOLD}./zone_connectivity_test.sh --device cloud${C_RESET}"
            _log ""
            _log "  Or update the IP addresses in Section 1 of the script."
            exit 2
            ;;
    esac

    # ── Summary ──────────────────────────────────────────────────────────────
    local total=$(( PASS + FAIL + WARN ))
    _log ""
    _log "${C_BLUE}${C_BOLD}╔══════════════════════════════════════════════════════════════╗${C_RESET}"
    _log "${C_BLUE}${C_BOLD}║  TEST SUMMARY                                                ║${C_RESET}"
    _log "${C_BLUE}${C_BOLD}╚══════════════════════════════════════════════════════════════╝${C_RESET}"
    _log ""
    _log "  Total tests run : $total"
    _log "  ${C_GREEN}${C_BOLD}PASSED          : $PASS${C_RESET}"
    _log "  ${C_RED}${C_BOLD}FAILED          : $FAIL${C_RESET}"
    _log "  ${C_MAGENTA}SKIPPED/WARN    : $WARN${C_RESET}"
    _log ""

    if [[ $FAIL -eq 0 && $WARN -eq 0 ]]; then
        _log "  ${C_GREEN}${C_BOLD}✔  All rules satisfied. Network zone isolation is correctly configured.${C_RESET}"
    elif [[ $FAIL -eq 0 ]]; then
        _log "  ${C_YELLOW}${C_BOLD}⚠  No failures, but some tests were skipped. Review SKIP entries above.${C_RESET}"
    else
        _log "  ${C_RED}${C_BOLD}✘  $FAIL rule(s) violated. Investigate FAIL entries above immediately.${C_RESET}"
        _log "  ${C_RED}     Any DENY test that PASSED a connection is a live security gap.${C_RESET}"
    fi

    _log ""

    if [[ -n "$REPORT_FILE" ]]; then
        _log "  Report saved to: $REPORT_FILE"
    fi

    # Exit with non-zero if any tests failed
    [[ $FAIL -eq 0 ]]
}

main "$@"
