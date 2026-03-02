#!/usr/bin/env bash
set -euo pipefail

# DNSSinkspector Linux Port Logging Bootstrap
#
# Purpose:
# - Add dedicated iptables chains that emit kernel log events for traffic metadata.
# - Route those events via rsyslog into a structured TSV-style log file.
# - Configure rotation for the generated log file.
#
# Primary output:
#   /var/log/dnssinkspector/port-events.log
#
# Operational modes:
# - install: create/refresh chains and logging config
# - remove: delete chains/jumps and logging config files
# - status: inspect whether hooks/config/log are present

ACTION="${1:-install}"

# Shared names for iptables log prefix and custom chains.
# Prefix is parsed by rsyslog to select/filter these log lines.
PREFIX="DNSSINK_PORTLOG"
CHAIN_IN="DNSSINK_PORTLOG_IN"
CHAIN_OUT="DNSSINK_PORTLOG_OUT"
CHAIN_FWD="DNSSINK_PORTLOG_FWD"

# Linux system file paths used by this setup.
RSYSLOG_CONF="/etc/rsyslog.d/49-dnssinkspector-portlog.conf"
LOGROTATE_CONF="/etc/logrotate.d/dnssinkspector-portlog"
LOG_DIR="/var/log/dnssinkspector"
LOG_FILE="${LOG_DIR}/port-events.log"
RAW_LOG_FILE="${LOG_DIR}/port-events-raw.log"
SELFTEST_WAIT_SECONDS=3
LOG_OWNER="root"
LOG_GROUP="root"

IPTABLES_CMDS=()

init_firewall_cmds() {
    IPTABLES_CMDS=()
    if command -v iptables >/dev/null 2>&1; then
        IPTABLES_CMDS+=("iptables")
    fi
    if command -v ip6tables >/dev/null 2>&1; then
        IPTABLES_CMDS+=("ip6tables")
    fi
}

require_firewall_cmds() {
    init_firewall_cmds
    if [[ "${#IPTABLES_CMDS[@]}" -eq 0 ]]; then
        echo "Required command not found: iptables/ip6tables" >&2
        exit 1
    fi
}

run_fw() {
    local fw_cmd="$1"
    shift
    "${fw_cmd}" "$@"
}

chain_packet_count() {
    local fw_cmd="$1"
    local chain="$2"
    run_fw "${fw_cmd}" -vnL "${chain}" 2>/dev/null \
        | awk 'NR > 2 && $1 ~ /^[0-9]+$/ {sum += $1} END {print sum + 0}'
}

total_chain_packet_count() {
    local total=0
    local fw_cmd
    for fw_cmd in "${IPTABLES_CMDS[@]}"; do
        local in_count out_count fwd_count
        in_count="$(chain_packet_count "${fw_cmd}" "${CHAIN_IN}")"
        out_count="$(chain_packet_count "${fw_cmd}" "${CHAIN_OUT}")"
        fwd_count="$(chain_packet_count "${fw_cmd}" "${CHAIN_FWD}")"
        total=$((total + in_count + out_count + fwd_count))
    done
    echo "${total}"
}

generate_probe_traffic() {
    if command -v nc >/dev/null 2>&1; then
        nc -z -w1 127.0.0.1 9 >/dev/null 2>&1 || true
        nc -z -w1 ::1 9 >/dev/null 2>&1 || true
    elif command -v timeout >/dev/null 2>&1; then
        timeout 1 bash -lc 'cat < /dev/null > /dev/tcp/127.0.0.1/9' >/dev/null 2>&1 || true
    fi
    if command -v ping >/dev/null 2>&1; then
        ping -4 -c1 -W1 127.0.0.1 >/dev/null 2>&1 || true
        ping -6 -c1 -W1 ::1 >/dev/null 2>&1 || true
    fi
}

# CLI help/usage block.
usage() {
    cat <<'EOF'
Usage:
  sudo ./scripts/setup-linux-port-logging.sh [install|remove|status]

Actions:
  install  Configure iptables + rsyslog logging for inbound/outbound/forward traffic.
  remove   Remove DNSSinkspector iptables hooks and rsyslog routing config.
  status   Show current iptables hooks and log file status.
EOF
}

# Safety check: actions that modify firewall/syslog require root.
require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "This script must be run as root." >&2
        exit 1
    fi
}

# Guardrail: fail fast when required binaries are missing.
require_cmd() {
    local cmd="$1"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "Required command not found: ${cmd}" >&2
        exit 1
    fi
}

resolve_log_identity() {
    LOG_OWNER="root"
    LOG_GROUP="root"

    if id -u syslog >/dev/null 2>&1; then
        LOG_OWNER="syslog"
    fi

    if getent group adm >/dev/null 2>&1; then
        LOG_GROUP="adm"
    elif getent group "${LOG_OWNER}" >/dev/null 2>&1; then
        LOG_GROUP="${LOG_OWNER}"
    fi
}

# Restart rsyslog after config changes.
# Supports both systemd and SysV-style environments.
restart_rsyslog() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart rsyslog
    elif command -v service >/dev/null 2>&1; then
        service rsyslog restart
    else
        echo "Unable to restart rsyslog automatically (no systemctl/service)." >&2
        echo "Please restart rsyslog manually." >&2
        exit 1
    fi
}

# Ensure custom chain exists, then clear existing rules.
# This makes install idempotent (safe to re-run).
ensure_chain() {
    local fw_cmd="$1"
    local chain="$2"
    if ! run_fw "${fw_cmd}" -nL "${chain}" >/dev/null 2>&1; then
        run_fw "${fw_cmd}" -N "${chain}"
    fi
    run_fw "${fw_cmd}" -F "${chain}"
}

# Ensure parent chain has a jump to our custom chain.
# Insert at top so logging sees packets early.
ensure_jump() {
    local fw_cmd="$1"
    local parent="$2"
    local chain="$3"
    if ! run_fw "${fw_cmd}" -C "${parent}" -j "${chain}" >/dev/null 2>&1; then
        run_fw "${fw_cmd}" -I "${parent}" 1 -j "${chain}"
    fi
}

# Remove all parent->custom chain jumps (if multiple exist).
remove_jumps() {
    local fw_cmd="$1"
    local parent="$2"
    local chain="$3"
    while run_fw "${fw_cmd}" -C "${parent}" -j "${chain}" >/dev/null 2>&1; do
        run_fw "${fw_cmd}" -D "${parent}" -j "${chain}"
    done
}

# Add logging rules inside a custom chain.
# Rule strategy:
# - Log TCP SYN packets only (connection attempts)
# - Optionally log UDP NEW flows when conntrack is available
# - Skip established-flow, ICMP, and catch-all logging to reduce volume
# - Return to parent chain for normal packet handling
add_chain_rules() {
    local fw_cmd="$1"
    local chain="$2"
    local direction="$3"

    # Prefer TCP SYN logging to capture connection attempts without conntrack dependency.
    if ! run_fw "${fw_cmd}" -A "${chain}" \
        -p tcp \
        --syn \
        -m limit --limit 200/second --limit-burst 400 \
        -j LOG --log-prefix "${PREFIX} ${direction} " --log-level info 2>/dev/null; then
        # Fallback when --syn is unavailable: still only TCP at attempt-oriented rates.
        run_fw "${fw_cmd}" -A "${chain}" \
            -p tcp \
            -m limit --limit 200/second --limit-burst 400 \
            -j LOG --log-prefix "${PREFIX} ${direction} " --log-level info
    fi
    # UDP has no handshake; treat first packet of a flow as an "attempt" when conntrack is available.
    if run_fw "${fw_cmd}" -A "${chain}" \
        -p udp \
        -m conntrack --ctstate NEW \
        -m limit --limit 200/second --limit-burst 400 \
        -j LOG --log-prefix "${PREFIX} ${direction} " --log-level info 2>/dev/null; then
        :
    fi

    # Continue normal firewall traversal.
    run_fw "${fw_cmd}" -A "${chain}" -j RETURN
}

# Create log directory/file and emit rsyslog parsing config.
# rsyslog extracts fields from kernel log line and writes a cleaner record.
write_rsyslog_config() {
    resolve_log_identity
    install -d -m 0755 "${LOG_DIR}"
    touch "${LOG_FILE}"
    touch "${RAW_LOG_FILE}"
    chmod 0664 "${LOG_FILE}"
    chmod 0664 "${RAW_LOG_FILE}"
    chown "${LOG_OWNER}:${LOG_GROUP}" "${LOG_FILE}" "${RAW_LOG_FILE}" "${LOG_DIR}"

    cat > "${RSYSLOG_CONF}" <<'EOF'
# DNSSinkspector port logging parser/output.
# Input: kernel/iptables LOG lines that contain "DNSSINK_PORTLOG".
# Output: one line per event with extracted traffic metadata fields.
template(name="DnssinkPortRawFmt" type="string"
    string="%timereported:::date-rfc3339%\thost=%hostname%\traw=%$.line%\n")
template(name="DnssinkPortLogFmt" type="string"
    string="%timereported:::date-rfc3339%\thost=%hostname%\tdirection=%$.direction%\tprotocol=%$.proto%\tsrc_ip=%$.src%\tsrc_port=%$.spt%\tdst_ip=%$.dst%\tdst_port=%$.dpt%\tin_if=%$.inif%\tout_if=%$.outif%\tpacket_len=%$.pktlen%\n")

if (($msg contains "DNSSINK_PORTLOG") or ($rawmsg contains "DNSSINK_PORTLOG")) then {
    set $.line = $msg;
    if not ($.line contains "DNSSINK_PORTLOG") then {
        set $.line = $rawmsg;
    }
    action(type="omfile" file="/var/log/dnssinkspector/port-events-raw.log" template="DnssinkPortRawFmt" fileCreateMode="0664" dirCreateMode="0755")
    set $.direction = re_extract($.line, "DNSSINK_PORTLOG[ ]+(IN|OUT|FWD)", 0, 1, "UNK");
    set $.proto = re_extract($.line, "PROTO=([^ ]+)", 0, 1, "-");
    set $.src = re_extract($.line, "SRC=([^ ]+)", 0, 1, "-");
    set $.dst = re_extract($.line, "DST=([^ ]+)", 0, 1, "-");
    set $.spt = re_extract($.line, "SPT=([0-9]+)", 0, 1, "-");
    set $.dpt = re_extract($.line, "DPT=([0-9]+)", 0, 1, "-");
    set $.inif = re_extract($.line, "IN=([^ ]*)", 0, 1, "-");
    set $.outif = re_extract($.line, "OUT=([^ ]*)", 0, 1, "-");
    set $.pktlen = re_extract($.line, "LEN=([0-9]+)", 0, 1, "-");
    action(type="omfile" file="/var/log/dnssinkspector/port-events.log" template="DnssinkPortLogFmt" fileCreateMode="0664" dirCreateMode="0755")
    unset $.line;
    unset $.direction;
    unset $.proto;
    unset $.src;
    unset $.dst;
    unset $.spt;
    unset $.dpt;
    unset $.inif;
    unset $.outif;
    unset $.pktlen;
    stop
}
EOF
}

run_rsyslog_selftest() {
    local raw_before=0
    if [[ -f "${RAW_LOG_FILE}" ]]; then
        raw_before="$(wc -l < "${RAW_LOG_FILE}" 2>/dev/null || echo 0)"
    fi
    local packets_before
    packets_before="$(total_chain_packet_count)"

    local marker="DNSSINK_PORTLOG SELFTEST LOGGER_MARKER=$(date +%s)"
    if command -v logger >/dev/null 2>&1; then
        logger -t dnssinkspector-portlog "${marker}" || true
    fi
    generate_probe_traffic

    local waited=0
    local marker_seen=false
    while [[ "${waited}" -lt "${SELFTEST_WAIT_SECONDS}" ]]; do
        if [[ -f "${RAW_LOG_FILE}" ]] && grep -q "${marker}" "${RAW_LOG_FILE}" 2>/dev/null; then
            marker_seen=true
            break
        fi
        sleep 1
        waited=$((waited + 1))
    done

    local packets_after
    packets_after="$(total_chain_packet_count)"
    local packet_delta=$((packets_after - packets_before))

    local kernel_journal_seen=false
    if command -v journalctl >/dev/null 2>&1; then
        if journalctl -k --since '-2 minutes' --no-pager 2>/dev/null | grep -q 'DNSSINK_PORTLOG'; then
            kernel_journal_seen=true
        fi
    fi

    if [[ "${marker_seen}" == true ]]; then
        echo "Rsyslog self-test passed (marker reached ${RAW_LOG_FILE})."
    else
        echo "Warning: rsyslog self-test did not observe marker in ${RAW_LOG_FILE}." >&2
    fi

    if [[ "${packet_delta}" -gt 0 ]]; then
        echo "Packet self-test: firewall counters increased by ${packet_delta} packet(s)."
    else
        echo "Warning: packet self-test did not increment DNSSINK chains." >&2
        echo "Warning: likely firewall backend mismatch (nft/iptables) or rules not in active path." >&2
    fi

    if [[ "${kernel_journal_seen}" == true ]]; then
        echo "Kernel journal contains DNSSINK_PORTLOG lines."
    else
        echo "Warning: no DNSSINK_PORTLOG lines observed in kernel journal window." >&2
    fi

    if [[ "${packet_delta}" -gt 0 ]] && [[ "${marker_seen}" != true ]]; then
        echo "Warning: packets hit iptables chains but rsyslog file routing is failing." >&2
    fi

    local raw_after=0
    if [[ -f "${RAW_LOG_FILE}" ]]; then
        raw_after="$(wc -l < "${RAW_LOG_FILE}" 2>/dev/null || echo 0)"
    fi
    echo "Self-test raw log lines: before=${raw_before}, after=${raw_after}"
}

# Configure daily rotation to keep /var/log bounded.
write_logrotate_config() {
    resolve_log_identity

    cat > "${LOGROTATE_CONF}" <<EOF
${LOG_FILE} ${RAW_LOG_FILE} {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0664 ${LOG_OWNER} ${LOG_GROUP}
    postrotate
        /bin/systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
    endscript
}
EOF
}

# INSTALL FLOW:
# 1) Validate environment
# 2) Build/refresh custom chains and hook them into INPUT/OUTPUT/FORWARD
# 3) Write rsyslog/logrotate config
# 4) Restart rsyslog
install_port_logging() {
    require_root
    require_firewall_cmds
    require_cmd rsyslogd

    for fw_cmd in "${IPTABLES_CMDS[@]}"; do
        ensure_chain "${fw_cmd}" "${CHAIN_IN}"
        ensure_chain "${fw_cmd}" "${CHAIN_OUT}"
        ensure_chain "${fw_cmd}" "${CHAIN_FWD}"

        add_chain_rules "${fw_cmd}" "${CHAIN_IN}" "IN"
        add_chain_rules "${fw_cmd}" "${CHAIN_OUT}" "OUT"
        add_chain_rules "${fw_cmd}" "${CHAIN_FWD}" "FWD"

        ensure_jump "${fw_cmd}" INPUT "${CHAIN_IN}"
        ensure_jump "${fw_cmd}" OUTPUT "${CHAIN_OUT}"
        ensure_jump "${fw_cmd}" FORWARD "${CHAIN_FWD}"
    done

    write_rsyslog_config
    write_logrotate_config
    local rsyslog_check_output="/tmp/dnssinkspector-rsyslog-check.out"
    if ! rsyslogd -N1 >"${rsyslog_check_output}" 2>&1; then
        echo "Rsyslog config validation failed (rsyslogd -N1)." >&2
        sed -n '1,120p' "${rsyslog_check_output}" >&2 || true
        echo "Check ${RSYSLOG_CONF} for syntax/compatibility issues." >&2
        rm -f "${rsyslog_check_output}" || true
        exit 1
    fi
    rm -f "${rsyslog_check_output}" || true
    restart_rsyslog
    run_rsyslog_selftest

    echo "Installed DNSSinkspector Linux port logging."
    echo "Traffic log: ${LOG_FILE}"
    echo "Raw kernel match log: ${RAW_LOG_FILE}"
    echo "Note: if your distribution does not persist iptables rules, configure persistence separately."
}

# REMOVE FLOW:
# 1) Unhook parent chain jumps
# 2) Flush/delete custom chains
# 3) Remove rsyslog/logrotate config
# 4) Restart rsyslog
# Existing log file is intentionally retained.
remove_port_logging() {
    require_root
    require_firewall_cmds

    for fw_cmd in "${IPTABLES_CMDS[@]}"; do
        remove_jumps "${fw_cmd}" INPUT "${CHAIN_IN}"
        remove_jumps "${fw_cmd}" OUTPUT "${CHAIN_OUT}"
        remove_jumps "${fw_cmd}" FORWARD "${CHAIN_FWD}"

        for chain in "${CHAIN_IN}" "${CHAIN_OUT}" "${CHAIN_FWD}"; do
            if run_fw "${fw_cmd}" -nL "${chain}" >/dev/null 2>&1; then
                run_fw "${fw_cmd}" -F "${chain}"
                run_fw "${fw_cmd}" -X "${chain}"
            fi
        done
    done

    rm -f "${RSYSLOG_CONF}" "${LOGROTATE_CONF}"
    if command -v rsyslogd >/dev/null 2>&1; then
        restart_rsyslog
    fi

    echo "Removed DNSSinkspector Linux port logging hooks."
    echo "Existing log file retained at ${LOG_FILE}."
}

# STATUS FLOW:
# - Show whether iptables jumps are active
# - Show rsyslog config presence
# - Show log file presence and recent lines
status_port_logging() {
    require_firewall_cmds
    for fw_cmd in "${IPTABLES_CMDS[@]}"; do
        echo "${fw_cmd} jump status:"
        for pair in \
            "INPUT ${CHAIN_IN}" \
            "OUTPUT ${CHAIN_OUT}" \
            "FORWARD ${CHAIN_FWD}"; do
            parent="$(echo "${pair}" | awk '{print $1}')"
            chain="$(echo "${pair}" | awk '{print $2}')"
            if run_fw "${fw_cmd}" -C "${parent}" -j "${chain}" >/dev/null 2>&1; then
                echo "  ${parent} -> ${chain}: enabled"
            else
                echo "  ${parent} -> ${chain}: disabled"
            fi
        done
        for chain in "${CHAIN_IN}" "${CHAIN_OUT}" "${CHAIN_FWD}"; do
            if run_fw "${fw_cmd}" -nL "${chain}" >/dev/null 2>&1; then
                echo "  ${chain} counters (${fw_cmd}):"
                run_fw "${fw_cmd}" -vnL "${chain}" | sed 's/^/    /'
            fi
        done
    done

    echo "rsyslog config: ${RSYSLOG_CONF}"
    if [[ -f "${RSYSLOG_CONF}" ]]; then
        echo "  present"
    else
        echo "  missing"
    fi

    echo "log file: ${LOG_FILE}"
    if [[ -f "${LOG_FILE}" ]]; then
        echo "  present ($(wc -l < "${LOG_FILE}") lines)"
        tail -n 5 "${LOG_FILE}" || true
    else
        echo "  missing"
    fi

    echo "raw log file: ${RAW_LOG_FILE}"
    if [[ -f "${RAW_LOG_FILE}" ]]; then
        echo "  present ($(wc -l < "${RAW_LOG_FILE}") lines)"
        tail -n 5 "${RAW_LOG_FILE}" || true
    else
        echo "  missing"
    fi
    echo "log ownership:"
    ls -ld "${LOG_DIR}" "${LOG_FILE}" "${RAW_LOG_FILE}" 2>/dev/null | sed 's/^/  /' || true

    if command -v journalctl >/dev/null 2>&1; then
        echo "kernel journal matches (recent):"
        journalctl -k --no-pager -n 200 | grep 'DNSSINK_PORTLOG' | tail -n 5 || true
    fi
}

# Action dispatcher.
case "${ACTION}" in
install)
    install_port_logging
    ;;
remove)
    remove_port_logging
    ;;
status)
    status_port_logging
    ;;
help|-h|--help)
    usage
    ;;
*)
    echo "Unknown action: ${ACTION}" >&2
    usage
    exit 1
    ;;
esac
