#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-install}"

PREFIX="DNSSINK_PORTLOG"
CHAIN_IN="DNSSINK_PORTLOG_IN"
CHAIN_OUT="DNSSINK_PORTLOG_OUT"
CHAIN_FWD="DNSSINK_PORTLOG_FWD"

RSYSLOG_CONF="/etc/rsyslog.d/49-dnssinkspector-portlog.conf"
LOGROTATE_CONF="/etc/logrotate.d/dnssinkspector-portlog"
LOG_DIR="/var/log/dnssinkspector"
LOG_FILE="${LOG_DIR}/port-events.log"

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

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "This script must be run as root." >&2
        exit 1
    fi
}

require_cmd() {
    local cmd="$1"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "Required command not found: ${cmd}" >&2
        exit 1
    fi
}

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

ensure_chain() {
    local chain="$1"
    if ! iptables -nL "${chain}" >/dev/null 2>&1; then
        iptables -N "${chain}"
    fi
    iptables -F "${chain}"
}

ensure_jump() {
    local parent="$1"
    local chain="$2"
    if ! iptables -C "${parent}" -j "${chain}" >/dev/null 2>&1; then
        iptables -I "${parent}" 1 -j "${chain}"
    fi
}

remove_jumps() {
    local parent="$1"
    local chain="$2"
    while iptables -C "${parent}" -j "${chain}" >/dev/null 2>&1; do
        iptables -D "${parent}" -j "${chain}"
    done
}

add_chain_rules() {
    local chain="$1"
    local direction="$2"

    if ! iptables -A "${chain}" \
        -p tcp \
        -m conntrack --ctstate NEW \
        -m limit --limit 1200/second --limit-burst 2400 \
        -j LOG --log-prefix "${PREFIX} ${direction} " --log-level info 2>/dev/null; then
        iptables -A "${chain}" \
            -p tcp \
            -m limit --limit 1200/second --limit-burst 2400 \
            -j LOG --log-prefix "${PREFIX} ${direction} " --log-level info
    fi

    iptables -A "${chain}" \
        -p udp \
        -m limit --limit 1200/second --limit-burst 2400 \
        -j LOG --log-prefix "${PREFIX} ${direction} " --log-level info

    iptables -A "${chain}" \
        -p icmp \
        -m limit --limit 600/second --limit-burst 1200 \
        -j LOG --log-prefix "${PREFIX} ${direction} " --log-level info

    iptables -A "${chain}" \
        -m limit --limit 300/second --limit-burst 600 \
        -j LOG --log-prefix "${PREFIX} ${direction} " --log-level info

    iptables -A "${chain}" -j RETURN
}

write_rsyslog_config() {
    install -d -m 0750 "${LOG_DIR}"
    touch "${LOG_FILE}"
    chmod 0640 "${LOG_FILE}"
    if getent group adm >/dev/null 2>&1; then
        chown root:adm "${LOG_FILE}" "${LOG_DIR}"
    else
        chown root:root "${LOG_FILE}" "${LOG_DIR}"
    fi

    cat > "${RSYSLOG_CONF}" <<'EOF'
template(name="DnssinkPortLogFmt" type="string"
    string="%timereported:::date-rfc3339%\tdirection=%$.direction%\tprotocol=%$.proto%\tsrc_ip=%$.src%\tsrc_port=%$.spt%\tdst_ip=%$.dst%\tdst_port=%$.dpt%\tin_if=%$.inif%\tout_if=%$.outif%\tpacket_len=%$.pktlen%\n")

if ($msg contains "DNSSINK_PORTLOG ") then {
    set $.direction = re_extract($msg, "DNSSINK_PORTLOG (IN|OUT|FWD)", 0, 1, "UNK");
    set $.proto = re_extract($msg, "PROTO=([^ ]+)", 0, 1, "-");
    set $.src = re_extract($msg, "SRC=([^ ]+)", 0, 1, "-");
    set $.dst = re_extract($msg, "DST=([^ ]+)", 0, 1, "-");
    set $.spt = re_extract($msg, "SPT=([0-9]+)", 0, 1, "-");
    set $.dpt = re_extract($msg, "DPT=([0-9]+)", 0, 1, "-");
    set $.inif = re_extract($msg, "IN=([^ ]*)", 0, 1, "-");
    set $.outif = re_extract($msg, "OUT=([^ ]*)", 0, 1, "-");
    set $.pktlen = re_extract($msg, "LEN=([0-9]+)", 0, 1, "-");
    action(type="omfile" file="/var/log/dnssinkspector/port-events.log" template="DnssinkPortLogFmt")
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

write_logrotate_config() {
    local group_name="root"
    if getent group adm >/dev/null 2>&1; then
        group_name="adm"
    fi

    cat > "${LOGROTATE_CONF}" <<EOF
${LOG_FILE} {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root ${group_name}
    postrotate
        /bin/systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
    endscript
}
EOF
}

install_port_logging() {
    require_root
    require_cmd iptables
    require_cmd rsyslogd

    ensure_chain "${CHAIN_IN}"
    ensure_chain "${CHAIN_OUT}"
    ensure_chain "${CHAIN_FWD}"

    add_chain_rules "${CHAIN_IN}" "IN"
    add_chain_rules "${CHAIN_OUT}" "OUT"
    add_chain_rules "${CHAIN_FWD}" "FWD"

    ensure_jump INPUT "${CHAIN_IN}"
    ensure_jump OUTPUT "${CHAIN_OUT}"
    ensure_jump FORWARD "${CHAIN_FWD}"

    write_rsyslog_config
    write_logrotate_config
    restart_rsyslog

    echo "Installed DNSSinkspector Linux port logging."
    echo "Traffic log: ${LOG_FILE}"
    echo "Note: if your distribution does not persist iptables rules, configure persistence separately."
}

remove_port_logging() {
    require_root
    require_cmd iptables

    remove_jumps INPUT "${CHAIN_IN}"
    remove_jumps OUTPUT "${CHAIN_OUT}"
    remove_jumps FORWARD "${CHAIN_FWD}"

    for chain in "${CHAIN_IN}" "${CHAIN_OUT}" "${CHAIN_FWD}"; do
        if iptables -nL "${chain}" >/dev/null 2>&1; then
            iptables -F "${chain}"
            iptables -X "${chain}"
        fi
    done

    rm -f "${RSYSLOG_CONF}" "${LOGROTATE_CONF}"
    if command -v rsyslogd >/dev/null 2>&1; then
        restart_rsyslog
    fi

    echo "Removed DNSSinkspector Linux port logging hooks."
    echo "Existing log file retained at ${LOG_FILE}."
}

status_port_logging() {
    require_cmd iptables
    echo "iptables jump status:"
    for pair in \
        "INPUT ${CHAIN_IN}" \
        "OUTPUT ${CHAIN_OUT}" \
        "FORWARD ${CHAIN_FWD}"; do
        parent="$(echo "${pair}" | awk '{print $1}')"
        chain="$(echo "${pair}" | awk '{print $2}')"
        if iptables -C "${parent}" -j "${chain}" >/dev/null 2>&1; then
            echo "  ${parent} -> ${chain}: enabled"
        else
            echo "  ${parent} -> ${chain}: disabled"
        fi
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
}

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
