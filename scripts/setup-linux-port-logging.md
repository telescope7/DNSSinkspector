# setup-linux-port-logging.sh Walkthrough

This document explains each major block in [`scripts/setup-linux-port-logging.sh`](/Users/mthomas/eclipse-workspace/DNSSinkspector/scripts/setup-linux-port-logging.sh).

## 1) Script Preamble and Constants

What it does:
- Enables strict shell mode (`set -euo pipefail`) so failures are not ignored.
- Defines action mode (`install`, `remove`, `status`).
- Defines names for:
  - iptables log prefix (`DNSSINK_PORTLOG`)
  - custom chains (`DNSSINK_PORTLOG_IN`, `..._OUT`, `..._FWD`)
  - rsyslog config path
  - logrotate config path
  - output log file (`/var/log/dnssinkspector/port-events.log`)

Why:
- Keeps paths and identifiers centralized for easier maintenance.

## 2) `usage()`

What it does:
- Prints command syntax and available actions.

Why:
- Fast operator reference without opening docs.

## 3) `require_root()`

What it does:
- Exits if the script is not running as root.

Why:
- `iptables`, `/etc/rsyslog.d`, and `/var/log` modifications require root.

## 4) `require_cmd()`

What it does:
- Verifies required binaries exist (`iptables`, `rsyslogd`, etc.).

Why:
- Fails early with actionable errors instead of partial setup.

## 5) `restart_rsyslog()`

What it does:
- Restarts rsyslog via `systemctl` or `service`.

Why:
- New/changed rsyslog config does not apply until reload/restart.

## 6) Chain Management Functions

Functions:
- `ensure_chain(chain)`
- `ensure_jump(parent, chain)`
- `remove_jumps(parent, chain)`

What they do:
- Create and flush custom chains.
- Insert parent-chain jumps to those chains.
- Remove jumps during uninstall.

Why:
- Makes setup idempotent and cleanup deterministic.

## 7) `add_chain_rules(chain, direction)`

What it does:
- Adds rate-limited LOG rules:
  - TCP (prefer NEW state if conntrack is supported)
  - UDP
  - ICMP
  - low-rate catch-all for other protocols
- Appends `RETURN` so packets continue normal firewall processing.

Why:
- Captures connection metadata without turning firewall into an allow/deny policy.
- Rate limits protect kernel logs from floods.

## 8) `write_rsyslog_config()`

What it does:
- Creates `/var/log/dnssinkspector` and output file permissions.
- Writes rsyslog parser config:
  - matches messages containing `DNSSINK_PORTLOG`
  - extracts `direction`, `PROTO`, `SRC`, `DST`, `SPT`, `DPT`, interfaces, length
  - writes clean TSV-like lines to `/var/log/dnssinkspector/port-events.log`

Why:
- Converts noisy kernel log messages into analysis-friendly records.

## 9) `write_logrotate_config()`

What it does:
- Writes daily log rotation policy:
  - keep 14 compressed archives
  - skip empty/missing files
  - create secure permissions
  - HUP rsyslog after rotation

Why:
- Prevents unbounded growth in `/var/log`.

## 10) `install_port_logging()`

Execution order:
1. Validate root + dependencies.
2. Ensure custom chains exist and are refreshed.
3. Add rules for IN/OUT/FWD direction tags.
4. Hook chains into `INPUT`, `OUTPUT`, `FORWARD`.
5. Write rsyslog/logrotate config.
6. Restart rsyslog.

Result:
- Host starts emitting structured traffic metadata logs.

## 11) `remove_port_logging()`

Execution order:
1. Validate root + iptables.
2. Remove chain jumps from parent chains.
3. Flush/delete custom chains.
4. Remove rsyslog + logrotate configs.
5. Restart rsyslog.

Result:
- Logging hooks are removed, but existing log file content is preserved.

## 12) `status_port_logging()`

What it reports:
- Whether parent chain jumps are active.
- Whether rsyslog config file exists.
- Whether log file exists, line count, and recent lines.

Why:
- Quick health check after install or during operations.

## 13) Action Dispatcher (`case`)

What it does:
- Calls one of: `install_port_logging`, `remove_port_logging`, `status_port_logging`.
- Prints usage for unknown actions.

Why:
- Keeps entrypoint behavior explicit and predictable.
