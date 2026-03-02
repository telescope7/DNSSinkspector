#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_HOME="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${APP_HOME}"

if ! command -v java >/dev/null 2>&1; then
    echo "java not found on PATH" >&2
    exit 1
fi

JAR_FILE=""
while IFS= read -r candidate; do
    if [[ -s "${candidate}" ]]; then
        JAR_FILE="${candidate}"
        break
    fi
done < <(find "${APP_HOME}/lib" -maxdepth 1 -type f -name '*.jar' ! -name '._*' | sort)

if [[ -z "${JAR_FILE}" ]]; then
    echo "No runnable jar found under ${APP_HOME}/lib" >&2
    exit 1
fi

DEFAULT_CONFIG="${SINKHOLE_CONFIG:-${APP_HOME}/config/sinkhole.toml}"
ARGS=("$@")
HAS_CONFIG=false
for ((i = 0; i < ${#ARGS[@]}; i++)); do
    if [[ "${ARGS[$i]}" == "--config" ]]; then
        HAS_CONFIG=true
        break
    fi
done

if [[ "${HAS_CONFIG}" == false ]]; then
    ARGS=(--config "${DEFAULT_CONFIG}" "${ARGS[@]}")
fi

if [[ -n "${JAVA_OPTS:-}" ]]; then
    JAVA_ARGS=()
    read -r -a JAVA_ARGS <<< "${JAVA_OPTS}"
    exec java "${JAVA_ARGS[@]}" -jar "${JAR_FILE}" "${ARGS[@]}"
fi

exec java -jar "${JAR_FILE}" "${ARGS[@]}"
