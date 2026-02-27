#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if ! command -v mvn >/dev/null 2>&1; then
    echo "mvn not found on PATH" >&2
    exit 1
fi
if ! command -v zip >/dev/null 2>&1; then
    echo "zip not found on PATH" >&2
    exit 1
fi

cd "${PROJECT_ROOT}"
MAVEN_REPO_LOCAL="${MAVEN_REPO_LOCAL:-${PROJECT_ROOT}/.m2/repository}"

echo "Building jar with Maven..."
mvn -q -Dmaven.repo.local="${MAVEN_REPO_LOCAL}" -DskipTests clean package

ARTIFACT_ID="$(awk -F'[<>]' '/<artifactId>/{print $3; exit}' pom.xml)"
VERSION="$(awk -F'[<>]' '/<version>/{print $3; exit}' pom.xml)"
JAR_FILE="${PROJECT_ROOT}/target/${ARTIFACT_ID}-${VERSION}.jar"

if [[ ! -f "${JAR_FILE}" ]]; then
    JAR_FILE="$(find "${PROJECT_ROOT}/target" -maxdepth 1 -type f -name '*.jar' ! -name '*sources*' ! -name '*javadoc*' | head -n 1 || true)"
fi
if [[ -z "${JAR_FILE}" || ! -f "${JAR_FILE}" ]]; then
    echo "Unable to find built jar under target/" >&2
    exit 1
fi

DIST_ROOT="${PROJECT_ROOT}/dist"
BUNDLE_NAME="${ARTIFACT_ID}-${VERSION}"
BUNDLE_DIR="${DIST_ROOT}/${BUNDLE_NAME}"

rm -rf "${BUNDLE_DIR}"
mkdir -p "${BUNDLE_DIR}/bin" "${BUNDLE_DIR}/lib" "${BUNDLE_DIR}/config"

cp "${JAR_FILE}" "${BUNDLE_DIR}/lib/"
cp "${PROJECT_ROOT}/scripts/run.sh" "${BUNDLE_DIR}/bin/run.sh"
cp "${PROJECT_ROOT}/config/sinkhole.toml" "${BUNDLE_DIR}/config/sinkhole.toml"
cp "${PROJECT_ROOT}/README.md" "${BUNDLE_DIR}/README.md"
chmod +x "${BUNDLE_DIR}/bin/run.sh"

rm -f "${DIST_ROOT}/${BUNDLE_NAME}.zip" "${DIST_ROOT}/${BUNDLE_NAME}.tar.gz"
(
    cd "${DIST_ROOT}"
    zip -qr "${BUNDLE_NAME}.zip" "${BUNDLE_NAME}"
    tar -czf "${BUNDLE_NAME}.tar.gz" "${BUNDLE_NAME}"
)

echo "Distribution created:"
echo "  ${DIST_ROOT}/${BUNDLE_NAME}.zip"
echo "  ${DIST_ROOT}/${BUNDLE_NAME}.tar.gz"
echo "Run using:"
echo "  ${BUNDLE_DIR}/bin/run.sh"
