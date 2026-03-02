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

# Include default MaxMind ASN database when present.
if [[ -f "${PROJECT_ROOT}/GeoLite2-ASN.mmdb" ]]; then
    cp "${PROJECT_ROOT}/GeoLite2-ASN.mmdb" "${BUNDLE_DIR}/GeoLite2-ASN.mmdb"
else
    echo "Warning: GeoLite2-ASN.mmdb not found at project root; ASN enrichment may fail at runtime." >&2
fi

# Remove common macOS metadata files if they exist in the staging tree.
find "${BUNDLE_DIR}" -name '.DS_Store' -type f -delete || true
find "${BUNDLE_DIR}" -name '._*' -type f -delete || true

# On macOS, clear xattrs so tar/zip don't carry Apple provenance/resource metadata.
if command -v xattr >/dev/null 2>&1; then
    while IFS= read -r -d '' path; do
        xattr -c "${path}" 2>/dev/null || true
    done < <(find "${BUNDLE_DIR}" -print0)
fi

rm -f "${DIST_ROOT}/${BUNDLE_NAME}.zip" "${DIST_ROOT}/${BUNDLE_NAME}.tar.gz"
(
    cd "${DIST_ROOT}"
    # -X strips extra file attributes; -x filters known macOS archive noise.
    COPYFILE_DISABLE=1 zip -X -qr "${BUNDLE_NAME}.zip" "${BUNDLE_NAME}" \
        -x "*/.DS_Store" "*/._*" "__MACOSX/*"

    TAR_EXTRA_OPTS=""
    if tar --help 2>&1 | grep -q -- "--no-xattrs"; then
        TAR_EXTRA_OPTS="${TAR_EXTRA_OPTS} --no-xattrs"
    fi
    if tar --help 2>&1 | grep -q -- "--disable-copyfile"; then
        TAR_EXTRA_OPTS="${TAR_EXTRA_OPTS} --disable-copyfile"
    elif tar --help 2>&1 | grep -q -- "--no-mac-metadata"; then
        TAR_EXTRA_OPTS="${TAR_EXTRA_OPTS} --no-mac-metadata"
    fi

    # shellcheck disable=SC2086
    COPYFILE_DISABLE=1 tar ${TAR_EXTRA_OPTS} -czf "${BUNDLE_NAME}.tar.gz" "${BUNDLE_NAME}"
)

echo "Distribution created:"
echo "  ${DIST_ROOT}/${BUNDLE_NAME}.zip"
echo "  ${DIST_ROOT}/${BUNDLE_NAME}.tar.gz"
echo "Run using:"
echo "  ${BUNDLE_DIR}/bin/run.sh"
