#!/bin/bash
#
#  build-verification-plugin.sh
#  scripts
#
#  文件职责：生成不修改源 Bundle 的 MTR01 端到端验证变体并复用正式签名逻辑。
#

set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_bundle="${project_root}/bundle"
build_root="${project_root}/.build"
verification_source="${build_root}/verification-source"
verification_output="${build_root}/verification/com.leeway.mtr01.leewayplugin"
required_identity="${LEEWAY_CODE_SIGN_IDENTITY:-}"

if [[ -z "${required_identity}" || "${required_identity}" == "-" ]]; then
    printf 'Stable code-signing identity is required.\n' >&2
    exit 4
fi
if [[ ! -d "${source_bundle}" ]]; then
    printf 'Source plugin Bundle is missing.\n' >&2
    exit 4
fi

mkdir -p "${build_root}"
temporary_source="$(
    mktemp -d "${build_root}/verification-source.XXXXXX"
)"
trap 'rm -rf "${temporary_source}"' EXIT

/usr/bin/ditto \
    "${source_bundle}" \
    "${temporary_source}/bundle"
scenario="${temporary_source}/bundle/Contents/Resources/scenario.json"
manifest="${temporary_source}/bundle/Contents/Resources/plugin.json"
scenario_tmp="${scenario}.tmp"
jq '.scenarioId = "mtr01-plugin-sim"' \
    "${scenario}" >"${scenario_tmp}"
mv "${scenario_tmp}" "${scenario}"

file_hash() {
    /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'
}
manifest_tmp="${manifest}.tmp"
jq \
    --arg protocol "$(
        file_hash \
            "${temporary_source}/bundle/Contents/Resources/protocol.json"
    )" \
    --arg scenario "$(file_hash "${scenario}")" \
    --arg configuration "$(
        file_hash \
            "${temporary_source}/bundle/Contents/Resources/configuration.json"
    )" \
    '
        .files.protocolSha256 = $protocol
        | .files.scenarioSha256 = $scenario
        | .files.configurationSha256 = $configuration
    ' \
    "${manifest}" >"${manifest_tmp}"
mv "${manifest_tmp}" "${manifest}"

rm -rf "${verification_source}"
mv "${temporary_source}/bundle" "${verification_source}"

mkdir -p "${build_root}/verification"
LEEWAY_PLUGIN_BUNDLE_SOURCE="${verification_source}" \
LEEWAY_PLUGIN_BUNDLE_OUTPUT="${verification_output}" \
    bash "${project_root}/scripts/build-plugin.sh" "$@"

validate_only=false
for argument in "$@"; do
    if [[ "${argument}" == "--validate-template" ]]; then
        validate_only=true
    fi
done
if [[ "${validate_only}" == false && ! -d "${verification_output}" ]]; then
    printf 'Verification plugin output is missing.\n' >&2
    exit 4
fi
