#!/bin/bash
#
# build-plugin.sh
#
# 文件职责：验证、构建并使用稳定身份签名独立官方协议插件 Bundle。
#

set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bundle_source="${LEEWAY_PLUGIN_BUNDLE_SOURCE:-${project_root}/bundle}"
output_override="${LEEWAY_PLUGIN_BUNDLE_OUTPUT:-}"
package="leeway-protocol-mtr01-plugin"
validate_only=false
json_output=false
action="validate"

usage() {
    fail invalid_arguments 2 \
        "Usage: $(basename "$0") [--validate-template] [--json]"
}

fail() {
    local code="$1"
    local exit_code="$2"
    local message="$3"
    if [[ "${json_output}" == true ]]; then
        jq -n \
            --arg action "${action}" \
            --arg code "${code}" \
            --arg message "${message}" \
            '{
                schemaVersion: 1,
                ok: false,
                action: $action,
                error: {
                    code: $code,
                    message: $message
                },
                warnings: []
            }'
    else
        printf '%s: %s\n' "${code}" "${message}" >&2
    fi
    exit "${exit_code}"
}

while (($# > 0)); do
    case "$1" in
        --validate-template)
            validate_only=true
            shift
            ;;
        --json)
            json_output=true
            shift
            ;;
        *)
            usage
            ;;
    esac
done

file_hash() {
    /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'
}

require_file() {
    local path="$1"
    if [[ ! -f "${path}" ]]; then
        fail template_invalid 4 "Missing plugin Bundle file: ${path}"
    fi
}

checks='[]'
add_check() {
    local code="$1"
    local message="$2"
    checks="$(
        jq -c \
            --arg code "${code}" \
            --arg message "${message}" \
            '. + [{code: $code, status: "pass", message: $message}]' \
            <<<"${checks}"
    )"
}

manifest="${bundle_source}/Contents/Resources/plugin.json"
info_plist="${bundle_source}/Contents/Info.plist"
protocol_document_source="${project_root}/docs/PROTOCOL.md"
protocol_document_relative="Contents/Resources/protocol.md"
require_file "${info_plist}"
require_file "${manifest}"
require_file "${protocol_document_source}"
for resource in protocol.json scenario.json configuration.json; do
    require_file "${bundle_source}/Contents/Resources/${resource}"
done

if ! /usr/bin/plutil -lint "${info_plist}" >/dev/null 2>&1; then
    fail template_invalid 4 "Invalid plugin Info.plist."
fi
if /usr/bin/plutil -extract CFBundleExecutable raw \
    "${info_plist}" >/dev/null 2>&1
then
    fail template_invalid 4 "Plugin Bundle must not define CFBundleExecutable."
fi
for json_file in \
    plugin.json \
    protocol.json \
    scenario.json \
    configuration.json
do
    if ! jq empty \
        "${bundle_source}/Contents/Resources/${json_file}" \
        >/dev/null 2>&1
    then
        fail template_invalid 4 "Invalid plugin JSON: ${json_file}"
    fi
done

if ! jq -e '
    .schemaVersion == 1
    and (.pluginId | test("^[a-z0-9]+(?:\\.[a-z0-9][a-z0-9_-]*)+$"))
    and (.pluginId | length) <= 128
    and .abiVersion == 1
    and (.protocolId | type) == "string"
    and (.protocolVersion | type) == "string"
    and (.library | test(
        "^Contents/MacOS/[A-Za-z0-9][A-Za-z0-9._-]{0,121}\\.dylib$"
    ))
    and .protocolFile == "Contents/Resources/protocol.json"
    and .protocolDocumentFile == "Contents/Resources/protocol.md"
    and .scenarioFile == "Contents/Resources/scenario.json"
    and .configurationFile == "Contents/Resources/configuration.json"
    and (.architectures | length) >= 1
    and .files.librarySha256 ==
        "0000000000000000000000000000000000000000000000000000000000000000"
' "${manifest}" >/dev/null 2>&1
then
    fail template_invalid 4 "Invalid plugin manifest."
fi
add_check manifest "Plugin manifest is valid."

plugin_id="$(jq -r '.pluginId' "${manifest}")"
if [[ -n "${output_override}" ]]; then
    allowed_output="${project_root}/.build/verification/${plugin_id}.leewayplugin"
    if [[ "${output_override}" != "${allowed_output}" ]]; then
        fail \
            invalid_arguments \
            2 \
            "Verification output path must equal ${allowed_output}."
    fi
fi
protocol_id="$(jq -r '.protocolId' "${manifest}")"
protocol_version="$(jq -r '.protocolVersion' "${manifest}")"
library="$(jq -r '.library' "${manifest}")"
library_basename="${library#Contents/MacOS/}"

if ! bundle_identifier="$(
    /usr/bin/plutil -extract CFBundleIdentifier raw "${info_plist}" 2>/dev/null
)"
then
    fail template_invalid 4 "Plugin Bundle identifier is missing."
fi
if [[ "${bundle_identifier}" != "${plugin_id}" ]]; then
    fail template_invalid 4 "Bundle identifier does not match the manifest."
fi
add_check bundle_info "Bundle identifier and resource-only plist are valid."

if [[ ! -s "${protocol_document_source}" ]]; then
    fail template_invalid 4 "Protocol document must not be empty."
fi
add_check protocol_document "Original protocol document is present."

if ! jq -e \
    --arg protocol_id "${protocol_id}" \
    --arg protocol_version "${protocol_version}" \
    '
        .schemaVersion == 1
        and .protocolId == $protocol_id
        and .protocolVersion == $protocol_version
        and (.messages | length) >= 1
    ' \
    "${bundle_source}/Contents/Resources/protocol.json" \
    >/dev/null 2>&1
then
    fail template_invalid 4 "Protocol definition does not match the manifest."
fi
add_check protocol_definition "Protocol definition is valid."

if ! jq -e \
    --arg protocol_id "${protocol_id}" \
    --arg protocol_version "${protocol_version}" \
    '
        .schemaVersion == 1
        and (.scenarioId | test("^[a-z][a-zA-Z0-9_-]{0,63}$"))
        and .protocolId == $protocol_id
        and .protocolVersion == $protocol_version
    ' \
    "${bundle_source}/Contents/Resources/scenario.json" \
    >/dev/null 2>&1
then
    fail template_invalid 4 "Scenario definition does not match the manifest."
fi
add_check scenario_definition "Scenario definition is valid."

if ! jq -e '
    .schemaVersion == 1
    and (.fields | type) == "array"
    and (.fields | length) <= 8
' "${bundle_source}/Contents/Resources/configuration.json" \
    >/dev/null 2>&1
then
    fail template_invalid 4 "Plugin configuration schema is invalid."
fi
add_check configuration_schema "Configuration schema is valid."

while IFS=$'\t' read -r relative expected; do
    actual="$(file_hash "${bundle_source}/${relative}")"
    if [[ "${actual}" != "${expected}" ]]; then
        fail template_invalid 4 "Plugin resource hash mismatch: ${relative}"
    fi
done < <(
    jq -r '
        [
            ["Contents/Resources/protocol.json", .files.protocolSha256],
            ["Contents/Resources/scenario.json", .files.scenarioSha256],
            [
                "Contents/Resources/configuration.json",
                .files.configurationSha256
            ]
        ][]
        | @tsv
    ' "${manifest}"
)
add_check resource_hash "Plugin resource hashes are valid."

if ! command -v cargo >/dev/null 2>&1; then
    fail cargo_unavailable 4 "Cargo is unavailable."
fi
metadata_file="${TMPDIR:-/tmp}/leeway-standalone-plugin-metadata.$$.json"
metadata_error="${TMPDIR:-/tmp}/leeway-standalone-plugin-metadata.$$.err"
temp_files=("${metadata_file}" "${metadata_error}")
trap 'rm -f "${temp_files[@]}"' EXIT
if ! cargo metadata \
    --format-version 1 \
    --no-deps \
    --manifest-path "${project_root}/Cargo.toml" \
    >"${metadata_file}" 2>"${metadata_error}"
then
    fail invalid_project 2 "Cargo metadata rejected the standalone project."
fi
target_directory="$(
    jq -r '.target_directory // empty' "${metadata_file}"
)"
if [[ -z "${target_directory}" ]]; then
    fail invalid_project 2 "Cargo metadata did not return a target directory."
fi
package_count="$(
    jq \
        --arg package "${package}" \
        '[.packages[] | select(.name == $package)] | length' \
        "${metadata_file}"
)"
if [[ "${package_count}" -ne 1 ]]; then
    fail invalid_project 2 "Plugin Cargo package is missing or ambiguous."
fi
cdylib_targets="$(
    jq -r \
        --arg package "${package}" \
        '
            [
                .packages[]
                | select(.name == $package)
                | .targets[]
                | select(.kind | index("cdylib"))
                | .name
            ][]
        ' \
        "${metadata_file}"
)"
cdylib_count="$(
    /usr/bin/awk 'NF { count += 1 } END { print count + 0 }' \
        <<<"${cdylib_targets}"
)"
if [[ "${cdylib_count}" -ne 1 ]]; then
    fail invalid_project 2 "Plugin package must define exactly one cdylib target."
fi
cdylib_name="${cdylib_targets}"
add_check cargo_package "Cargo package and unique cdylib target are valid."
add_check target_directory "${target_directory}"

if [[ "${validate_only}" == true ]]; then
    if [[ "${json_output}" == true ]]; then
        jq -n \
            --argjson checks "${checks}" \
            '{
                schemaVersion: 1,
                ok: true,
                action: "validate",
                result: {
                    checks: $checks
                },
                warnings: []
            }'
    else
        printf 'Validated standalone plugin template: %s\n' "${bundle_source}"
    fi
    exit 0
fi

action="build"
signing_identity="${LEEWAY_CODE_SIGN_IDENTITY:-}"
if [[ -z "${signing_identity}" || "${signing_identity}" == "-" ]]; then
    fail signing_identity_missing 4 "Stable code-signing identity is required."
fi
identities="$(
    /usr/bin/security find-identity -v -p codesigning 2>/dev/null || true
)"
if ! /usr/bin/grep -Fq -- "${signing_identity}" <<<"${identities}"; then
    fail signing_identity_missing 4 "Requested code-signing identity is unavailable."
fi

if [[ ! -f "${project_root}/Cargo.lock" ]]; then
    lock_log="${TMPDIR:-/tmp}/leeway-standalone-plugin-lock.$$.log"
    temp_files+=("${lock_log}")
    if ! cargo generate-lockfile \
        --manifest-path "${project_root}/Cargo.toml" \
        >"${lock_log}" 2>&1
    then
        fail lock_failed 4 "Cargo.lock generation failed."
    fi
fi

build_log="${TMPDIR:-/tmp}/leeway-standalone-plugin-build.$$.log"
temp_files+=("${build_log}")
if ! CARGO_TARGET_DIR="${target_directory}" cargo build \
    --locked \
    --release \
    --manifest-path "${project_root}/Cargo.toml" \
    -p "${package}" \
    >"${build_log}" 2>&1
then
    fail build_failed 4 "Release plugin build failed."
fi

source_dylib="${target_directory}/release/lib${cdylib_name}.dylib"
if [[ ! -f "${source_dylib}" ]]; then
    fail build_failed 4 "Built plugin dylib is missing."
fi

output_root="${output_override:-${project_root}/.build/protocol-plugins/${plugin_id}.leewayplugin}"
rm -rf "${output_root}"
mkdir -p "${output_root}/Contents/MacOS"
/usr/bin/ditto \
    "${info_plist}" \
    "${output_root}/Contents/Info.plist"
/usr/bin/ditto \
    "${bundle_source}/Contents/Resources" \
    "${output_root}/Contents/Resources"
/usr/bin/ditto \
    "${protocol_document_source}" \
    "${output_root}/${protocol_document_relative}"
/usr/bin/ditto \
    "${source_dylib}" \
    "${output_root}/Contents/MacOS/${library_basename}"
chmod 755 "${output_root}/Contents/MacOS/${library_basename}"

if ! /usr/bin/codesign \
    --force \
    --sign "${signing_identity}" \
    --options runtime \
    --timestamp \
    "${output_root}/Contents/MacOS/${library_basename}" \
    >/dev/null 2>&1
then
    fail signature_failed 4 "Plugin dylib signing failed."
fi

final_library_hash="$(
    file_hash "${output_root}/Contents/MacOS/${library_basename}"
)"
architectures='[]'
for architecture in $(/usr/bin/lipo -archs "${source_dylib}"); do
    architectures="$(
        jq -c \
            --arg architecture "${architecture}" \
            '. + [$architecture]' <<<"${architectures}"
    )"
done

protocol_document_hash="$(
    file_hash "${output_root}/${protocol_document_relative}"
)"
manifest_tmp="$(
    mktemp "${output_root}/Contents/Resources/.plugin.XXXXXX"
)"
jq \
    --arg library "${final_library_hash}" \
    --arg protocol_document "${protocol_document_hash}" \
    --argjson architectures "${architectures}" \
    '
        .architectures = $architectures
        | .files.librarySha256 = $library
        | .protocolDocumentFile = "Contents/Resources/protocol.md"
        | .files.protocolDocumentSha256 = $protocol_document
    ' \
    "${output_root}/Contents/Resources/plugin.json" >"${manifest_tmp}"
mv "${manifest_tmp}" "${output_root}/Contents/Resources/plugin.json"

if ! /usr/bin/codesign \
    --force \
    --sign "${signing_identity}" \
    --options runtime \
    --timestamp \
    "${output_root}" \
    >/dev/null 2>&1
then
    fail signature_failed 4 "Plugin Bundle signing failed."
fi
if ! /usr/bin/codesign \
    --verify \
    --deep \
    --strict \
    --verbose=2 \
    "${output_root}" \
    >/dev/null 2>&1
then
    fail signature_failed 4 "Plugin Bundle signature verification failed."
fi

code_resources="${output_root}/Contents/_CodeSignature/CodeResources"
if [[ ! -f "${code_resources}" ]] ||
    ! /usr/bin/plutil -p "${code_resources}" |
        /usr/bin/grep -Fq "\"MacOS/${library_basename}\" =>"
then
    fail signature_failed 4 "CodeResources does not seal the nested dylib."
fi

bundle_details="$(
    /usr/bin/codesign -dv --verbose=4 "${output_root}" 2>&1
)"
library_details="$(
    /usr/bin/codesign -dv --verbose=4 \
        "${output_root}/Contents/MacOS/${library_basename}" 2>&1
)"
bundle_team_id="$(
    /usr/bin/sed -n 's/^TeamIdentifier=//p' <<<"${bundle_details}" |
        /usr/bin/head -n 1
)"
library_team_id="$(
    /usr/bin/sed -n 's/^TeamIdentifier=//p' <<<"${library_details}" |
        /usr/bin/head -n 1
)"
bundle_timestamp="$(
    /usr/bin/sed -n 's/^Timestamp=//p' <<<"${bundle_details}" |
        /usr/bin/head -n 1
)"
if [[ -z "${bundle_team_id}" || "${bundle_team_id}" == "not set" ||
    "${library_team_id}" != "${bundle_team_id}" ]]
then
    fail signature_failed 4 "Plugin Bundle and dylib Team IDs do not match."
fi
if [[ -z "${bundle_timestamp}" || "${bundle_timestamp}" == "none" ]]; then
    fail signature_failed 4 "Plugin Bundle signature has no secure timestamp."
fi

if [[ "${json_output}" == true ]]; then
    jq -n \
        --arg bundle "${output_root}" \
        --arg dylib "${output_root}/Contents/MacOS/${library_basename}" \
        --arg hash "${final_library_hash}" \
        --argjson architectures "${architectures}" \
        --arg bundle_team "${bundle_team_id}" \
        --arg dylib_team "${library_team_id}" \
        '{
            schemaVersion: 1,
            ok: true,
            action: "build",
            result: {
                bundlePath: $bundle,
                dylibPath: $dylib,
                finalDylibSha256: $hash,
                architectures: $architectures,
                bundleTeamId: $bundle_team,
                dylibTeamId: $dylib_team,
                teamsMatch: ($bundle_team == $dylib_team),
                codesignVerified: true,
                codeResourcesVerified: true
            },
            warnings: []
        }'
else
    printf 'Built plugin: %s\n' "${output_root}"
    printf 'Team ID: %s\n' "${bundle_team_id}"
fi
