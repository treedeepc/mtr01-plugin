#!/bin/bash
#
#  test-build-plugin-output-guard.sh
#  scripts
#
#  文件职责：验证非法验证输出路径在删除动作前被拒绝且 sentinel 保持不变。
#

set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
builder="${project_root}/scripts/build-plugin.sh"
guard_parent="${project_root}/.build/output-guard-sentinel.$$"
sentinel="${guard_parent}/sentinel.leewayplugin"
output_file="${guard_parent}/builder.json"

mkdir -p "${sentinel}"
printf 'keep\n' >"${sentinel}/keep.txt"
trap 'rm -rf "${guard_parent}"' EXIT

set +e
LEEWAY_PLUGIN_BUNDLE_OUTPUT="${sentinel}" \
    bash "${builder}" --json >"${output_file}" 2>&1
status=$?
set -e

if [[ "${status}" -ne 2 ]]; then
    printf 'Invalid output guard exit was %s, expected 2.\n' \
        "${status}" >&2
    cat "${output_file}" >&2
    exit 1
fi
if ! jq -e '.ok == false and .error.code == "invalid_arguments"' \
    "${output_file}" >/dev/null
then
    cat "${output_file}" >&2
    exit 1
fi
if [[ ! -f "${sentinel}/keep.txt" || ! -d "${guard_parent}" ]]; then
    printf 'Invalid output override modified its sentinel path.\n' >&2
    exit 1
fi

printf 'Invalid verification output override rejected before deletion.\n'
