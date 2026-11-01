#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
set -Eeuo pipefail

TRACER_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
TEST_PROGS_BIN="${TEST_PROGS_BIN:-${TRACER_DIR}/../test_progs}"
OUTPUT_ROOT="${OUTPUT_ROOT:-/output}"
TRACE_PID=""
READY_FILE=""
OLD_JIT="$(cat /proc/sys/net/core/bpf_jit_enable)"

cleanup()
{
	if [ -n "${TRACE_PID}" ]; then
		kill -INT "${TRACE_PID}" 2>/dev/null || true
		wait "${TRACE_PID}" || true
	fi
	[ -z "${READY_FILE}" ] || rm -f "${READY_FILE}"
	echo "${OLD_JIT}" > /proc/sys/net/core/bpf_jit_enable
}
trap cleanup EXIT

echo 0 > /proc/sys/net/core/bpf_jit_enable
mkdir -p "${OUTPUT_ROOT}/test_progs" "${OUTPUT_ROOT}/diagnostics"
cd "${TRACER_DIR}/.."
# Every program checks its result and canaries against constants both times.
if ! "${TEST_PROGS_BIN}" -a map_helpers > "${OUTPUT_ROOT}/map-baseline.log" 2>&1; then
	cat "${OUTPUT_ROOT}/map-baseline.log" >&2
	exit 1
fi

capture()
{
	local output="$1" log="$2"
	shift 2
	READY_FILE="$(mktemp)"
	rm -f "${READY_FILE}"
	TRACE_READY_FILE="${READY_FILE}" "${TRACER_DIR}/trace_user" "${output}" \
		> "${log}.tracer" 2>&1 &
	TRACE_PID=$!
	for ((attempt = 0; attempt < 200; attempt++)); do
		[ ! -f "${READY_FILE}" ] || break
		kill -0 "${TRACE_PID}"
		sleep 0.05
	done
	[ -f "${READY_FILE}" ]
	if ! "${TEST_PROGS_BIN}" "$@" > "${log}" 2>&1; then
		cat "${log}" >&2
		exit 1
	fi
	kill -INT "${TRACE_PID}"
	wait "${TRACE_PID}"
	TRACE_PID=""
	rm -f "${READY_FILE}"
	READY_FILE=""
}

export TRACE_FIXTURE_FILE="${OUTPUT_ROOT}/map-fixture.txt"
: > "${TRACE_FIXTURE_FILE}"
capture "${OUTPUT_ROOT}/test_progs/map_helpers.json" "${OUTPUT_ROOT}/map-captured.log" \
	-a map_helpers/array_ops,map_helpers/array_1022,map_helpers/array_tail,map_helpers/array_overlap,map_helpers/array_map_key,map_helpers/array_direct
capture "${OUTPUT_ROOT}/diagnostics/map_alias.json" "${OUTPUT_ROOT}/map-alias.log" \
	-a map_helpers/array_alias,map_helpers/array_key_alias
capture "${OUTPUT_ROOT}/diagnostics/map_budget.json" "${OUTPUT_ROOT}/map-budget.log" \
	-a map_helpers/array_1023
"${TRACER_DIR}/helper_memory_smoke.sh"
