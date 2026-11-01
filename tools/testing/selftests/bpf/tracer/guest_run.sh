#!/bin/bash

set -Eeuo pipefail

SUITE="${1:-smoke}"
shift || true

TRACER_DIR="/root/bpf/tracer"
OUTPUT_ROOT="/output"
TEST_PROGS_BIN="/root/bpf/test_progs"
TEST_BPF_MODULE="/root/bpf/test_bpf.ko"

if [ ! -d "${OUTPUT_ROOT}" ] || [ ! -w "${OUTPUT_ROOT}" ]; then
	echo "The vmtest output share is not mounted at ${OUTPUT_ROOT}" >&2
	exit 1
fi

if [ ! -x "${TRACER_DIR}/trace_user" ]; then
	echo "Missing tracer executable: ${TRACER_DIR}/trace_user" >&2
	exit 1
fi

mkdir -p "${OUTPUT_ROOT}/test_progs" "${OUTPUT_ROOT}/test_bpf"
uname -a > "${OUTPUT_ROOT}/guest-uname.txt"
cat /proc/cmdline > "${OUTPUT_ROOT}/guest-cmdline.txt"

run_test_progs()
{
	TRACE_OUTPUT_DIR="${OUTPUT_ROOT}/test_progs" \
	TEST_PROGS_BIN="${TEST_PROGS_BIN}" \
		"${TRACER_DIR}/run_traces.sh" "$@"
}

run_test_bpf()
{
	TRACE_OUTPUT_DIR="${OUTPUT_ROOT}/test_bpf" \
	TEST_BPF_MODULE="${TEST_BPF_MODULE}" \
		"${TRACER_DIR}/run_test_bpf.sh"
}

run_smoke()
{
	local available candidate
	local -a selected=()
	local -a preferred=(
		"tailcalls"
		"verifier_bswap"
	)

	available="$("${TEST_PROGS_BIN}" -l)"
	for candidate in "${preferred[@]}"; do
		if grep -qx "${candidate}" <<<"${available}"; then
			selected+=("${candidate}")
		fi
	done

	if [ "${#selected[@]}" -eq 0 ]; then
		candidate="$(sed -n '1p' <<<"${available}")"
		if [ -z "${candidate}" ]; then
			echo "test_progs did not report any available tests" >&2
			exit 1
		fi
		selected=("${candidate}")
	fi

	echo "Smoke tests: ${selected[*]}"
	run_test_progs "${selected[@]}"
}

cd "${TRACER_DIR}"

case "${SUITE}" in
map-helper)
	"${TRACER_DIR}/map_helper_smoke.sh"
	;;
helper-memory)
	"${TRACER_DIR}/helper_memory_smoke.sh"
	;;
smoke)
	run_smoke
	;;
test_progs)
	run_test_progs "$@"
	;;
test_bpf)
	run_test_bpf
	;;
all)
	run_test_progs
	run_test_bpf
	;;
*)
	echo "Unknown suite: ${SUITE}" >&2
	exit 2
	;;
esac

echo "BPF observer experiment completed: ${SUITE}"
