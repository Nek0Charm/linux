#!/bin/bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
KERNEL_DIR="$(cd -- "${SCRIPT_DIR}/../../../../.." && pwd -P)"
VMTEST="${KERNEL_DIR}/tools/testing/selftests/bpf/vmtest.sh"

SUITE="smoke"
CACHE_DIR="${BPF_VMTEST_CACHE:-${HOME}/.bpf_selftests}"
RESULTS_DIR=""
ROOTFS_ARCHIVE=""
UPDATE_IMAGE="no"
ALLOW_TCG="no"
JOBS="$(nproc)"
declare -a TESTS=()

PLATFORM="${PLATFORM:-$(uname -m)}"
case "${PLATFORM}" in
x86_64) QEMU_BINARY="qemu-system-x86_64" ;;
aarch64) QEMU_BINARY="qemu-system-aarch64" ;;
*)
	echo "Unsupported architecture: ${PLATFORM}; only x86_64 and aarch64 are supported." >&2
	exit 1
	;;
esac

usage()
{
	cat <<EOF
Usage: $0 [options]

Build the kernel and tracer, boot the vmtest VM, run the selected tracing
experiment, and write JSON files to a host directory.

Options:
  --suite <smoke|map-helper|helper-memory|test_progs|test_bpf|all>
                              Experiment suite (default: smoke)
  --test <name>               test_progs test name; may be repeated
  --output <directory>        Result directory
  --cache <directory>         vmtest image/config cache
                              (default: ${CACHE_DIR})
  --rootfs <archive.tar.zst>  Local libbpf CI rootfs archive
  --update-image              Recreate the cached rootfs image
  --jobs <number>             Parallel build jobs (default: ${JOBS})
  --allow-tcg                 Permit slow QEMU emulation without KVM
  -h, --help                  Show this help
EOF
}

while (($#)); do
	case "$1" in
	--suite)
		SUITE="$2"
		shift 2
		;;
	--test)
		TESTS+=("$2")
		shift 2
		;;
	--output)
		RESULTS_DIR="$2"
		shift 2
		;;
	--cache)
		CACHE_DIR="$2"
		shift 2
		;;
	--rootfs)
		ROOTFS_ARCHIVE="$2"
		shift 2
		;;
	--update-image)
		UPDATE_IMAGE="yes"
		shift
		;;
	--jobs)
		JOBS="$2"
		shift 2
		;;
	--allow-tcg)
		ALLOW_TCG="yes"
		shift
		;;
	-h|--help)
		usage
		exit 0
		;;
	*)
		echo "Unknown option: $1" >&2
		usage >&2
		exit 2
		;;
	esac
done

case "${SUITE}" in
smoke|map-helper|helper-memory|test_progs|test_bpf|all) ;;
*)
	echo "Unknown suite: ${SUITE}" >&2
	exit 2
	;;
esac

if [ "${#TESTS[@]}" -gt 0 ] && [ "${SUITE}" != "test_progs" ]; then
	echo "--test can only be used with --suite test_progs" >&2
	exit 2
fi

for tool in clang bpftool jq make pahole "${QEMU_BINARY}" zstd; do
	if ! command -v "${tool}" >/dev/null 2>&1; then
		echo "Missing required host tool: ${tool}" >&2
		exit 1
	fi
done

if [ ! -r /dev/kvm ]; then
	if [ "${ALLOW_TCG}" != "yes" ]; then
		echo "/dev/kvm is not accessible. Enable KVM or pass --allow-tcg for a slow smoke run." >&2
		exit 1
	fi
	export BPF_VM_USE_KVM=0
	echo "Warning: running without KVM; full suites can take a very long time." >&2
else
	export BPF_VM_USE_KVM=1
fi

mkdir -p "${CACHE_DIR}"
CACHE_DIR="$(realpath "${CACHE_DIR}")"

if [ -z "${RESULTS_DIR}" ]; then
	RESULTS_DIR="${SCRIPT_DIR}/results/$(date -u +%Y%m%dT%H%M%SZ)-${SUITE}"
fi
mkdir -p "${RESULTS_DIR}"
RESULTS_DIR="$(realpath "${RESULTS_DIR}")"

if [ -n "${ROOTFS_ARCHIVE}" ]; then
	ROOTFS_ARCHIVE="$(realpath "${ROOTFS_ARCHIVE}")"
	if [ ! -f "${ROOTFS_ARCHIVE}" ]; then
		echo "Rootfs archive not found: ${ROOTFS_ARCHIVE}" >&2
		exit 1
	fi
fi

declare -a VMTEST_ARGS=(
	-d "${CACHE_DIR}"
	-r "${RESULTS_DIR}"
	-j "${JOBS}"
)
export BPF_VMTEST_BUILD_TARGETS="PCAP_CFLAGS= PCAP_LIBS= SKIP_LLVM=1 test_progs"

if [ -n "${ROOTFS_ARCHIVE}" ]; then
	VMTEST_ARGS+=(-l "${ROOTFS_ARCHIVE}")
fi
if [ "${UPDATE_IMAGE}" = "yes" ] || [ ! -f "${CACHE_DIR}/root.img" ]; then
	VMTEST_ARGS+=(-i)
fi

# git -C "${KERNEL_DIR}" rev-parse HEAD > "${RESULTS_DIR}/git-commit.txt"
printf '%s\n' "${SUITE}" > "${RESULTS_DIR}/suite.txt"

echo "Kernel tree: ${KERNEL_DIR}"
echo "VM cache:    ${CACHE_DIR}"
echo "Results:     ${RESULTS_DIR}"
echo "Suite:       ${SUITE}"

VALID_JSON_COUNT=0
EMPTY_JSON_COUNT=0
INVALID_JSON_COUNT=0
UNSUPPORTED_JSON_COUNT=0

check_json_results()
{
	local file state

	shopt -s nullglob
	for file in "${RESULTS_DIR}"/{test_progs,test_bpf}/*.json{,.tmp}; do
		if [[ "${file}" == *.tmp ]] || ! state="$(jq -sr '
			if length != 1 or (.[0] | type) != "array" then error("expected one run array")
			else .[0] | if length == 0 then "empty"
			elif any(.[]; .capture_status != "complete" and .capture_status != "unsupported") then "error"
			elif any(.[]; .capture_status == "unsupported") then "unsupported"
			else "complete" end end
		' "${file}")"; then
			state=error
		fi
		case "${state}" in
		complete) VALID_JSON_COUNT=$((VALID_JSON_COUNT + 1)) ;;
		unsupported) UNSUPPORTED_JSON_COUNT=$((UNSUPPORTED_JSON_COUNT + 1)) ;;
		empty) EMPTY_JSON_COUNT=$((EMPTY_JSON_COUNT + 1)) ;;
		*)
			INVALID_JSON_COUNT=$((INVALID_JSON_COUNT + 1))
			echo "Invalid JSON or incomplete capture: ${file}" >&2
			;;
		esac
	done
	shopt -u nullglob
}

set +e
"${VMTEST}" "${VMTEST_ARGS[@]}" -- \
	./tracer/guest_run.sh "${SUITE}" "${TESTS[@]}" \
	2>&1 | tee "${RESULTS_DIR}/vmtest-console.log"
status=${PIPESTATUS[0]}
set -e

if [ -f "${RESULTS_DIR}/exit-status" ]; then
	status="$(cat "${RESULTS_DIR}/exit-status")"
fi

check_json_results

if [ "${INVALID_JSON_COUNT}" -gt 0 ]; then
	echo "Error: ${INVALID_JSON_COUNT} invalid or incomplete JSON file(s)." >&2
	if [ "${status}" -eq 0 ]; then
		status=1
	fi
fi
if [ "${VALID_JSON_COUNT}" -eq 0 ]; then
	echo "Error: no non-empty JSON trace with complete capture status was generated." >&2
	if [ "${status}" -eq 0 ]; then
		status=1
	fi
fi

echo "JSON complete status:   ${VALID_JSON_COUNT}"
echo "JSON unsupported:       ${UNSUPPORTED_JSON_COUNT}"
echo "JSON empty:             ${EMPTY_JSON_COUNT}"
echo "JSON invalid/incomplete:${INVALID_JSON_COUNT}"
echo "Exit status: ${status}"
echo "Results: ${RESULTS_DIR}"

exit "${status}"
