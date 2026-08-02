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
  --suite <smoke|test_progs|test_bpf|all>
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
smoke|test_progs|test_bpf|all) ;;
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

classify_json_results()
{
	local experiment_dir error_dir empty_dir file relative_path
	local validation_file="${RESULTS_DIR}/json-validation.tsv"

	printf 'status\tfile\n' > "${validation_file}"

	for experiment_dir in \
		"${RESULTS_DIR}/test_progs" \
		"${RESULTS_DIR}/test_bpf"; do
		[ -d "${experiment_dir}" ] || continue

		error_dir="${experiment_dir}/error"
		empty_dir="${experiment_dir}/empty"
		mkdir -p "${error_dir}" "${empty_dir}"

		while IFS= read -r -d '' file; do
			relative_path="${file#"${RESULTS_DIR}/"}"
			printf 'incomplete\t%s\n' "${relative_path}" >> "${validation_file}"
			mv -- "${file}" "${error_dir}/"
			INVALID_JSON_COUNT=$((INVALID_JSON_COUNT + 1))
		done < <(find "${experiment_dir}" -maxdepth 1 -type f \
			-name '*.json.tmp' -print0)

		while IFS= read -r -d '' file; do
			relative_path="${file#"${RESULTS_DIR}/"}"
			if ! jq -e 'type == "array"' "${file}" >/dev/null 2>&1; then
				printf 'invalid\t%s\n' "${relative_path}" >> "${validation_file}"
				mv -- "${file}" "${error_dir}/"
				INVALID_JSON_COUNT=$((INVALID_JSON_COUNT + 1))
			elif jq -e 'length == 0' "${file}" >/dev/null; then
				printf 'empty\t%s\n' "${relative_path}" >> "${validation_file}"
				mv -- "${file}" "${empty_dir}/"
				EMPTY_JSON_COUNT=$((EMPTY_JSON_COUNT + 1))
			else
				printf 'valid\t%s\n' "${relative_path}" >> "${validation_file}"
				VALID_JSON_COUNT=$((VALID_JSON_COUNT + 1))
			fi
		done < <(find "${experiment_dir}" -maxdepth 1 -type f \
			-name '*.json' -print0)
	done
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

classify_json_results

if [ "${INVALID_JSON_COUNT}" -gt 0 ]; then
	echo "Error: ${INVALID_JSON_COUNT} invalid or incomplete JSON file(s)." >&2
	if [ "${status}" -eq 0 ]; then
		status=1
	fi
fi
if [ "${VALID_JSON_COUNT}" -eq 0 ]; then
	echo "Error: no valid non-empty JSON trace was generated." >&2
	if [ "${status}" -eq 0 ]; then
		status=1
	fi
fi

echo "JSON valid (non-empty): ${VALID_JSON_COUNT}"
echo "JSON empty:             ${EMPTY_JSON_COUNT}"
echo "JSON invalid/incomplete:${INVALID_JSON_COUNT}"
echo "Validation manifest:    ${RESULTS_DIR}/json-validation.tsv"
echo "Exit status: ${status}"
echo "Results: ${RESULTS_DIR}"

exit "${status}"
