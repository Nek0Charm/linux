#!/bin/bash

set -uo pipefail

# --- Configuration ---
OUT_DIR="${TRACE_OUTPUT_DIR:-bpf_trace/test_bpf}"
MODULE_NAME="test_bpf"
TEST_MODULE="${TEST_BPF_MODULE:-../../../../../lib/test_bpf.ko}"
TRACE_USER="${TRACE_USER:-./trace_user}"
TRACE_PID=""
READY_FILE=""
OLD_JIT=""

# --- Multiline blacklist configuration (fully supported) ---
BLACKLIST_RULES=(
    "43"                                # BPF_SUB, R0, R0
    "324 329 330 335 336 341 342"       # store
    "367-450 729-748 758-762 892-931"   # atomic
    "851-891 932-979"                   # pc oob
    "980-984 988 989 993 994"           # some reason
    "1000-1052"                         # pc oob
)

declare -A BLACKLIST_MAP
echo "Initializing blacklist..."

# Outer loop: read each line from the array
for group in "${BLACKLIST_RULES[@]}"; do
    # Inner loop: split each line into space-delimited items (intentionally leave $group unquoted)
    for item in $group; do
        if [[ "$item" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            # Handle a range such as 367-450
            start=${BASH_REMATCH[1]}
            end=${BASH_REMATCH[2]}
            for ((i=start; i<=end; i++)); do
                BLACKLIST_MAP[$i]=1
            done
        elif [[ "$item" =~ ^[0-9]+$ ]]; then
            # Handle a single number such as 43
            BLACKLIST_MAP[$item]=1
        fi
    done
done

# The lookup function remains unchanged
is_blacklisted() {
    [[ -n "${BLACKLIST_MAP[$1]:-}" ]]
}

cleanup()
{
    if [ -n "${TRACE_PID}" ] && kill -0 "${TRACE_PID}" 2>/dev/null; then
        kill -SIGINT "${TRACE_PID}" 2>/dev/null || true
        wait "${TRACE_PID}" 2>/dev/null || true
    fi
    rmmod "${MODULE_NAME}" 2>/dev/null || true
    if [ -n "${READY_FILE}" ]; then
        rm -f "${READY_FILE}"
    fi
    if [ -n "${OLD_JIT}" ]; then
        echo "${OLD_JIT}" > /proc/sys/net/core/bpf_jit_enable 2>/dev/null || true
    fi
}

wait_for_tracer()
{
    for ((attempt = 0; attempt < 100; attempt++)); do
        [ -f "${READY_FILE}" ] && return 0
        kill -0 "${TRACE_PID}" 2>/dev/null || return 1
        sleep 0.05
    done
    return 1
}

trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

# 1. Root Check
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root (or use sudo) to disable BPF JIT."
    exit 1
fi

# 2. Environment Setup
echo "Disabling BPF JIT for consistent tracing..."
OLD_JIT="$(cat /proc/sys/net/core/bpf_jit_enable)"
echo 0 > /proc/sys/net/core/bpf_jit_enable

# 3. Validation
if [ ! -f "$TEST_MODULE" ]; then # Use -f here to verify that this is a file
    echo "Error: $TEST_MODULE not found."
    exit 1
fi
if [ ! -x "$TRACE_USER" ]; then
    echo "Error: $TRACE_USER not found or not executable."
    exit 1
fi

mkdir -p "$OUT_DIR"

START_ID="${TEST_BPF_START_ID:-0}"
END_ID="${TEST_BPF_END_ID:-1052}"
BATCH_SIZE="${TEST_BPF_BATCH_SIZE:-10}"

echo "Starting automated tracing (Batch size: $BATCH_SIZE, IDs: $START_ID to $END_ID)..."

if lsmod | grep -q "^${MODULE_NAME} "; then
    echo "[!] Detected residual ${MODULE_NAME} module. Cleaning up..."
    rmmod "$MODULE_NAME"
fi

# Outer loop: advance one batch at a time
for (( batch_start=$START_ID; batch_start<=$END_ID; batch_start+=$BATCH_SIZE )); do
    
    batch_end=$(( batch_start + BATCH_SIZE - 1 ))
    if (( batch_end > END_ID )); then
        batch_end=$END_ID
    fi

    JSON_FILE="${OUT_DIR}/test_bpf_${batch_start}_to_${batch_end}.json"
    
    echo "=================================================="
    echo "Tracing batch: test_id $batch_start to $batch_end -> $JSON_FILE"
    
    READY_FILE="/tmp/bpf-tracer-ready-$$"
    rm -f "${READY_FILE}"
    TRACE_READY_FILE="${READY_FILE}" "${TRACE_USER}" "$JSON_FILE" &
    TRACE_PID=$!

    if ! wait_for_tracer; then
        echo "Error: ${TRACE_USER} did not become ready for batch ${batch_start}-${batch_end}."
        wait "${TRACE_PID}" 2>/dev/null || true
        TRACE_PID=""
        rm -f "${READY_FILE}"
        READY_FILE=""
        continue
    fi
    
    # Inner loop
    for (( id=$batch_start; id<=$batch_end; id++ )); do
        if is_blacklisted "$id"; then
            echo "  [-] Skipping test_id=$id (Blacklisted)"
            continue
        fi

        echo "  [+] Running test_id=$id..."
        
        rmmod "$MODULE_NAME" 2>/dev/null || true
        if ! insmod "$TEST_MODULE" test_id=$id; then
            echo "  [!] test_id=$id failed to load"
            continue
        fi
        
        sleep 0.2
        rmmod "$MODULE_NAME" 2>/dev/null || true
    done
    
    echo "  [*] Stopping tracer for batch ${batch_start}-${batch_end}..."
    kill -SIGINT "${TRACE_PID}" 2>/dev/null || true
    wait "${TRACE_PID}" 2>/dev/null || true
    TRACE_PID=""
    rm -f "${READY_FILE}"
    READY_FILE=""
    
    echo "  [v] Done with batch ${batch_start}-${batch_end}"
done

echo "--------------------------------------------------"
echo "Done! Raw trace files are saved in ${OUT_DIR}/ for host validation."
