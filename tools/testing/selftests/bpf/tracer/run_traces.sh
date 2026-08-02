#!/bin/bash

set -uo pipefail

# --- Configuration ---
OUT_DIR="${TRACE_OUTPUT_DIR:-bpf_trace/test_progs}"
TEST_PROGS_BIN="${TEST_PROGS_BIN:-../test_progs}"
TRACE_USER="${TRACE_USER:-./trace_user}"
TRACE_PID=""
READY_FILE=""
OLD_JIT=""

# --- Blacklist ---
BLACKLIST_RULES=(
    "bpf_iter"                          # too many content
    "l4lb_all"                          # too many content
    "ns_xsk_drv"                        # too many content
    "ns_xsk_skb"                        # too many content
    "xdp"                               # too many content
    "xdp_perf"                          # too many content
    "flow_dissector_classification"     # kernel panic
    "flow_dissector_skb"                # kernel panic
    "stream_success"                    # kernel panic
    "verifier_iterating_callbacks"      # kernel panic
    "verifier_xdp_direct_packet_access" # load from ctx
    "vrf_socket_lookup"                 # load from ctx
    "xdp_adjust_frags"                  # load from ctx
    "kprobe_multi_bench_attach"         # too many, too weird
    "map_lock"                          # ring buffer overflow
    "signal_pending"                    # ring buffer overflow
    "core_retro" "perf_buffer"          # record map content
    "get_stack_raw_tp" "hash_large_key" # helper return not ptr + need to record more maps
    "lwt_reroute" "sk_assign"           # load from ctx
    "task_fd_query_rawtp"
    "time_tai"
    "res_spin_lock_stress"              # too slow
    "verifier_bounds"                   # kernel panic
    "core_reloc"                        # kernel panic
    "skb_helpers"                       # kernel panic
)
BLACKLIST=$(IFS='|'; echo "${BLACKLIST_RULES[*]}")

cleanup()
{
    if [ -n "${TRACE_PID}" ] && kill -0 "${TRACE_PID}" 2>/dev/null; then
        kill -SIGINT "${TRACE_PID}" 2>/dev/null || true
        wait "${TRACE_PID}" 2>/dev/null || true
    fi
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
if [ ! -x "$TEST_PROGS_BIN" ]; then
    echo "Error: $TEST_PROGS_BIN not found or not executable."
    exit 1
fi
if [ ! -x "$TRACE_USER" ]; then
    echo "Error: $TRACE_USER not found or not executable."
    exit 1
fi

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd -P)"

# 4. Advanced Argument Handling
START_FROM=""
SELECTED_ARGS="$@"

if [ "${1:-}" == "--from" ]; then
    if [ -z "${2:-}" ]; then
        echo "Error: --from requires a test name." >&2
        exit 2
    fi
    START_FROM="$2"
    # Remove the first two arguments (--from <test_name>)
    shift 2
    SELECTED_ARGS="$@"
    echo "Mode: Start execution from '$START_FROM' onwards."
fi

# 5. Fetch Test List
AVAILABLE_TESTS="$("$TEST_PROGS_BIN" -l)"
if [ -n "$SELECTED_ARGS" ]; then
    TESTS="$SELECTED_ARGS"
    echo "Running specified tests: $TESTS"
else
    echo "Fetching all tests from $TEST_PROGS_BIN..."
    TESTS="$(grep -vwE "$BLACKLIST" <<<"$AVAILABLE_TESTS")"
fi

# 6. Execution Loop
SHOULD_SKIP=false
GENERATED_JSON=0
if [ -n "$START_FROM" ]; then
    SHOULD_SKIP=true
fi

for test in $TESTS; do
    # Logic to handle starting from a specific test
    if [ "$SHOULD_SKIP" = true ]; then
        if [ "$test" == "$START_FROM" ]; then
            SHOULD_SKIP=false
        else
            continue
        fi
    fi

    # Validation: Check if the test exists
    if ! grep -Fxq "$test" <<<"$AVAILABLE_TESTS"; then
        echo "Warning: Test '$test' not found. Skipping..."
        continue
    fi

    echo "=================================================="
    echo "Tracing test: $test"
    
    JSON_OUT="${OUT_DIR}/${test}.json"
    
    # 1. Start tracer in background (stays in tracer dir to find trace_user)
    READY_FILE="/tmp/bpf-tracer-ready-$$"
    rm -f "${READY_FILE}"
    TRACE_READY_FILE="${READY_FILE}" "$TRACE_USER" "$JSON_OUT" &
    TRACE_PID=$!

    if ! wait_for_tracer; then
        echo "Error: $TRACE_USER did not become ready for $test. Skipping..."
        wait "${TRACE_PID}" 2>/dev/null || true
        TRACE_PID=""
        rm -f "${READY_FILE}"
        READY_FILE=""
        continue
    fi
    
    # 2. Run test_progs (Switch to parent directory to find BPF objects)
    # Using subshell ( ) to ensure we return to current dir automatically
    (
        cd ..
        ./test_progs -a "$test" -j4
    )

    # Ensure all traces are pushed into Ring Buffer
    # sleep 0.2
    
    # 3. Stop tracer and cleanup
    kill -SIGINT "${TRACE_PID}" 2>/dev/null || true
    wait "${TRACE_PID}" 2>/dev/null || true
    TRACE_PID=""
    rm -f "${READY_FILE}"
    READY_FILE=""

    if [ -s "${JSON_OUT}" ]; then
        GENERATED_JSON=$((GENERATED_JSON + 1))
    fi
done

echo "--------------------------------------------------"
if [ "${GENERATED_JSON}" -eq 0 ]; then
    echo "Error: no JSON trace was generated in ${OUT_DIR}." >&2
    exit 1
fi
echo "Done! Generated ${GENERATED_JSON} raw JSON trace file(s) in ${OUT_DIR}/ for host validation."
