#!/bin/bash

# --- Configuration ---
OUT_DIR="bpf_trace/test_progs"
TEST_PROGS_BIN="../test_progs"
TRACE_USER="./trace_user"

# --- Blacklist ---
BLACKLIST_RULES=(
    "bpf_iter"                          # too many content
    "l4lb_all"                          # too many content
    "flow_dissector_classification"     # kernel panic
    "flow_dissector_skb"                # kernel panic
    "stream_success"                    # kernel panic
    "verifier_iterating_callbacks"      # kernel panic
)
BLACKLIST=$(IFS='|'; echo "${BLACKLIST_RULES[*]}")

# 1. Root Check
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root (or use sudo) to disable BPF JIT."
    exit 1
fi

# 2. Environment Setup
echo "Disabling BPF JIT for consistent tracing..."
echo 0 | tee /proc/sys/net/core/bpf_jit_enable > /dev/null

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

# 4. Advanced Argument Handling
START_FROM=""
SELECTED_ARGS="$@"

if [ "$1" == "--from" ]; then
    START_FROM="$2"
    # Remove the first two arguments (--from <test_name>)
    shift 2
    SELECTED_ARGS="$@"
    echo "Mode: Start execution from '$START_FROM' onwards."
fi

# 5. Fetch Test List
if [ -n "$SELECTED_ARGS" ]; then
    TESTS="$SELECTED_ARGS"
    echo "Running specified tests: $TESTS"
else
    echo "Fetching all tests from $TEST_PROGS_BIN..."
    TESTS=$($TEST_PROGS_BIN -l | grep -vE "$BLACKLIST")
fi

# 6. Execution Loop
SHOULD_SKIP=false
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
    if ! $TEST_PROGS_BIN -l | grep -qw "$test"; then
        echo "Warning: Test '$test' not found. Skipping..."
        continue
    fi

    echo "=================================================="
    echo "Tracing test: $test"
    
    # Get absolute path for the JSON output to avoid issues after cd
    JSON_OUT="$(pwd)/${OUT_DIR}/${test}.json"
    
    # 1. Start tracer in background (stays in tracer dir to find trace_user)
    $TRACE_USER "$JSON_OUT" &
    TRACE_PID=$!
    
    # Give tracer 0.5s to load BPF skeleton
    sleep 0.5
    
    if ! kill -0 $TRACE_PID 2>/dev/null; then
        echo "Error: Failed to start $TRACE_USER for $test. Skipping..."
        continue
    fi
    
    # 2. Run test_progs (Switch to parent directory to find BPF objects)
    # Using subshell ( ) to ensure we return to current dir automatically
    (
        cd ..
        ./test_progs -t "$test" -j4
    )

    # Ensure all traces are pushed into Ring Buffer
    sleep 0.2
    
    # 3. Stop tracer and cleanup
    kill -SIGINT $TRACE_PID
    
    # Wait for tracer to exit
    wait $TRACE_PID 2>/dev/null
done

echo "--------------------------------------------------"
echo "Done! All traces are perfectly saved in ./$OUT_DIR/"

mkdir -p "$OUT_DIR/empty"
mkdir -p "$OUT_DIR/error"

for f in "$OUT_DIR"/*.json; do
    [ -d "$f" ] && continue

    if ! jq . "$f" >/dev/null 2>&1; then
        echo "Corrupted json file: $f"
        mv "$f" "$OUT_DIR/error/"
        continue
    fi

    if [ "$(jq 'length' "$f")" -eq 0 ]; then
        echo "Empty json file: $f"
        mv "$f" "$OUT_DIR/empty/"
    fi
done