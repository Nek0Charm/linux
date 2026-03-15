#!/bin/bash

# --- Configuration ---
# Script location: ./tools/testing/selftests/bpf/tracer/
OUT_DIR="bpf_trace"
TEST_PROGS_BIN="../test_progs"
TRACE_USER="./trace_user"
BLACKLIST="flow_dissector_classification|verifier_iterating_callbacks"

# 1. Validation: Check if necessary files exist
if [ ! -x "$TEST_PROGS_BIN" ]; then
    echo "Error: $TEST_PROGS_BIN not found or not executable."
    exit 1
fi

if [ ! -x "$TRACE_USER" ]; then
    echo "Error: $TRACE_USER not found or not executable."
    exit 1
fi

mkdir -p "$OUT_DIR"

# 2. Argument Handling & List Fetching
if [ $# -gt 0 ]; then
    TESTS="$@"
    echo "Running specified tests: $TESTS"
else
    echo "Fetching test list from $TEST_PROGS_BIN..."
    TESTS=$($TEST_PROGS_BIN -l | grep -vE "$BLACKLIST")
fi

# 3. Execution Loop
for test in $TESTS; do
    # Validation: Check if the test exists (running from tracer dir)
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
        ./test_progs -t "$test" -j1
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