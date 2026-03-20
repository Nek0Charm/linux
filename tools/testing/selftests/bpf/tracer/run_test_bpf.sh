#!/bin/bash

# --- Configuration ---
OUT_DIR="bpf_trace/test_bpf"
MODULE_NAME="test_bpf"
TEST_MODULE="../../../../../lib/test_bpf.ko"
TRACE_USER="./trace_user"

# --- 你的多行黑名单配置 (完全支持) ---
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

# 第一层循环：取出数组里的每一行
for group in "${BLACKLIST_RULES[@]}"; do
    # 第二层循环：将每一行按空格拆分成单个元素 (重点在这里：不加引号的 $group)
    for item in $group; do
        if [[ "$item" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            # 处理范围格式 (例如 367-450)
            start=${BASH_REMATCH[1]}
            end=${BASH_REMATCH[2]}
            for ((i=start; i<=end; i++)); do
                BLACKLIST_MAP[$i]=1
            done
        elif [[ "$item" =~ ^[0-9]+$ ]]; then
            # 处理单个数字格式 (例如 43)
            BLACKLIST_MAP[$item]=1
        fi
    done
done

# 检查函数保持不变
is_blacklisted() {
    [[ -n "${BLACKLIST_MAP[$1]}" ]]
}

# 1. Root Check
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root (or use sudo) to disable BPF JIT."
    exit 1
fi

# 2. Environment Setup
echo "Disabling BPF JIT for consistent tracing..."
echo 0 | tee /proc/sys/net/core/bpf_jit_enable > /dev/null

# 3. Validation
if [ ! -f "$TEST_MODULE" ]; then # 修正：这里用 -f 检查文件更好
    echo "Error: $TEST_MODULE not found."
    exit 1
fi
if [ ! -x "$TRACE_USER" ]; then
    echo "Error: $TRACE_USER not found or not executable."
    exit 1
fi

mkdir -p "$OUT_DIR"

START_ID=0
END_ID=1052   
BATCH_SIZE=10 

echo "Starting automated tracing (Batch size: $BATCH_SIZE, IDs: $START_ID to $END_ID)..."

if lsmod | grep -q "^${MODULE_NAME} "; then
    echo "[!] Detected residual ${MODULE_NAME} module. Cleaning up..."
    rmmod "$MODULE_NAME"
fi

# 外层循环：按批次步进
for (( batch_start=$START_ID; batch_start<=$END_ID; batch_start+=$BATCH_SIZE )); do
    
    batch_end=$(( batch_start + BATCH_SIZE - 1 ))
    if (( batch_end > END_ID )); then
        batch_end=$END_ID
    fi

    JSON_FILE="${OUT_DIR}/test_bpf_${batch_start}_to_${batch_end}.json"
    
    echo "=================================================="
    echo "Tracing batch: test_id $batch_start to $batch_end -> $JSON_FILE"
    
    ./trace_user "$JSON_FILE" &
    TRACE_PID=$!
    
    sleep 0.5
    
    # 内层循环
    for (( id=$batch_start; id<=$batch_end; id++ )); do
        if is_blacklisted "$id"; then
            echo "  [-] Skipping test_id=$id (Blacklisted)"
            continue
        fi

        echo "  [+] Running test_id=$id..."
        
        rmmod "$MODULE_NAME" 2>/dev/null || true
        insmod "$TEST_MODULE" test_id=$id
        
        sleep 0.2
        rmmod "$MODULE_NAME" 2>/dev/null || true
    done
    
    echo "  [*] Stopping tracer for batch ${batch_start}-${batch_end}..."
    kill -SIGINT $TRACE_PID
    wait $TRACE_PID 2>/dev/null
    
    echo "  [v] Done with batch ${batch_start}-${batch_end}"
done

echo "--------------------------------------------------"
echo "Done! All traces are perfectly saved in ./$OUT_DIR/"

mkdir -p "$OUT_DIR/empty"
mkdir -p "$OUT_DIR/error"

for f in "$OUT_DIR"/*.json; do
    [ -e "$f" ] || continue # 修正：处理文件不存在的情况

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