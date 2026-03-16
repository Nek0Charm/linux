#!/bin/bash

# --- Configuration ---
OUT_DIR="bpf_trace/test_bpf"
MODULE_NAME="test_bpf"
TEST_MODULE="../../../../../lib/test_bpf.ko"
TRACE_USER="./trace_user"

# 1. Root Check
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root (or use sudo) to disable BPF JIT."
    exit 1
fi

# 2. Environment Setup
echo "Disabling BPF JIT for consistent tracing..."
echo 0 | tee /proc/sys/net/core/bpf_jit_enable > /dev/null

# 3. Validation
if [ ! "$TEST_MODULE" ]; then
    echo "Error: $TEST_MODULE not found."
    exit 1
fi
if [ ! -x "$TRACE_USER" ]; then
    echo "Error: $TRACE_USER not found or not executable."
    exit 1
fi

mkdir -p "$OUT_DIR"

START_ID=0
END_ID=1052   # 这里可以设置你想跑的总范围，比如 0 到 99
BATCH_SIZE=10 # 每 10 个测试存为一个 JSON 文件

echo "Starting automated tracing (Batch size: $BATCH_SIZE, IDs: $START_ID to $END_ID)..."
echo "Starting automated tracing for test_bpf (IDs: $START_ID to $END_ID)..."

if lsmod | grep -q "^${MODULE_NAME} "; then
    echo "[!] Detected residual ${MODULE_NAME} module. Cleaning up..."
    rmmod "$MODULE_NAME"
fi

# 外层循环：按批次步进 (0, 10, 20...)
for (( batch_start=$START_ID; batch_start<=$END_ID; batch_start+=$BATCH_SIZE )); do
    
    # 计算当前批次的结束 ID
    batch_end=$(( batch_start + BATCH_SIZE - 1 ))
    if (( batch_end > END_ID )); then
        batch_end=$END_ID
    fi

    JSON_FILE="${OUT_DIR}/test_bpf_${batch_start}_to_${batch_end}.json"
    
    echo "=================================================="
    echo "Tracing batch: test_id $batch_start to $batch_end -> $JSON_FILE"
    
    # 1. 启动这 10 个测试专属的追踪器进程
    ./trace_user "$JSON_FILE" &
    TRACE_PID=$!
    
    # 给追踪器初始化时间
    sleep 0.5
    
    # 内层循环：密集跑完这 10 个 test_id
    for (( id=$batch_start; id<=$batch_end; id++ )); do
        echo "  [+] Running test_id=$id..."
        
        # 极端防卫清理
        rmmod "$MODULE_NAME" 2>/dev/null || true
        
        # 加载执行
        insmod "$TEST_MODULE" test_id=$id
        
        # 等待事件推入 Ring Buffer
        sleep 0.2
        
        # 执行完毕，立刻卸载
        rmmod "$MODULE_NAME" 2>/dev/null || true
    done
    
    # 2. 这 10 个测试全跑完了，发送信号让追踪器闭合 JSON 数组并退出
    echo "  [*] Stopping tracer for batch ${batch_start}-${batch_end}..."
    kill -SIGINT $TRACE_PID
    wait $TRACE_PID 2>/dev/null
    
    echo "  [v] Done with batch ${batch_start}-${batch_end}"
done

echo "--------------------------------------------------"
echo "Done! All traces are perfectly saved in ./$OUT_DIR/"

mkdir -p "$OUT_DIR/empty"

for f in ./$OUT_DIR/*.json; do
    if [ "$(jq 'length' "$f")" -eq 0 ]; then
        mv "$f" "$OUT_DIR/empty"
    fi
done