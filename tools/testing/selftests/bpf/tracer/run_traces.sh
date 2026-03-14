#!/bin/bash

OUT_DIR="bpf_trace"
mkdir -p "$OUT_DIR"

echo "Fetching test list from test_progs..."
# 利用 -l 参数列出所有测试，过滤掉标题行，只保留纯净的测试名
TESTS=$(./test_progs -l | grep -v 'test_progs' | tr -d ' ')

for test in $TESTS; do
    echo "=================================================="
    echo "Tracing test: $test"
    
    # 1. 在后台启动追踪器，指定这个测试专属的 json 文件名
    ./trace_user "${OUT_DIR}/${test}.json" &
    TRACE_PID=$!
    
    # 给追踪器 0.5 秒时间加载 BPF skeleton 和挂载 Hook
    sleep 0.5
    
    # 2. 运行单个测试，必须加上 -j1 强制单线程运行，防止并发污染
    ./test_progs -t "$test" -j1

    # 【核心修复】：给内核一点喘息的时间，确保所有 trace 已经推入 Ring Buffer
    sleep 0.2
    
    # 3. 测试跑完，发送 SIGINT 信号给追踪器，触发 cleanup 闭合 JSON
    kill -SIGINT $TRACE_PID
    
    # 等待追踪器彻底落盘并退出
    wait $TRACE_PID 2>/dev/null
done

echo "Done! All traces are perfectly saved in ./$OUT_DIR/"