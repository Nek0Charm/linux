#ifndef __TRACE_COMMON_H
#define __TRACE_COMMON_H

#define MAX_INSN_DUMP 2048 // 最多抓取 2048 条原始指令 (16KB)
#define MAX_MEM_BLOCKS 16 // 假设最多 8 个 map，每个 map 产生 fd 和 value 两个块

struct mem_block_info {
	__u64 base_addr;
	__u32 size;
	__u32 is_direct_value;
};

/* 事件类型枚举 */
enum trace_evt_type {
	EVT_PROG_START = 1,
	EVT_TRACE_STEP = 2,
	EVT_PROG_END   = 3,
	EVT_PROG_CALL  = 4, // 新增内部调用事件
	EVT_PROG_TAILCALL = 5,
	EVT_PROG_TAILCALL_MAP = 6,
};

/* 基础事件头 */
struct trace_hdr {
	__u64 run_id;
	enum trace_evt_type type;
};

/* START 事件：只传核心 ID，拒绝内核字符串操作 */
struct evt_prog_start {
	struct trace_hdr hdr;
	__u32 prog_id;
	__u32 insn_cnt;
	__u64 ctx_ptr;      // 主程序入口的 R1
	__u64 sp;           // 主程序的 R10
	char prog_name[16];
	__u32 block_cnt;
	struct mem_block_info blocks[MAX_MEM_BLOCKS];
	struct bpf_insn insns[MAX_INSN_DUMP];
};

/* STEP 事件：寄存器快照 */
struct evt_trace_step {
	struct trace_hdr hdr;
	__u64 regs[12]; // BPF_R0 ~ BPF_R10 + BPF_RAX
};

/* END 事件：执行结束 */
struct evt_prog_end {
	struct trace_hdr hdr;
	__u64 ret_val;
};

struct evt_prog_call {
	struct trace_hdr hdr;
	__u64 sp;           // 内部调用的 R10
};

struct evt_prog_tailcall {
	struct trace_hdr hdr;
	__u32 pc;            // 发生跳转的 PC
	__u32 index;         // 尾调用传入的索引 (R3)
	__u64 map_ptr;       // 尾调用传入的 Map 指针 (R2)
	__u64 prog_ptr;      // 目标程序的内存地址
	__u32 insn_cnt;
	struct bpf_insn insns[MAX_INSN_DUMP];
};

struct evt_prog_tailcall_map {
	struct trace_hdr hdr;
	__u64 map_ptr;       // 尾调用传入的 Map 指针 (R2)
	__u32 max_entries;
};

#endif /* __TRACE_COMMON_H */