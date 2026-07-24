#ifndef __TRACE_COMMON_H
#define __TRACE_COMMON_H

#define MAX_INSN_DUMP 2048 // Capture at most 2,048 raw instructions (16 KB)
#define MAX_MEM_BLOCKS 16 // Assume at most 8 maps, each producing an fd block and a value block

struct mem_block_info {
	__u64 base_addr;
	__u32 size;
	__u32 is_direct_value;
};

/* Event types. */
enum trace_evt_type {
	EVT_PROG_START = 1,
	EVT_TRACE_STEP = 2,
	EVT_PROG_END   = 3,
	EVT_PROG_CALL  = 4, // Internal call event
	EVT_PROG_TAILCALL = 5,
	EVT_PROG_TAILCALL_MAP = 6,
	EVT_PROG_DROP = 7,
};

enum trace_drop_reason {
	TRACE_DROP_UNSUPPORTED_TAIL_TARGET = 1,
	TRACE_DROP_TAIL_COUNT_DIVERGENCE = 2,
	TRACE_DROP_CTX_INDIRECTION = 3,
	TRACE_DROP_HELPER_MEMORY_SIDE_EFFECT = 4,
	TRACE_DROP_CTX_INTERNAL_STATE = 5,
	TRACE_DROP_TAIL_INDEX_TRUNCATION = 6,
	TRACE_DROP_MAP_VALUE_ACCESS = 7,
};

/* Common event header. */
struct trace_hdr {
	__u64 run_id;
	enum trace_evt_type type;
};

/* START event: pass only core IDs and avoid kernel string operations. */
struct evt_prog_start {
	struct trace_hdr hdr;
	__u32 prog_id;
	__u32 insn_cnt;
	__u64 ctx_ptr;      // R1 at main program entry
	__u64 sp;           // R10 of the main program
	char prog_name[16];
	__u32 block_cnt;
	struct mem_block_info blocks[MAX_MEM_BLOCKS];
	struct bpf_insn insns[MAX_INSN_DUMP];
};

/* STEP event: register snapshot. */
struct evt_trace_step {
	struct trace_hdr hdr;
	__u64 regs[12]; // BPF_R0 ~ BPF_R10 + BPF_RAX
};

/* END event: execution completed. */
struct evt_prog_end {
	struct trace_hdr hdr;
	__u64 ret_val;
};

struct evt_prog_call {
	struct trace_hdr hdr;
	__u64 sp;           // R10 of the internal call
};

struct evt_prog_tailcall {
	struct trace_hdr hdr;
	__u32 pc;            // PC where the jump occurred
	__u32 index;         // Index passed to the tail call (R3)
	__u64 map_ptr;       // Map pointer passed to the tail call (R2)
	__u64 prog_ptr;      // Address of the target program
	__u32 insn_cnt;
	struct bpf_insn insns[MAX_INSN_DUMP];
};

struct evt_prog_tailcall_map {
	struct trace_hdr hdr;
	__u64 map_ptr;       // Map pointer passed to the tail call (R2)
	__u32 max_entries;
};

struct evt_prog_drop {
	struct trace_hdr hdr;
	__u32 reason;
};

#endif /* __TRACE_COMMON_H */
