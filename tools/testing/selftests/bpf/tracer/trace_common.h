#ifndef __TRACE_COMMON_H
#define __TRACE_COMMON_H

/* 事件类型枚举 */
enum trace_evt_type {
	EVT_PROG_START = 1,
	EVT_TRACE_STEP = 2,
	EVT_PROG_END   = 3,
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
};

/* STEP 事件：寄存器快照 */
struct evt_trace_step {
	struct trace_hdr hdr;
	__u64 regs[11]; // BPF_R0 到 BPF_R10
};

/* END 事件：执行结束 */
struct evt_prog_end {
	struct trace_hdr hdr;
	__u64 ret_val;
};

#endif /* __TRACE_COMMON_H */