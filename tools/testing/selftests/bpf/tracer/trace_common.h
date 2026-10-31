/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __TRACE_COMMON_H
#define __TRACE_COMMON_H
#include "../../../../../include/linux/bpf_interp_trace.h"

struct helper_call_info {
	__u32 pc;
	__u32 helper_id;
};

/* Only code declarations need a large transport record. */
struct evt_code {
	struct bpf_trace_event event;
	__u32 prog_id;
	__u32 insn_cnt;
	__u32 helper_call_cnt;
	char prog_name[16];
	struct bpf_insn insns[TRACE_MAX_INSNS];
	struct helper_call_info helper_calls[TRACE_MAX_INSNS];
};

struct evt_memory {
	struct bpf_trace_event event;
	__u8 bytes[TRACE_CHUNK_SIZE];
};
#endif
