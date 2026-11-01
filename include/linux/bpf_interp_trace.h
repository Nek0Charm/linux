/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BPF_INTERP_TRACE_H
#define _LINUX_BPF_INTERP_TRACE_H

/* Private interpreter/observer ABI. Rebuild kernel and observer together. */
#define TRACE_MAX_INSNS 2048
#define TRACE_MAX_REGIONS 256
#define TRACE_MAX_CODES 64
#define TRACE_MAX_CALLS 1024
#define TRACE_MAX_SNAPSHOTS 4096
#define TRACE_CHUNK_SIZE 256
#define TRACE_CALL_BYTES 4096
#define TRACE_RUN_BYTES (1024 * 1024)
#define TRACE_MAX_FRAMES 8
#define TRACE_MAX_MAPS 32
#define TRACE_MAP 12
#define TRACE_INITIAL_MEMORY 2
#define TRACE_READ 1
#define TRACE_WRITE 2
#define TRACE_UNSUPPORTED_MAP 12
#define TRACE_UNSUPPORTED_ALIAS 13
#define TRACE_UNSUPPORTED_CONCURRENCY 14

#define TRACE_START 1
#define TRACE_CODE 2
#define TRACE_REGION 3
#define TRACE_REGION_END 4
#define TRACE_HELPER_PRE 5
#define TRACE_HELPER_POST 6
#define TRACE_MEMORY 7
#define TRACE_STEP 8
#define TRACE_END 9
#define TRACE_REASON 10
#define TRACE_TAILCALL 11

#define TRACE_STACK 1
#define TRACE_MAP_FD 2
#define TRACE_MAP_VALUE 3
#define TRACE_GLOBAL_DATA 4
#define TRACE_CTX 5
#define TRACE_KERNEL_SOURCE 6

#define TRACE_COMPLETE 0
#define TRACE_UNSUPPORTED 1
#define TRACE_INCOMPLETE 2

/* One definition for producer and consumer; never silently drop a run. */
#define TRACE_DROP_UNSUPPORTED_TAIL_TARGET 1
#define TRACE_DROP_CTX_INDIRECTION 2
#define TRACE_DROP_HELPER_MEMORY_SIDE_EFFECT 3
#define TRACE_DROP_CTX_INTERNAL_STATE 4
#define TRACE_DROP_MAP_VALUE_ACCESS 5
#define TRACE_UNKNOWN_HELPER 6
#define TRACE_BUDGET 7
#define TRACE_UNKNOWN_REGION 8
#define TRACE_CODE_IDENTITY 9
#define TRACE_CALLBACK 10
#define TRACE_ALLOCATION 11

#ifndef __VMLINUX_H__
struct trace_hdr {
	__u64 run_id;
	__u64 seq;
	__u32 type;
	__s32 read_error;
};

struct trace_region {
	__u64 base_addr;
	__u64 size;
	__u32 region_id;
	__u32 type;
	__u32 frame_id;
	__u32 parent_frame_id;
	__u32 map_id, element_index, entry_id, permissions;
};

struct trace_map {
	__u64 address;
	__u32 map_id, kernel_map_id, map_region_id;
	__u32 map_type, key_size, value_size, max_entries, map_flags;
	__u32 value_stride, code_id, supported;
};

struct trace_map_effect {
	__u64 flags;
	__u32 map_id, key_snapshot_id, input_value_snapshot_id;
	__u32 state, entry_id, value_snapshot_id, return_region_id;
};

struct trace_helper {
	__u64 args[5];
	__u64 ret;
	__u64 trace_index;
	__u32 call_id;
	__u32 code_id;
	__u32 pc;
	__u32 helper_id;
	__u32 status;
	__u32 snapshots;
	struct trace_map_effect map_effect;
};

struct trace_memory {
	__u64 address;
	__u64 read_address;
	__u64 offset;
	__u32 snapshot_id;
	__u32 call_id;
	__u32 region_id;
	__u32 phase;
	__u32 length;
	__u32 chunk_index;
	__u32 chunk_offset;
	__u32 valid_length;
	__u32 expected_fault;
	__u32 map_id, code_id;
};

struct trace_code {
	__u64 time_ns;
	__u64 prog_ptr;
	__u64 ctx_ptr;
	__u64 map_ptr;
	__u32 code_id;
	__u32 from_code_id;
	__u32 pc;
	__u32 index;
	__u32 max_entries;
};

struct trace_summary {
	__u64 time_ns;
	__u64 events;
	__u64 steps;
	__u64 calls;
	__u64 snapshot_bytes;
	__u64 ret;
	__u32 regions;
	__u32 snapshots;
};

struct bpf_trace_event {
	struct trace_hdr hdr;
	union {
		struct trace_region region;
		struct trace_map map;
		struct trace_helper helper;
		struct trace_memory memory;
		struct trace_code code;
		struct trace_summary summary;
		struct {
			__u64 regs[12];
			__u64 index;
		} step;
		struct {
			__u32 reason;
			__u32 status;
		} diagnostic;
	};
};
#endif /* __VMLINUX_H__ */
#endif
