/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM bpf_interp

#if !defined(_TRACE_BPF_INTERP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_BPF_INTERP_H

#include <linux/tracepoint.h>
#include <linux/bpf_interp_trace.h>

TRACE_EVENT(bpf_interp,
	TP_PROTO(const struct bpf_trace_event *event),
	TP_ARGS(event),
	TP_STRUCT__entry(
		__field(u64, run_id)
		__field(u64, seq)
		__field(u32, type)
	),
	TP_fast_assign(
		__entry->run_id = event->hdr.run_id;
		__entry->seq = event->hdr.seq;
		__entry->type = event->hdr.type;
	),
	TP_printk("run=%llu seq=%llu type=%u", __entry->run_id,
		  __entry->seq, __entry->type)
);
#endif

#include <trace/define_trace.h>
