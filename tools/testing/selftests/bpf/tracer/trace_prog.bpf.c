// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "trace_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 32 * 1024 * 1024);
} rb SEC(".maps");

/* Kernel sequences count attempts before invoking this hook. A failed ring
 * reservation or metadata read leaves a gap, checked against RUN_END even if
 * the last STEP, POST, or chunk was lost. No per-CPU pending state or scratch.
 */
SEC("raw_tp/bpf_interp")
int on_event(struct bpf_raw_tracepoint_args *ctx)
{
	const struct bpf_trace_event *source = (const void *)ctx->args[0];
	struct trace_hdr hdr;

	if (bpf_probe_read_kernel(&hdr, sizeof(hdr), &source->hdr))
		return 0;
	if (hdr.type == TRACE_START || hdr.type == TRACE_CODE) {
		struct evt_code *out = bpf_ringbuf_reserve(&rb, sizeof(*out), 0);
		const struct bpf_prog *prog;
		struct bpf_prog_aux *aux = NULL;
		struct bpf_interp_helper_call *calls = NULL;
		u32 count = 0;
		int err;

		if (!out)
			return 0;
		out->prog_id = 0;
		out->insn_cnt = 0;
		out->helper_call_cnt = 0;
		__builtin_memset(out->prog_name, 0, sizeof(out->prog_name));
		err = bpf_probe_read_kernel(&out->event, sizeof(out->event), source);
		prog = (const void *)out->event.code.prog_ptr;
		err |= bpf_probe_read_kernel(&out->insn_cnt, sizeof(out->insn_cnt), &prog->len);
		err |= bpf_probe_read_kernel(&aux, sizeof(aux), &prog->aux);
		if (aux) {
			err |= bpf_probe_read_kernel(&out->prog_id, sizeof(out->prog_id), &aux->id);
			err |= bpf_probe_read_kernel(out->prog_name, sizeof(out->prog_name), aux->name);
			err |= bpf_probe_read_kernel(&count, sizeof(count), &aux->interp_helper_call_cnt);
			err |= bpf_probe_read_kernel(&calls, sizeof(calls), &aux->interp_helper_calls);
		}
		if (out->insn_cnt > TRACE_MAX_INSNS || count > TRACE_MAX_INSNS) {
			err = -7;
		} else {
			u32 len = out->insn_cnt;

			if (len && len <= TRACE_MAX_INSNS)
				err |= bpf_probe_read_kernel(out->insns, len * sizeof(struct bpf_insn), prog->insnsi);
			if (count && count <= TRACE_MAX_INSNS)
				err |= bpf_probe_read_kernel(out->helper_calls, count * sizeof(*calls), calls);
			out->helper_call_cnt = count;
		}
		out->event.hdr = hdr;
		out->event.hdr.read_error = err;
		bpf_ringbuf_submit(out, 0);
	} else if (hdr.type == TRACE_MEMORY) {
		struct evt_memory *out = bpf_ringbuf_reserve(&rb, sizeof(*out), 0);
		u32 len;
		int err;

		if (!out)
			return 0;
		__builtin_memset(out, 0, sizeof(*out));
		err = bpf_probe_read_kernel(&out->event, sizeof(out->event), source);
		len = out->event.memory.valid_length;
		if (!err && len && len <= TRACE_CHUNK_SIZE)
			err = bpf_probe_read_kernel(out->bytes, len,
				(const void *)(out->event.memory.read_address + out->event.memory.chunk_offset));
		else if (len > TRACE_CHUNK_SIZE)
			err = -7;
		out->event.hdr = hdr;
		out->event.hdr.read_error = err;
		bpf_ringbuf_submit(out, 0);
	} else {
		struct bpf_trace_event *out = bpf_ringbuf_reserve(&rb, sizeof(*out), 0);

		if (!out)
			return 0;
		if (bpf_probe_read_kernel(out, sizeof(*out), source)) {
			bpf_ringbuf_discard(out, 0);
			return 0;
		}
		bpf_ringbuf_submit(out, 0);
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
