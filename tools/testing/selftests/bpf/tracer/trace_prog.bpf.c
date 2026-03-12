#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "trace_common.h"

/* 定义一个 32MB 的超大 Ring Buffer，防止高频事件丢失 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 32 * 1024 * 1024);
} rb SEC(".maps");

SEC("fentry/bpf_interp_hook_start")
int BPF_PROG(on_start, u64 run_id, u32 prog_id)
{
	struct evt_prog_start *evt;
	
	evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
	if (!evt) return 0; // 内存不足则丢弃

	evt->hdr.run_id = run_id;
	evt->hdr.type = EVT_PROG_START;
	evt->prog_id = prog_id;
	
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("fentry/bpf_interp_hook_step")
int BPF_PROG(on_step, u64 run_id, const u64 *regs)
{
	struct evt_trace_step *evt;

	evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
	if (!evt) return 0;

	evt->hdr.run_id = run_id;
	evt->hdr.type = EVT_TRACE_STEP;
	/* 安全地从内核解释器栈上读取寄存器数组 */
	bpf_probe_read_kernel(evt->regs, sizeof(evt->regs), regs);
	
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("fentry/bpf_interp_hook_end")
int BPF_PROG(on_end, u64 run_id, u64 ret)
{
	struct evt_prog_end *evt;

	evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
	if (!evt) return 0;

	evt->hdr.run_id = run_id;
	evt->hdr.type = EVT_PROG_END;
	evt->ret_val = ret;
	
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";