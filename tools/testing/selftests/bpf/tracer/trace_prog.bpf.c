#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "trace_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 32 * 1024 * 1024);
} rb SEC(".maps");

SEC("fentry/bpf_interp_hook_start")
int BPF_PROG(on_start, u64 run_id, const struct bpf_prog *prog, u64 ctx_ptr, u64 fp)
{
	if (!prog) return 0;

	struct evt_prog_start *evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
	if (!evt) return 0;

	evt->hdr.run_id = run_id;
	evt->hdr.type = EVT_PROG_START;
	evt->ctx_ptr = ctx_ptr;
	evt->sp = fp;
	
	/* 1. 安全读取 prog->aux 指针 */
	struct bpf_prog_aux *aux = NULL;
	bpf_probe_read_kernel(&aux, sizeof(aux), &prog->aux);

	/* 2. 读取 id 和 name */
	if (aux) {
		bpf_probe_read_kernel(&evt->prog_id, sizeof(evt->prog_id), &aux->id);
		/* bpf_probe_read_kernel_str 会自动处理字符串和 \0 结尾 */
		bpf_probe_read_kernel_str(evt->prog_name, sizeof(evt->prog_name), aux->name);
	} else {
		evt->prog_id = 0;
		evt->prog_name[0] = '\0';
	}

	/* 3. 读取指令数量 prog->len */
	bpf_probe_read_kernel(&evt->insn_cnt, sizeof(evt->insn_cnt), &prog->len);

	/* 4. 读取原生未被篡改的字节码 (prog->insnsi 是柔性数组的首地址) */
	u32 cnt = evt->insn_cnt;
	if (cnt > MAX_INSN_DUMP) {
		cnt = MAX_INSN_DUMP;
	}
	bpf_probe_read_kernel(evt->insns, cnt * sizeof(struct bpf_insn), prog->insnsi);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("fentry/bpf_interp_hook_step")
int BPF_PROG(on_step, u64 run_id, const u64 *regs)
{
	struct evt_trace_step *evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
	if (!evt) return 0;

	evt->hdr.run_id = run_id;
	evt->hdr.type = EVT_TRACE_STEP;
	bpf_probe_read_kernel(evt->regs, sizeof(evt->regs), regs);
	
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("fentry/bpf_interp_hook_end")
int BPF_PROG(on_end, u64 run_id, u64 ret)
{
	struct evt_prog_end *evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
	if (!evt) return 0;

	evt->hdr.run_id = run_id;
	evt->hdr.type = EVT_PROG_END;
	evt->ret_val = ret;
	
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("fentry/bpf_interp_hook_call")
int BPF_PROG(on_call, u64 run_id, u64 fp)
{
	struct evt_prog_call *evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
	if (!evt) return 0;

	evt->hdr.run_id = run_id;
	evt->hdr.type = EVT_PROG_CALL;
	evt->sp = fp;
	
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("fentry/bpf_interp_hook_tailcall")
int BPF_PROG(on_tailcall, u64 run_id, const struct bpf_prog *prog, u32 pc, u64 map_ptr, u32 index)
{
	if (!prog) return 0;
	
	struct evt_prog_tailcall *evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
	if (!evt) return 0;

	evt->hdr.run_id = run_id;
	evt->hdr.type = EVT_PROG_TAILCALL;
	evt->pc = pc;
	evt->map_ptr = map_ptr;
	evt->index = index;
	evt->prog_ptr = (u64)prog;
	
	/* 提取指令序列 */
	bpf_probe_read_kernel(&evt->insn_cnt, sizeof(evt->insn_cnt), &prog->len);
	__u32 copy_cnt = evt->insn_cnt;
	if (copy_cnt > MAX_INSN_DUMP) copy_cnt = MAX_INSN_DUMP;
	
	if (copy_cnt > 0) {
		bpf_probe_read_kernel(evt->insns, copy_cnt * sizeof(struct bpf_insn), prog->insnsi);
	}

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";