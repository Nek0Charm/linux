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

	/* ================= 新增：读取 used_maps 生成 mem_blocks ================= */
	evt->block_cnt = 0;
	if (aux) {
		u32 used_map_cnt = 0;
		bpf_probe_read_kernel(&used_map_cnt, sizeof(used_map_cnt), &aux->used_map_cnt);
		struct bpf_map **used_maps = NULL;
		bpf_probe_read_kernel(&used_maps, sizeof(used_maps), &aux->used_maps);
		
		if (used_maps && used_map_cnt > 0) {
			u32 limit = used_map_cnt > 8 ? 8 : used_map_cnt;
			int b_idx = 0;
			
			for (u32 i = 0; i < 8; i++) {
				if (i >= limit || b_idx >= MAX_MEM_BLOCKS - 1) break;
				
				struct bpf_map *map = NULL;
				bpf_probe_read_kernel(&map, sizeof(map), &used_maps[i]);
				if (!map) continue;

				u32 map_type = 0;
				bpf_probe_read_kernel(&map_type, sizeof(map_type), &map->map_type);
				if (map_type == BPF_MAP_TYPE_PROG_ARRAY) break;

				/* 块 1: Map FD (不可直接解引用) */
				evt->blocks[b_idx].base_addr = (u64)map;
				evt->blocks[b_idx].size = 8; // here must > 0
				evt->blocks[b_idx].is_direct_value = 0;
				b_idx++;

				/* 块 2: Map Value (仅 Array Map 等支持直接解引用) */
				if (map_type == BPF_MAP_TYPE_ARRAY) {
					u32 v_size = 0, m_entries = 0;
					bpf_probe_read_kernel(&v_size, sizeof(v_size), &map->value_size);
					bpf_probe_read_kernel(&m_entries, sizeof(m_entries), &map->max_entries);
					
					/* 计算 value 数组的首地址：利用 vmlinux.h 中的 struct bpf_array */
					evt->blocks[b_idx].base_addr = (u64)map + __builtin_offsetof(struct bpf_array, value);
					evt->blocks[b_idx].size = v_size * m_entries;
					evt->blocks[b_idx].is_direct_value = 1;
					b_idx++;
				}
			}
			evt->block_cnt = b_idx;
		}
	}
	/* ======================================================================== */

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

SEC("fentry/bpf_interp_hook_tailcall_map")
int BPF_PROG(on_tailcall_map, u64 run_id, const struct bpf_map * map_ptr)
{	
	struct evt_prog_tailcall_map *evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
	if (!evt) return 0;

	evt->hdr.run_id = run_id;
	evt->hdr.type = EVT_PROG_TAILCALL_MAP;
	evt->map_ptr = (u64)map_ptr;
	evt->max_entries = map_ptr->max_entries;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";