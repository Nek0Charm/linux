/* SPDX-License-Identifier: GPL-2.0 */
/* Included by core.c: all mutable observation state belongs to an invocation.
 * The per-CPU pointer is saved/restored by every interpreter entry, including
 * recursive entries, while migration is disabled. Never hold the recursion
 * guard over the program or a helper call.
 */
struct interp_trace_region {
	struct trace_region info;
	bool alive;
};

struct interp_trace_range {
	u64 addr;
	u32 len;
	u32 region;
	bool post;
	bool expected_fault;
};

struct interp_trace_state {
	u64 run_id, seq, steps, calls, bytes;
	u32 region_count, snapshots, code_count, code_id, depth;
	bool stopped;
	const struct bpf_prog *codes[TRACE_MAX_CODES];
	struct interp_trace_region regions[TRACE_MAX_REGIONS];
	u32 frames[TRACE_MAX_FRAMES];
	struct trace_helper pending;
	struct interp_trace_range ranges[2];
	u32 range_count;
};

static DEFINE_PER_CPU(struct interp_trace_state *, bpf_trace_state);

static void interp_trace_emit(struct interp_trace_state *s,
			      struct bpf_trace_event *e, u32 type)
{
	if (!s || (s->stopped && type != TRACE_END && type != TRACE_REGION_END))
		return;
	e->hdr.run_id = s->run_id;
	e->hdr.seq = ++s->seq;
	e->hdr.type = type;
	this_cpu_inc(bpf_trace_active);
	trace_bpf_interp(e);
	this_cpu_dec(bpf_trace_active);
}

static void interp_trace_reason(struct interp_trace_state *s, u32 reason,
				u32 status)
{
	struct bpf_trace_event e = {};

	e.diagnostic.reason = reason;
	e.diagnostic.status = status;
	interp_trace_emit(s, &e, TRACE_REASON);
	if (reason == TRACE_BUDGET)
		s->stopped = true;
}

static void bpf_interp_trace_drop_run(u64 run_id, u32 reason)
{
	struct interp_trace_state *s = this_cpu_read(bpf_trace_state);

	if (s && run_id == s->run_id)
		interp_trace_reason(s, reason, TRACE_UNSUPPORTED);
	this_cpu_write(bpf_trace_current_drop, true);
}

static u32 interp_trace_region(struct interp_trace_state *s, u64 addr,
			       u64 size, u32 type, u32 parent)
{
	struct bpf_trace_event e = {};
	struct interp_trace_region *r;

	if (s->region_count == TRACE_MAX_REGIONS || addr > U64_MAX - size) {
		interp_trace_reason(s, TRACE_BUDGET, TRACE_INCOMPLETE);
		return 0;
	}
	r = &s->regions[s->region_count++];
	r->info.base_addr = addr;
	r->info.size = size;
	r->info.type = type;
	r->info.region_id = s->region_count;
	if (type == TRACE_STACK) {
		r->info.frame_id = r->info.region_id;
		r->info.parent_frame_id = parent;
	}
	r->alive = true;
	e.region = r->info;
	interp_trace_emit(s, &e, TRACE_REGION);
	return r->info.region_id;
}

static void interp_trace_region_end(struct interp_trace_state *s, u32 id)
{
	struct bpf_trace_event e = {};

	if (!id || id > s->region_count || !s->regions[id - 1].alive)
		return;
	s->regions[id - 1].alive = false;
	e.region = s->regions[id - 1].info;
	interp_trace_emit(s, &e, TRACE_REGION_END);
}

static void interp_trace_frame_enter(struct interp_trace_state *s, u64 fp,
				     u32 size)
{
	u32 parent = s->depth ? s->frames[s->depth - 1] : 0;
	u32 id;

	if (s->depth == TRACE_MAX_FRAMES || fp < size) {
		interp_trace_reason(s, TRACE_BUDGET, TRACE_INCOMPLETE);
		return;
	}
	id = interp_trace_region(s, fp - size, size, TRACE_STACK, parent);
	s->frames[s->depth++] = id;
}

static void interp_trace_frame_exit(struct interp_trace_state *s)
{
	if (s->depth)
		interp_trace_region_end(s, s->frames[--s->depth]);
}

static void interp_trace_maps(struct interp_trace_state *s,
			      const struct bpf_prog *prog)
{
	u32 i, j;

	if (!prog->aux)
		return;
	for (i = 0; i < prog->aux->used_map_cnt; i++) {
		const struct bpf_map *map = prog->aux->used_maps[i];
		u64 start, end;
		bool found = false;

		for (j = 0; j < s->region_count; j++)
			if (s->regions[j].info.type == TRACE_MAP_FD &&
			    s->regions[j].info.base_addr == (u64)(unsigned long)map)
				found = true;
		if (found || !map)
			continue;
		interp_trace_region(s, (u64)(unsigned long)map, 8, TRACE_MAP_FD, 0);
		if (bpf_interp_trace_array_value_region(map, &start, &end))
			interp_trace_region(s, start, end - start, TRACE_MAP_VALUE, 0);
	}
}

static void interp_trace_code(struct interp_trace_state *s,
			      const struct bpf_prog *prog, u64 ctx)
{
	struct bpf_trace_event e = {};
	u32 i;

	for (i = 0; i < s->code_count; i++)
		if (s->codes[i] == prog) {
			s->code_id = i;
			return;
		}
	if (i == TRACE_MAX_CODES) {
		interp_trace_reason(s, TRACE_BUDGET, TRACE_INCOMPLETE);
		return;
	}
	s->codes[s->code_count++] = prog;
	s->code_id = i;
	e.code.prog_ptr = (u64)(unsigned long)prog;
	e.code.code_id = i;
	e.code.ctx_ptr = ctx;
	interp_trace_emit(s, &e, i ? TRACE_CODE : TRACE_START);
	interp_trace_maps(s, prog);
}

static u32 interp_trace_pc(struct interp_trace_state *s,
			   const struct bpf_insn *insn)
{
	const struct bpf_prog *prog = s->codes[s->code_id];
	unsigned long addr = (unsigned long)insn;
	unsigned long base = (unsigned long)prog->insnsi;

	if (addr < base || (addr - base) % sizeof(*insn) ||
	    (addr - base) / sizeof(*insn) >= prog->len) {
		interp_trace_reason(s, TRACE_CODE_IDENTITY, TRACE_UNSUPPORTED);
		return U32_MAX;
	}
	return (addr - base) / sizeof(*insn);
}

static bool interp_trace_external_read(const struct bpf_insn *insn, const u64 *regs)
{
	struct interp_trace_state *s = this_cpu_read(bpf_trace_state);
	u32 i;
	u64 addr, end;
	size_t size;

	if (BPF_CLASS(insn->code) != BPF_LDX &&
	    !(BPF_CLASS(insn->code) == BPF_STX && BPF_MODE(insn->code) == BPF_ATOMIC))
		return false;
	size = bpf_interp_trace_access_size(insn);
	if (!size)
		return false;
	addr = regs[BPF_CLASS(insn->code) == BPF_LDX ? insn->src_reg : insn->dst_reg] + insn->off;
	if (check_add_overflow(addr, (u64)size, &end))
		return true;
	for (i = 0; s && i < s->region_count; i++) {
		const struct interp_trace_region *r = &s->regions[i];

		if (r->alive && r->info.type == TRACE_STACK &&
		    addr >= r->info.base_addr && end <= r->info.base_addr + r->info.size)
			return false;
	}
	return true;
}

static void interp_trace_step(struct interp_trace_state *s, const u64 *regs)
{
	struct bpf_trace_event e = {};

	if (s->stopped)
		return;
	e.step.index = s->steps++;
	memcpy(e.step.regs, regs, sizeof(e.step.regs));
	interp_trace_emit(s, &e, TRACE_STEP);
}

/* Only explicitly described helpers may clear helper-memory restrictions.
 * All other helpers, including scalar-return helpers with side effects, are
 * unsupported. The descriptor is selected using the verifier's original ID.
 */
static bool interp_trace_add_range(struct interp_trace_state *s, u64 addr,
				   u64 len, bool post, bool fault_source)
{
	struct interp_trace_range *range;
	u32 i;

	if (len > TRACE_CALL_BYTES || addr > U64_MAX - len) {
		interp_trace_reason(s, TRACE_BUDGET, TRACE_INCOMPLETE);
		return false;
	}
	for (i = 0; i < s->region_count; i++) {
		struct interp_trace_region *r = &s->regions[i];

		if (r->alive && r->info.type == TRACE_STACK &&
		    addr >= r->info.base_addr &&
		    addr - r->info.base_addr <= r->info.size &&
		    len <= r->info.size - (addr - r->info.base_addr))
			break;
	}
	/* The first fixture uses initialized interpreter stack bytes, or NULL
	 * as an independently known invalid source. Arbitrary kernel addresses
	 * cannot establish the stable-source premise and are unsupported.
	 */
	if (i == s->region_count && fault_source && !addr) {
		u32 id = interp_trace_region(s, addr, len, TRACE_KERNEL_SOURCE, 0);

		if (!id)
			return false;
		i = id - 1;
	} else if (i == s->region_count) {
		interp_trace_reason(s, TRACE_UNKNOWN_REGION, TRACE_UNSUPPORTED);
		return false;
	}
	range = &s->ranges[s->range_count++];
	range->addr = addr;
	range->len = len;
	range->region = i + 1;
	range->post = post;
	range->expected_fault = fault_source && !addr && len;
	return true;
}

static void interp_trace_snapshot(struct interp_trace_state *s,
				  const struct interp_trace_range *r, u32 phase)
{
	struct bpf_trace_event e = {};
	u32 offset = 0;

	e.memory.address = r->addr;
	e.memory.offset = r->addr - s->regions[r->region - 1].info.base_addr;
	e.memory.snapshot_id = ++s->snapshots;
	e.memory.call_id = s->pending.call_id;
	e.memory.region_id = r->region;
	e.memory.phase = phase;
	e.memory.length = r->len;
	e.memory.expected_fault = r->expected_fault;
	s->bytes += r->len;
	do {
		e.memory.chunk_offset = offset;
		e.memory.valid_length = min_t(u32, r->len - offset, TRACE_CHUNK_SIZE);
		interp_trace_emit(s, &e, TRACE_MEMORY);
		offset += e.memory.valid_length;
		e.memory.chunk_index++;
	} while (offset < r->len);
}

static void interp_trace_helper_pre(struct interp_trace_state *s,
				    const struct bpf_insn *insn, const u64 *regs)
{
	const struct bpf_prog *prog = s->codes[s->code_id];
	struct bpf_trace_event e = {};
	u64 bytes = 0;
	u32 i, snapshots = 0;
	bool supported = true;

	if (s->stopped)
		return;
	memset(&s->pending, 0, sizeof(s->pending));
	s->range_count = 0;
	s->pending.call_id = ++s->calls;
	s->pending.code_id = s->code_id;
	s->pending.pc = interp_trace_pc(s, insn);
	s->pending.trace_index = s->steps;
	memcpy(s->pending.args, regs + BPF_REG_1, sizeof(s->pending.args));
	for (i = 0; prog->aux && i < prog->aux->interp_helper_call_cnt; i++)
		if (prog->aux->interp_helper_calls[i].pc == s->pending.pc) {
			s->pending.helper_id = prog->aux->interp_helper_calls[i].helper_id;
			break;
		}
	if (s->calls > TRACE_MAX_CALLS) {
		interp_trace_reason(s, TRACE_BUDGET, TRACE_INCOMPLETE);
		supported = false;
	} else {
		switch (s->pending.helper_id) {
		case BPF_FUNC_get_prandom_u32:
			break;
		case BPF_FUNC_strtol:
		case BPF_FUNC_strtoul:
			supported = interp_trace_add_range(s, regs[1], regs[2], true, false);
			if (supported)
				supported = interp_trace_add_range(s, regs[4], 8, true, false);
			break;
		case BPF_FUNC_probe_read_kernel: {
			u32 len = (u32)regs[2];

			if (regs[1] > U64_MAX - len || regs[3] > U64_MAX - len ||
			    (len && regs[1] < regs[3] + len && regs[3] < regs[1] + len)) {
				interp_trace_reason(s, TRACE_UNKNOWN_REGION, TRACE_UNSUPPORTED);
				supported = false;
				break;
			}
			supported = interp_trace_add_range(s, regs[3], len, false, true);
			if (supported)
				supported = interp_trace_add_range(s, regs[1], len, true, false);
			break;
		}
		default:
			interp_trace_reason(s, TRACE_UNKNOWN_HELPER, TRACE_UNSUPPORTED);
			supported = false;
		}
	}
	for (i = 0; i < s->range_count; i++) {
		bytes += s->ranges[i].len * (s->ranges[i].post ? 2 : 1);
		snapshots += s->ranges[i].post ? 2 : 1;
	}
	if (bytes > TRACE_CALL_BYTES || s->bytes + bytes > TRACE_RUN_BYTES ||
	    s->snapshots + snapshots > TRACE_MAX_SNAPSHOTS) {
		interp_trace_reason(s, TRACE_BUDGET, TRACE_INCOMPLETE);
		supported = false;
	}
	if (!supported)
		s->range_count = 0;
	if (s->stopped)
		return;
	s->pending.status = supported ? TRACE_COMPLETE : TRACE_UNSUPPORTED;
	s->pending.snapshots = s->range_count;
	e.helper = s->pending;
	interp_trace_emit(s, &e, TRACE_HELPER_PRE);
	for (i = 0; i < s->range_count; i++)
		interp_trace_snapshot(s, &s->ranges[i], 0);
}

static void interp_trace_helper_post(struct interp_trace_state *s, u64 ret)
{
	struct bpf_trace_event e = {};
	u32 i;

	if (s->stopped)
		return;
	s->pending.ret = ret;
	s->pending.snapshots = 0;
	e.helper = s->pending;
	for (i = 0; i < s->range_count; i++)
		if (s->ranges[i].post)
			e.helper.snapshots++;
	interp_trace_emit(s, &e, TRACE_HELPER_POST);
	for (i = 0; i < s->range_count; i++)
		if (s->ranges[i].post)
			interp_trace_snapshot(s, &s->ranges[i], 1);
	for (i = 0; i < s->range_count; i++)
		if (s->regions[s->ranges[i].region - 1].info.type == TRACE_KERNEL_SOURCE)
			interp_trace_region_end(s, s->ranges[i].region);
}

static void interp_trace_end(struct interp_trace_state *s, u64 ret)
{
	struct bpf_trace_event e = {};
	u32 i;

	for (i = 0; i < s->region_count; i++)
		interp_trace_region_end(s, i + 1);
	e.summary.events = s->seq + 1;
	e.summary.steps = s->steps;
	e.summary.calls = s->calls;
	e.summary.regions = s->region_count;
	e.summary.snapshots = s->snapshots;
	e.summary.snapshot_bytes = s->bytes;
	e.summary.ret = ret;
	interp_trace_emit(s, &e, TRACE_END);
}
