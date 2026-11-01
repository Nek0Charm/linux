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
	u64 addr, read_addr;
	u32 len;
	u32 region;
	bool post;
	bool expected_fault;
};

struct interp_trace_map {
	const struct bpf_map *map;
	struct trace_map info;
	u32 first_region;
};

struct interp_trace_state {
	u64 run_id, seq, steps, calls, bytes;
	u32 region_count, snapshots, code_count, code_id, depth;
	bool stopped;
	const struct bpf_prog *codes[TRACE_MAX_CODES];
	struct interp_trace_region regions[TRACE_MAX_REGIONS];
	u32 frames[TRACE_MAX_FRAMES];
	struct trace_helper pending;
	struct interp_trace_range ranges[3];
	u32 range_count, map_count, frozen_key;
	struct interp_trace_map maps[TRACE_MAX_MAPS];
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
	r->info.permissions = type == TRACE_MAP_FD || type == TRACE_KERNEL_SOURCE ? 0 : TRACE_READ | TRACE_WRITE;
	if (type == TRACE_STACK) {
		r->info.frame_id = r->info.region_id;
		r->info.parent_frame_id = parent;
	}
	if (type == TRACE_MAP_VALUE && r->info.map_id) {
		u32 flags = s->maps[r->info.map_id - 1].map->map_flags;

		r->info.permissions = (flags & BPF_F_WRONLY_PROG ? 0 : TRACE_READ) |
			(flags & BPF_F_RDONLY_PROG ? 0 : TRACE_WRITE);
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

static void interp_trace_snapshot(struct interp_trace_state *s,
				 const struct interp_trace_range *r, u32 phase);

static void interp_trace_maps(struct interp_trace_state *s,
			      const struct bpf_prog *prog)
{
	u32 i, j, k;

	if (!prog->aux)
		return;
	for (i = 0; i < prog->aux->used_map_cnt && !s->stopped; i++) {
		const struct bpf_map *map = prog->aux->used_maps[i];
		struct interp_trace_map *m;
		struct bpf_trace_event e = {};
		const struct bpf_array *array;
		u64 start, end, bytes;
		bool supported;

		for (j = 0; j < s->map_count; j++)
			if (s->maps[j].map == map)
				break;
		if (j < s->map_count || !map)
			continue;
		if (s->map_count == TRACE_MAX_MAPS) {
			interp_trace_reason(s, TRACE_BUDGET, TRACE_INCOMPLETE);
			return;
		}
		m = &s->maps[s->map_count++];
		m->map = map;
		m->info.address = (u64)(unsigned long)map;
		m->info.map_id = s->map_count;
		m->info.kernel_map_id = map->id;
		m->info.map_type = map->map_type;
		m->info.key_size = map->key_size;
		m->info.value_size = map->value_size;
		m->info.max_entries = map->max_entries;
		m->info.map_flags = map->map_flags;
		m->info.code_id = s->code_id;
		m->info.map_region_id = interp_trace_region(s, m->info.address, 0, TRACE_MAP_FD, 0);
		/* Non-struct BTF values can carry ERR_PTR(-EINVAL), which
		 * means there is no special-field record (see syscall.c).
		 */
		supported = map->key_size == 4 && IS_ERR_OR_NULL(map->record) &&
			!bpf_interp_trace_global_map(map) &&
			bpf_interp_trace_array_value_region(map, &start, &end);
		if (supported) {
			array = container_of(map, struct bpf_array, map);
			m->info.value_stride = array->elem_size;
			bytes = (u64)map->max_entries * map->value_size;
			/* Reserve room for active and future interpreter frames. */
			if (s->region_count > TRACE_MAX_REGIONS - TRACE_MAX_FRAMES ||
			    map->max_entries > TRACE_MAX_REGIONS - TRACE_MAX_FRAMES - s->region_count ||
			    map->max_entries > TRACE_MAX_SNAPSHOTS - s->snapshots ||
			    bytes > TRACE_RUN_BYTES - s->bytes || !map->value_size ||
			    map->value_size > TRACE_CALL_BYTES) {
				interp_trace_reason(s, TRACE_BUDGET, TRACE_INCOMPLETE);
				return;
			}
		}
		m->info.supported = supported;
		e.map = m->info;
		interp_trace_emit(s, &e, TRACE_MAP);
		if (!supported) {
			if (map->map_type != BPF_MAP_TYPE_PROG_ARRAY)
				interp_trace_reason(s, TRACE_UNSUPPORTED_MAP, TRACE_UNSUPPORTED);
			continue;
		}
		m->first_region = s->region_count + 1;
		for (k = 0; k < map->max_entries; k++) {
			struct interp_trace_range range = {};
			struct interp_trace_region *r;
			u32 id;

			/* Fill identity before emitting the declaration. */
			r = &s->regions[s->region_count];
			r->info.map_id = m->info.map_id;
			r->info.element_index = k;
			r->info.entry_id = k + 1;
			id = interp_trace_region(s, start + (u64)k * m->info.value_stride,
					map->value_size, TRACE_MAP_VALUE, 0);
			/* Region helper derives permissions from the real map flags. */
			range.addr = s->regions[id - 1].info.base_addr;
			range.read_addr = range.addr;
			range.len = map->value_size;
			range.region = id;
			interp_trace_snapshot(s, &range, TRACE_INITIAL_MEMORY);
		}
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
	e.code.time_ns = ktime_get_ns();
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

static bool interp_trace_registered_access(u64 addr, u64 size, bool write)
{
	struct interp_trace_state *s = this_cpu_read(bpf_trace_state);
	u32 i;

	for (i = 0; s && !s->stopped && i < s->region_count; i++) {
		struct interp_trace_region *r = &s->regions[i];

		if (r->alive && r->info.type == TRACE_MAP_VALUE &&
		    (r->info.permissions & (write ? TRACE_WRITE : TRACE_READ)) &&
		    addr >= r->info.base_addr && addr - r->info.base_addr <= r->info.size &&
		    size <= r->info.size - (addr - r->info.base_addr))
			return true;
	}
	return false;
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

		if (r->alive && (r->info.type == TRACE_STACK ||
		     (r->info.type == TRACE_MAP_VALUE && (r->info.permissions & TRACE_READ))) &&
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

		if (r->alive && (r->info.type == TRACE_STACK ||
		     (r->info.type == TRACE_MAP_VALUE && (r->info.permissions & TRACE_READ))) &&
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
	if (s->range_count == ARRAY_SIZE(s->ranges))
		return false;
	range = &s->ranges[s->range_count++];
	range->addr = addr;
	range->read_addr = addr;
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
	e.memory.read_address = r->read_addr;
	e.memory.offset = r->addr - s->regions[r->region - 1].info.base_addr;
	e.memory.snapshot_id = ++s->snapshots;
	e.memory.call_id = phase == TRACE_INITIAL_MEMORY ? 0 : s->pending.call_id;
	e.memory.map_id = phase == TRACE_INITIAL_MEMORY ? s->regions[r->region - 1].info.map_id : 0;
	e.memory.code_id = s->code_id;
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

/* R1 is compared only with verifier-owned used_maps identities. */
static bool interp_trace_map_pre(struct interp_trace_state *s, const u64 *regs)
{
	struct trace_map_effect *effect = &s->pending.map_effect;
	struct interp_trace_map *m = NULL;
	u32 i, id = s->pending.helper_id;
	u64 target;

	for (i = 0; i < s->map_count; i++)
		if (s->maps[i].info.address == regs[1]) {
			const struct bpf_prog_aux *aux = s->codes[s->code_id]->aux;
			u32 j;

			for (j = 0; aux && j < aux->used_map_cnt; j++)
				if (aux->used_maps[j] == s->maps[i].map)
					m = &s->maps[i];
		}
	if (!m || !m->info.supported) {
		interp_trace_reason(s, TRACE_UNSUPPORTED_MAP, TRACE_UNSUPPORTED);
		return false;
	}
	effect->map_id = m->info.map_id;
	effect->flags = regs[4];
	if (!interp_trace_add_range(s, regs[2], 4, true, false))
		return false;
	if (copy_from_kernel_nofault(&s->frozen_key, (void *)(unsigned long)regs[2], 4)) {
		interp_trace_reason(s, TRACE_UNKNOWN_REGION, TRACE_INCOMPLETE);
		return false;
	}
	effect->state = s->frozen_key < m->info.max_entries ? 1 : 2;
	if (id == BPF_FUNC_map_update_elem &&
	    !interp_trace_add_range(s, regs[3], m->info.value_size, true, false))
		return false;
	if (effect->state == 1) {
		u32 region = m->first_region + s->frozen_key;

		target = s->regions[region - 1].info.base_addr;
		if (id == BPF_FUNC_map_update_elem &&
		    ((regs[2] < target + m->info.value_size && target < regs[2] + 4) ||
		     (regs[3] < target + m->info.value_size && target < regs[3] + m->info.value_size))) {
			interp_trace_reason(s, TRACE_UNSUPPORTED_ALIAS, TRACE_UNSUPPORTED);
			/* Preserve the observed boundary bytes even when no overlap
			 * contract is offered. The helper still uses the original args.
			 */
			s->pending.status = TRACE_UNSUPPORTED;
		}
		effect->entry_id = s->frozen_key + 1;
		/* Observation may read write-only BPF memory. */
		s->ranges[s->range_count++] = (struct interp_trace_range) {
			.addr = target, .read_addr = target, .len = m->info.value_size,
			.region = region, .post = true,
		};
	}
	effect->key_snapshot_id = s->snapshots + 1;
	if (id == BPF_FUNC_map_update_elem)
		effect->input_value_snapshot_id = s->snapshots + 2;
	if (effect->state == 1)
		effect->value_snapshot_id = s->snapshots + s->range_count;
	return true;
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
		case BPF_FUNC_map_lookup_elem:
		case BPF_FUNC_map_update_elem:
		case BPF_FUNC_map_delete_elem:
			supported = interp_trace_map_pre(s, regs);
			break;
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
	s->pending.status = supported ? s->pending.status : TRACE_UNSUPPORTED;
	s->pending.snapshots = s->range_count;
	e.helper = s->pending;
	interp_trace_emit(s, &e, TRACE_HELPER_PRE);
	for (i = 0; i < s->range_count; i++) {
		struct interp_trace_range range = s->ranges[i];

		if (!i && s->pending.map_effect.map_id)
			range.read_addr = (u64)(unsigned long)&s->frozen_key;
		interp_trace_snapshot(s, &range, 0);
	}
}

static void interp_trace_helper_post(struct interp_trace_state *s, u64 ret)
{
	struct bpf_trace_event e = {};
	u32 i;

	if (s->stopped)
		return;
	s->pending.ret = ret;
	if (s->pending.map_effect.map_id && s->range_count) {
		struct trace_map_effect *effect = &s->pending.map_effect;

		effect->key_snapshot_id = s->snapshots + 1;
		if (effect->input_value_snapshot_id)
			effect->input_value_snapshot_id = s->snapshots + 2;
		if (effect->state == 1)
			effect->value_snapshot_id = s->snapshots + s->range_count;
		if (s->pending.helper_id == BPF_FUNC_map_lookup_elem && ret) {
			u32 region = s->ranges[s->range_count - 1].region;

			if (effect->state != 1 || ret != s->regions[region - 1].info.base_addr)
				interp_trace_reason(s, TRACE_UNKNOWN_REGION, TRACE_INCOMPLETE);
			else
				effect->return_region_id = region;
		}
	}
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
	e.summary.time_ns = ktime_get_ns();
	e.summary.events = s->seq + 1;
	e.summary.steps = s->steps;
	e.summary.calls = s->calls;
	e.summary.regions = s->region_count;
	e.summary.snapshots = s->snapshots;
	e.summary.snapshot_bytes = s->bytes;
	e.summary.ret = ret;
	interp_trace_emit(s, &e, TRACE_END);
}
