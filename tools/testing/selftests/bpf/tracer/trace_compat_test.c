// SPDX-License-Identifier: GPL-2.0
#include <assert.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include "trace_common.h"
#include "trace_consumer.h"

static unsigned int run_id, seq, regions;

static void event(struct bpf_trace_event *e, unsigned int type)
{
	e->hdr = (struct trace_hdr) { .run_id = run_id, .seq = ++seq, .type = type };
	assert(trace_consumer_event(NULL, e, sizeof(*e)) == 0);
}

static void code(unsigned int id)
{
	struct evt_code e = {};

	e.event.hdr = (struct trace_hdr) {
		.run_id = run_id, .seq = ++seq, .type = id ? TRACE_CODE : TRACE_START,
	};
	e.event.code.code_id = id;
	e.event.code.prog_ptr = 0x10000 + id * 0x1000;
	e.insn_cnt = 2;
	e.insns[0] = (struct bpf_insn) {
		.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0,
		.imm = 42 + id,
	};
	e.insns[1].code = BPF_JMP | BPF_EXIT;
	snprintf(e.prog_name, sizeof(e.prog_name), "compat_%u", run_id);
	assert(trace_consumer_event(NULL, &e, sizeof(e)) == 0);
}

static void start(unsigned int id)
{
	run_id = id;
	seq = 0;
	regions = 0;
	code(0);
}

static struct trace_region stack(unsigned int addr, unsigned int size, unsigned int parent)
{
	struct bpf_trace_event e = {};

	regions++;
	e.region = (struct trace_region) {
		.region_id = regions, .frame_id = regions, .type = TRACE_STACK,
		.base_addr = addr, .size = size, .parent_frame_id = parent,
	};
	event(&e, TRACE_REGION);
	return e.region;
}

static void leave(struct trace_region region)
{
	struct bpf_trace_event e = { .region = region };

	event(&e, TRACE_REGION_END);
}

static void tail(unsigned int target, unsigned int from, unsigned int index)
{
	struct bpf_trace_event e = {};

	e.code = (struct trace_code) {
		.code_id = target, .from_code_id = from, .index = index,
		.prog_ptr = 0x10000 + target * 0x1000,
		.map_ptr = 0x4000, .max_entries = 8,
	};
	event(&e, TRACE_TAILCALL);
}

static void end(void)
{
	struct bpf_trace_event e = {};

	e.summary.events = seq + 1;
	e.summary.regions = regions;
	e.summary.ret = 42;
	event(&e, TRACE_END);
}

int main(void)
{
	struct trace_region main, child;

	assert(trace_consumer_open(stdout) == 0);
	start(1);
	main = stack(0x8000, 32, 0);
	leave(main);
	end();

	start(2);
	main = stack(0x8000, 32, 0);
	child = stack(0x7000, 64, main.region_id);
	leave(child);
	/* A later call can reuse an earlier frame's address. */
	child = stack(0x7000, 64, main.region_id);
	leave(child);
	leave(main);
	end();

	start(3);
	main = stack(0x8000, 512, 0);
	code(1);
	tail(1, 0, 2);
	code(2);
	tail(2, 1, 5);
	/* A repeated transition must still refer to the original code. */
	tail(1, 2, 2);
	leave(main);
	end();

	start(4);
	tail(TRACE_MAX_CODES, 0, 0);
	end();

	/* Incomplete captures must retain the same parseable field shape. */
	start(5);
	assert(trace_consumer_close() == 0);
	return 0;
}
