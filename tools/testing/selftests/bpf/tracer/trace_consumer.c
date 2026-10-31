// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "trace_common.h"
#include "trace_consumer.h"

#define REASON_SEQUENCE 100
#define REASON_START 101
#define REASON_END 102
#define REASON_EVENT 103
#define REASON_PAIR 104
#define REASON_CHUNK 105
#define REASON_REFERENCE 106
#define REASON_READ 107
#define REASON_COUNT 108
#define REASON_OUTPUT 109
#define REASON_LIMIT 110
#define REASON_MAX 128
#define MAX_CALL_SNAPSHOTS 4

typedef unsigned long long ull;

struct region_record {
	struct trace_region info;
	__u64 born, dead;
};

struct snapshot_record {
	struct trace_memory info;
	__u32 received, chunks;
	int error;
	unsigned char bytes[TRACE_CALL_BYTES];
};

struct pending_call {
	struct trace_helper pre, post;
	__u64 pre_seq, post_seq;
	bool active, posted;
	__u32 count;
	struct snapshot_record snapshots[MAX_CALL_SNAPSHOTS];
};

struct active_run {
	__u64 id, seq, events, steps, calls, bytes, snapshots;
	bool started, ended;
	int status;
	bool reasons[REASON_MAX];
	FILE *trace, *helpers, *tails;
	struct evt_code *codes[TRACE_MAX_CODES];
	__u32 code_count, region_count, tail_count, helper_count;
	struct region_record regions[TRACE_MAX_REGIONS];
	struct pending_call pending;
	struct trace_summary summary;
	struct active_run *next;
};

static struct active_run *runs;
static FILE *output;
static bool first_run;
static int output_error;

static const char *status_name(int status)
{
	return status == TRACE_INCOMPLETE ? "incomplete" :
		status == TRACE_UNSUPPORTED ? "unsupported" : "complete";
}

static const char *reason_name(unsigned int reason)
{
	switch (reason) {
	case TRACE_DROP_UNSUPPORTED_TAIL_TARGET: return "unsupported_program";
	case TRACE_DROP_CTX_INDIRECTION: return "context_indirection";
	case TRACE_DROP_HELPER_MEMORY_SIDE_EFFECT: return "helper_memory";
	case TRACE_DROP_CTX_INTERNAL_STATE: return "context_state";
	case TRACE_DROP_MAP_VALUE_ACCESS: return "map_initial_memory";
	case TRACE_UNKNOWN_HELPER: return "unsupported_helper";
	case TRACE_BUDGET: return "capture_budget";
	case TRACE_UNKNOWN_REGION: return "unsupported_region";
	case TRACE_CODE_IDENTITY: return "code_identity";
	case TRACE_CALLBACK: return "helper_callback";
	case TRACE_ALLOCATION: return "allocation";
	case REASON_SEQUENCE: return "event_sequence";
	case REASON_START: return "missing_or_duplicate_start";
	case REASON_END: return "missing_end";
	case REASON_EVENT: return "invalid_event";
	case REASON_PAIR: return "helper_pair";
	case REASON_CHUNK: return "snapshot_chunks";
	case REASON_REFERENCE: return "invalid_reference";
	case REASON_READ: return "snapshot_read";
	case REASON_COUNT: return "producer_counts";
	case REASON_OUTPUT: return "output_io";
	case REASON_LIMIT: return "consumer_budget";
	default: return "unknown_reason";
	}
}

static void fail(struct active_run *r, unsigned int reason, int status)
{
	if (status > r->status)
		r->status = status;
	if (reason >= REASON_MAX)
		reason = REASON_EVENT;
	r->reasons[reason] = true;
}

static void json_string(FILE *fp, const char *s, size_t limit)
{
	fputc('"', fp);
	for (size_t i = 0; i < limit && s[i]; i++) {
		unsigned char c = s[i];

		if (c == '"' || c == '\\')
			fprintf(fp, "\\%c", c);
		else if (c < 32 || c >= 127)
			fprintf(fp, "\\u%04x", c);
		else
			fputc(c, fp);
	}
	fputc('"', fp);
}

static struct active_run *get_run(__u64 id)
{
	struct active_run *r;

	for (r = runs; r; r = r->next)
		if (r->id == id)
			return r;
	r = calloc(1, sizeof(*r));
	if (!r) {
		output_error = ENOMEM;
		return NULL;
	}
	r->id = id;
	r->trace = tmpfile();
	r->helpers = tmpfile();
	r->tails = tmpfile();
	if (!r->trace || !r->helpers || !r->tails) {
		if (r->trace)
			fclose(r->trace);
		if (r->helpers)
			fclose(r->helpers);
		if (r->tails)
			fclose(r->tails);
		free(r);
		output_error = errno ? errno : EIO;
		return NULL;
	}
	r->next = runs;
	runs = r;
	return r;
}

static void write_insns(FILE *fp, const struct evt_code *code, int indent)
{
	fprintf(fp, "[");
	for (__u32 i = 0; code && i < code->insn_cnt; i++) {
		__u64 bits;

		memcpy(&bits, &code->insns[i], sizeof(bits));
		fprintf(fp, "%s\n%*s\"0x%llx\"", i ? "," : "",
			indent + 2, "", (ull)bits);
	}
	if (code && code->insn_cnt)
		fprintf(fp, "\n%*s", indent, "");
	fprintf(fp, "]");
}

static void write_static_helpers(FILE *fp, const struct evt_code *code, int indent)
{
	fprintf(fp, "[");
	for (__u32 i = 0; code && i < code->helper_call_cnt; i++)
		fprintf(fp, "%s\n%*s{ \"pc\": %u, \"helper_id\": %u }",
			i ? "," : "", indent + 2, "",
			code->helper_calls[i].pc, code->helper_calls[i].helper_id);
	if (code && code->helper_call_cnt)
		fprintf(fp, "\n%*s", indent, "");
	fprintf(fp, "]");
}

static void copy_stream(FILE *dst, FILE *src)
{
	char buffer[4096];
	size_t len;

	if (fflush(src) || ferror(src) || fseek(src, 0, SEEK_SET)) {
		output_error = EIO;
		return;
	}
	while ((len = fread(buffer, 1, sizeof(buffer), src)))
		if (fwrite(buffer, 1, len, dst) != len)
			output_error = EIO;
	if (ferror(src))
		output_error = EIO;
}

static bool live_range(struct active_run *r, __u32 id, __u64 offset,
		       __u32 length, __u64 seq)
{
	struct region_record *b;

	if (!id || id > r->region_count)
		return false;
	b = &r->regions[id - 1];
	return b->info.region_id == id && b->born <= seq &&
		(!b->dead || seq < b->dead) && offset <= b->info.size &&
		length <= b->info.size - offset && b->info.type != TRACE_MAP_FD;
}

static void write_snapshots(FILE *fp, struct pending_call *p, unsigned int phase)
{
	bool first = true;

	fprintf(fp, "[");
	for (__u32 i = 0; i < p->count; i++) {
		struct snapshot_record *s = &p->snapshots[i];

		if (s->info.phase != phase)
			continue;
		fprintf(fp, "%s\n          {\n"
			"            \"region_id\": %u,\n"
			"            \"offset\": %llu,\n"
			"            \"length\": %u,\n",
			first ? "" : ",", s->info.region_id, (ull)s->info.offset, s->info.length);
		first = false;
		fprintf(fp, "            \"snapshot_id\": %u,\n"
			"            \"chunks\": %u,\n"
			"            \"read_status\": \"%s\"",
			s->info.snapshot_id, s->chunks,
			s->received != s->info.length ? "missing" :
			s->error ? (s->info.expected_fault ? "fault" : "error") : "ok");
		if (s->error)
			fprintf(fp, ",\n            \"error\": %d", s->error);
		if (!s->error && s->received == s->info.length) {
			fprintf(fp, ",\n            \"bytes\": \"");
			for (__u32 j = 0; j < s->received; j++)
				fprintf(fp, "%02x", s->bytes[j]);
			fprintf(fp, "\"");
		}
		fprintf(fp, "\n          }");
	}
	if (!first)
		fprintf(fp, "\n        ");
	fprintf(fp, "]");
}

static void finish_call(struct active_run *r, const struct bpf_trace_event *step)
{
	struct pending_call *p = &r->pending;
	unsigned int counts[2] = {};
	int status = p->pre.status;
	FILE *fp = r->helpers;

	if (!p->active)
		return;
	if (!p->posted || !step || p->post.trace_index != step->step.index ||
	    p->post.ret != step->step.regs[0]) {
		fail(r, REASON_PAIR, TRACE_INCOMPLETE);
		status = TRACE_INCOMPLETE;
	}
	for (__u32 i = 0; i < p->count; i++) {
		struct snapshot_record *s = &p->snapshots[i];

		counts[s->info.phase]++;
		if (s->received != s->info.length ||
		    (s->error && !s->info.expected_fault)) {
			fail(r, REASON_CHUNK, TRACE_INCOMPLETE);
			status = TRACE_INCOMPLETE;
		}
	}
	if (counts[0] != p->pre.snapshots || counts[1] != p->post.snapshots) {
		fail(r, REASON_CHUNK, TRACE_INCOMPLETE);
		status = TRACE_INCOMPLETE;
	}
	fprintf(fp, "%s      {\n"
		"        \"call_id\": %u,\n"
		"        \"code_id\": %u,\n"
		"        \"pc\": %u,\n",
		r->helper_count++ ? ",\n" : "", p->pre.call_id, p->pre.code_id, p->pre.pc);
	fprintf(fp, "        \"trace_index\": %llu,\n"
		"        \"pre_seq\": %llu,\n"
		"        \"post_seq\": %llu,\n"
		"        \"helper_id\": %u,\n"
		"        \"args\": [",
		(ull)p->pre.trace_index, (ull)p->pre_seq, (ull)p->post_seq, p->pre.helper_id);
	for (unsigned int i = 0; i < 5; i++)
		fprintf(fp, "%s\"0x%llx\"", i ? ", " : "", (ull)p->pre.args[i]);
	fprintf(fp, "],\n        \"ret\": \"0x%llx\",\n        \"premem\": ",
		(ull)p->post.ret);
	write_snapshots(fp, p, 0);
	fprintf(fp, ",\n        \"postmem\": ");
	write_snapshots(fp, p, 1);
	fprintf(fp, ",\n        \"capture_status\": \"%s\"\n      }", status_name(status));
	memset(p, 0, sizeof(*p));
}

static void receive_memory(struct active_run *r, const struct evt_memory *evt)
{
	const struct trace_memory *m = &evt->event.memory;
	struct pending_call *p = &r->pending;
	struct snapshot_record *s = NULL;

	if (!p->active || m->call_id != p->pre.call_id || m->phase > 1 ||
	    m->phase != (unsigned int)p->posted || m->length > TRACE_CALL_BYTES ||
	    m->valid_length > TRACE_CHUNK_SIZE || m->chunk_offset > m->length ||
	    m->valid_length != (m->length - m->chunk_offset > TRACE_CHUNK_SIZE ?
		TRACE_CHUNK_SIZE : m->length - m->chunk_offset) ||
	    !live_range(r, m->region_id, m->offset, m->length, evt->event.hdr.seq)) {
		fail(r, REASON_REFERENCE, TRACE_INCOMPLETE);
		return;
	}
	if (m->address != r->regions[m->region_id - 1].info.base_addr + m->offset ||
	    (m->expected_fault && (m->address || m->phase ||
	     r->regions[m->region_id - 1].info.type != TRACE_KERNEL_SOURCE))) {
		fail(r, REASON_REFERENCE, TRACE_INCOMPLETE);
		return;
	}
	if (p->count && p->snapshots[p->count - 1].info.snapshot_id == m->snapshot_id)
		s = &p->snapshots[p->count - 1];
	if (!s) {
		if (p->count == MAX_CALL_SNAPSHOTS || m->chunk_index || m->chunk_offset ||
		    m->snapshot_id != r->snapshots + 1) {
			fail(r, REASON_CHUNK, TRACE_INCOMPLETE);
			return;
		}
		if (p->count && p->snapshots[p->count - 1].received !=
		    p->snapshots[p->count - 1].info.length)
			fail(r, REASON_CHUNK, TRACE_INCOMPLETE);
		s = &p->snapshots[p->count++];
		s->info = *m;
		r->snapshots++;
		r->bytes += m->length;
	}
	if (s->received != m->chunk_offset || s->chunks != m->chunk_index ||
	    s->info.region_id != m->region_id || s->info.offset != m->offset ||
	    s->info.length != m->length || s->info.phase != m->phase ||
	    s->info.expected_fault != m->expected_fault ||
	    (!m->valid_length && (m->length || s->chunks))) {
		fail(r, REASON_CHUNK, TRACE_INCOMPLETE);
		return;
	}
	if (evt->event.hdr.read_error) {
		s->error = evt->event.hdr.read_error;
		if (!m->expected_fault)
			fail(r, REASON_READ, TRACE_INCOMPLETE);
	} else {
		memcpy(s->bytes + s->received, evt->bytes, m->valid_length);
	}
	s->received += m->valid_length;
	s->chunks++;
}

static void receive_region(struct active_run *r, const struct bpf_trace_event *e)
{
	const struct trace_region *b = &e->region;
	struct region_record *record;

	if (!b->region_id || b->region_id > TRACE_MAX_REGIONS ||
	    b->base_addr > UINT64_MAX - b->size ||
	    b->type < TRACE_STACK || b->type > TRACE_KERNEL_SOURCE) {
		fail(r, REASON_REFERENCE, TRACE_INCOMPLETE);
		return;
	}
	record = &r->regions[b->region_id - 1];
	if (e->hdr.type == TRACE_REGION_END) {
		if (!record->born || record->dead || memcmp(&record->info, b, sizeof(*b)))
			fail(r, REASON_REFERENCE, TRACE_INCOMPLETE);
		else
			record->dead = e->hdr.seq;
		return;
	}
	if (b->region_id != r->region_count + 1 || record->born) {
		fail(r, REASON_REFERENCE, TRACE_INCOMPLETE);
		return;
	}
	if (b->type == TRACE_STACK) {
		if (b->frame_id != b->region_id || !b->size || b->size > 512 ||
		    (b->parent_frame_id &&
		     (b->parent_frame_id >= b->region_id ||
		      r->regions[b->parent_frame_id - 1].info.type != TRACE_STACK ||
		      r->regions[b->parent_frame_id - 1].dead)))
			fail(r, REASON_REFERENCE, TRACE_INCOMPLETE);
	}
	for (__u32 i = 0; i < r->region_count; i++) {
		struct region_record *other = &r->regions[i];

		if (!other->dead && b->size && other->info.size &&
		    b->base_addr < other->info.base_addr + other->info.size &&
		    other->info.base_addr < b->base_addr + b->size)
			fail(r, REASON_REFERENCE, TRACE_INCOMPLETE);
	}
	record->info = *b;
	record->born = e->hdr.seq;
	r->region_count++;
}

static void receive_code(struct active_run *r, const struct evt_code *e)
{
	__u32 id = e->event.code.code_id;

	if (id >= TRACE_MAX_CODES || id != r->code_count || r->codes[id] ||
	    e->insn_cnt > TRACE_MAX_INSNS || e->helper_call_cnt > TRACE_MAX_INSNS ||
	    e->event.hdr.read_error) {
		fail(r, REASON_EVENT, TRACE_INCOMPLETE);
		return;
	}
	for (__u32 i = 0; i < e->helper_call_cnt; i++) {
		const struct helper_call_info *c = &e->helper_calls[i];

		if (c->pc >= e->insn_cnt || !c->helper_id ||
		    (i && e->helper_calls[i - 1].pc >= c->pc) ||
		    e->insns[c->pc].code != (BPF_JMP | BPF_CALL))
			fail(r, REASON_REFERENCE, TRACE_INCOMPLETE);
	}
	r->codes[id] = malloc(sizeof(*e));
	if (!r->codes[id]) {
		fail(r, TRACE_ALLOCATION, TRACE_INCOMPLETE);
		return;
	}
	*r->codes[id] = *e;
	r->code_count++;
}

static bool helper_identity(struct active_run *r, const struct trace_helper *h)
{
	struct evt_code *c;

	if (h->code_id >= r->code_count)
		return false;
	c = r->codes[h->code_id];
	if (h->pc >= c->insn_cnt)
		return false;
	for (__u32 i = 0; i < c->helper_call_cnt; i++)
		if (c->helper_calls[i].pc == h->pc)
			return c->helper_calls[i].helper_id == h->helper_id;
	return !h->helper_id && h->status == TRACE_UNSUPPORTED;
}

static const char *region_name(__u32 type)
{
	static const char * const names[] = {
		"invalid", "stack", "map_fd", "map_value", "global_data", "ctx", "kernel_source",
	};

	return names[type <= TRACE_KERNEL_SOURCE ? type : 0];
}

static void finish_run(struct active_run *r)
{
	struct active_run **link;
	struct evt_code *main = r->codes[0];
	bool first = true;

	finish_call(r, NULL);
	if (!r->started)
		fail(r, REASON_START, TRACE_INCOMPLETE);
	if (!r->ended)
		fail(r, REASON_END, TRACE_INCOMPLETE);
	if (fflush(r->trace) || fflush(r->helpers) || fflush(r->tails) ||
	    ferror(r->trace) || ferror(r->helpers) || ferror(r->tails)) {
		fail(r, REASON_OUTPUT, TRACE_INCOMPLETE);
		output_error = EIO;
	}
	fprintf(output, "%s  {\n"
		"    \"run_id\": %llu,\n"
		"    \"prog_id\": %u,\n"
		"    \"prog_name\": ",
		first_run ? "" : ",\n", (ull)r->id, main ? main->prog_id : 0);
	first_run = false;
	json_string(output, main ? main->prog_name : "", main ? sizeof(main->prog_name) : 0);
	fprintf(output, ",\n    \"byte_order\": \"%s\",\n    \"pointer_size\": %zu,\n",
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		"little",
#else
		"big",
#endif
		sizeof(void *));
	fprintf(output, "    \"prog_insn_cnt\": %u,\n"
		"    \"ctx_ptr\": \"0x%llx\",\n"
		"    \"prog_insn\": ",
		main ? main->insn_cnt : 0, (ull)(main ? main->event.code.ctx_ptr : 0));
	write_insns(output, main, 4);
	fprintf(output, ",\n    \"helper_calls\": ");
	write_static_helpers(output, main, 4);
	fprintf(output, ",\n    \"codes\": [");
	for (__u32 i = 0; i < r->code_count; i++) {
		fprintf(output, "%s\n      {\n"
			"        \"code_id\": %u,\n"
			"        \"target\": \"0x%llx\",\n"
			"        \"insns\": ",
			i ? "," : "", i, (ull)r->codes[i]->event.code.prog_ptr);
		write_insns(output, r->codes[i], 8);
		fprintf(output, ",\n        \"helper_calls\": ");
		write_static_helpers(output, r->codes[i], 8);
		fprintf(output, "\n      }");
	}
	if (r->code_count)
		fprintf(output, "\n    ");
	fprintf(output, "],\n    \"trace\": [");
	if (r->steps)
		fprintf(output, "\n");
	copy_stream(output, r->trace);
	if (r->steps)
		fprintf(output, "\n    ");
	fprintf(output, "],\n    \"helper_events\": [");
	if (r->helper_count)
		fprintf(output, "\n");
	copy_stream(output, r->helpers);
	if (r->helper_count)
		fprintf(output, "\n    ");
	fprintf(output, "],\n    \"jmp_table\": [");
	if (r->tail_count)
		fprintf(output, "\n");
	copy_stream(output, r->tails);
	if (r->tail_count)
		fprintf(output, "\n    ");
	fprintf(output, "],\n    \"mem_blocks\": [");
	for (__u32 i = 0; i < r->region_count; i++) {
		struct region_record *b = &r->regions[i];

		fprintf(output, "%s\n      {\n"
			"        \"region_id\": %u,\n"
			"        \"base_addr\": \"0x%llx\",\n"
			"        \"size\": %llu,\n",
			i ? "," : "", b->info.region_id, (ull)b->info.base_addr, (ull)b->info.size);
		fprintf(output, "        \"type\": \"%s\",\n"
			"        \"permissions\": \"%s\",\n"
			"        \"born_seq\": %llu,\n"
			"        \"dead_seq\": ",
			region_name(b->info.type),
			b->info.type == TRACE_MAP_FD || b->info.type == TRACE_KERNEL_SOURCE ? "none" : "rw",
			(ull)b->born);
		if (b->dead)
			fprintf(output, "%llu", (ull)b->dead);
		else
			fprintf(output, "null");
		if (b->info.type == TRACE_STACK) {
			fprintf(output, ",\n        \"frame_id\": %u,\n"
				"        \"parent_frame_id\": ", b->info.frame_id);
			if (b->info.parent_frame_id)
				fprintf(output, "%u", b->info.parent_frame_id);
			else
				fprintf(output, "null");
		}
		fprintf(output, "\n      }");
	}
	if (r->region_count)
		fprintf(output, "\n    ");
	fprintf(output, "],\n    \"capture_config\": {\n"
		"      \"chunk_size\": %u,\n"
		"      \"call_bytes\": %u,\n"
		"      \"run_bytes\": %u,\n"
		"      \"max_calls\": %u,\n"
		"      \"max_regions\": %u,\n"
		"      \"max_snapshots\": %u\n    },\n",
		TRACE_CHUNK_SIZE, TRACE_CALL_BYTES, TRACE_RUN_BYTES,
		TRACE_MAX_CALLS, TRACE_MAX_REGIONS, TRACE_MAX_SNAPSHOTS);
	fprintf(output, "    \"capture_summary\": {\n"
		"      \"events\": %llu,\n"
		"      \"steps\": %llu,\n"
		"      \"calls\": %llu,\n"
		"      \"regions\": %u,\n"
		"      \"snapshots\": %u,\n"
		"      \"snapshot_bytes\": %llu,\n"
		"      \"ret\": \"0x%llx\",\n"
		"      \"received_events\": %llu,\n"
		"      \"last_seq\": %llu,\n"
		"      \"has_start\": %s,\n"
		"      \"has_end\": %s\n    },\n",
		(ull)r->summary.events, (ull)r->summary.steps, (ull)r->summary.calls,
		r->summary.regions, r->summary.snapshots, (ull)r->summary.snapshot_bytes,
		(ull)r->summary.ret, (ull)r->events, (ull)r->seq,
		r->started ? "true" : "false", r->ended ? "true" : "false");
	fprintf(output, "    \"capture_status\": \"%s\",\n    \"capture_reasons\": [",
		status_name(r->status));
	for (unsigned int i = 0; i < REASON_MAX; i++) {
		if (!r->reasons[i])
			continue;
		fprintf(output, "%s\"%s\"", first ? "" : ", ", reason_name(i));
		first = false;
	}
	fprintf(output, "]\n  }");
	if (fflush(output) || ferror(output))
		output_error = EIO;
	for (link = &runs; *link && *link != r; link = &(*link)->next)
		;
	if (*link)
		*link = r->next;
	for (__u32 i = 0; i < TRACE_MAX_CODES; i++)
		free(r->codes[i]);
	fclose(r->trace);
	fclose(r->helpers);
	fclose(r->tails);
	free(r);
}

int trace_consumer_event(void *ctx, void *data, size_t size)
{
	const struct bpf_trace_event *e = data;
	struct active_run *r;
	size_t expected;

	(void)ctx;
	if (size < sizeof(struct trace_hdr)) {
		output_error = EINVAL;
		return -EINVAL;
	}
	r = get_run(e->hdr.run_id);
	if (!r)
		return -output_error;
	r->events++;
	if (e->hdr.seq != r->seq + 1)
		fail(r, REASON_SEQUENCE, TRACE_INCOMPLETE);
	r->seq = e->hdr.seq;
	expected = e->hdr.type == TRACE_START || e->hdr.type == TRACE_CODE ? sizeof(struct evt_code) :
		e->hdr.type == TRACE_MEMORY ? sizeof(struct evt_memory) : sizeof(*e);
	if (size != expected) {
		fail(r, REASON_EVENT, TRACE_INCOMPLETE);
		return 0;
	}
	if (e->hdr.type != TRACE_START && !r->started)
		fail(r, REASON_START, TRACE_INCOMPLETE);
	if (e->hdr.read_error && e->hdr.type != TRACE_MEMORY)
		fail(r, REASON_READ, TRACE_INCOMPLETE);
	switch (e->hdr.type) {
	case TRACE_START:
		if (r->started || e->hdr.seq != 1 || e->code.code_id)
			fail(r, REASON_START, TRACE_INCOMPLETE);
		r->started = true;
		receive_code(r, data);
		break;
	case TRACE_CODE:
		receive_code(r, data);
		break;
	case TRACE_REGION:
	case TRACE_REGION_END:
		receive_region(r, e);
		break;
	case TRACE_HELPER_PRE:
		if (r->pending.active)
			finish_call(r, NULL);
		if (e->helper.call_id != ++r->calls || e->helper.trace_index != r->steps ||
		    e->helper.status > TRACE_UNSUPPORTED || !helper_identity(r, &e->helper))
			fail(r, REASON_PAIR, TRACE_INCOMPLETE);
		if (e->helper.status == TRACE_UNSUPPORTED)
			fail(r, TRACE_UNKNOWN_HELPER, TRACE_UNSUPPORTED);
		r->pending.active = true;
		r->pending.pre = e->helper;
		r->pending.pre_seq = e->hdr.seq;
		break;
	case TRACE_HELPER_POST:
		if (!r->pending.active || r->pending.posted ||
		    e->helper.call_id != r->pending.pre.call_id ||
		    e->helper.code_id != r->pending.pre.code_id || e->helper.pc != r->pending.pre.pc ||
		    e->helper.helper_id != r->pending.pre.helper_id ||
		    e->helper.status != r->pending.pre.status ||
		    e->helper.trace_index != r->pending.pre.trace_index ||
		    memcmp(e->helper.args, r->pending.pre.args, sizeof(e->helper.args)))
			fail(r, REASON_PAIR, TRACE_INCOMPLETE);
		r->pending.posted = true;
		r->pending.post = e->helper;
		r->pending.post_seq = e->hdr.seq;
		break;
	case TRACE_MEMORY:
		receive_memory(r, data);
		break;
	case TRACE_STEP:
		if (e->step.index != r->steps)
			fail(r, REASON_COUNT, TRACE_INCOMPLETE);
		finish_call(r, e);
		fprintf(r->trace, "%s      [", r->steps++ ? ",\n" : "");
		for (unsigned int i = 0; i < 12; i++)
			fprintf(r->trace, "%s\"0x%llx\"", i ? ", " : "", (ull)e->step.regs[i]);
		fprintf(r->trace, "]");
		break;
	case TRACE_REASON:
		if (e->diagnostic.status < TRACE_UNSUPPORTED || e->diagnostic.status > TRACE_INCOMPLETE)
			fail(r, REASON_EVENT, TRACE_INCOMPLETE);
		else
			fail(r, e->diagnostic.reason, e->diagnostic.status);
		break;
	case TRACE_TAILCALL:
		if (e->code.code_id >= r->code_count || e->code.from_code_id >= r->code_count)
			fail(r, REASON_REFERENCE, TRACE_INCOMPLETE);
		fprintf(r->tails, "%s      {\n"
			"        \"code_id\": %u,\n"
			"        \"from_code_id\": %u,\n"
			"        \"pc\": %u,\n"
			"        \"index\": %u,\n"
			"        \"target\": \"0x%llx\",\n"
			"        \"map_ptr\": \"0x%llx\",\n"
			"        \"max_entries\": %u\n      }",
			r->tail_count++ ? ",\n" : "", e->code.code_id, e->code.from_code_id,
			e->code.pc, e->code.index, (ull)e->code.prog_ptr, (ull)e->code.map_ptr,
			e->code.max_entries);
		break;
	case TRACE_END:
		r->ended = true;
		r->summary = e->summary;
		if (r->events != e->summary.events || r->seq != e->summary.events ||
		    r->steps != e->summary.steps || r->calls != e->summary.calls ||
		    r->region_count != e->summary.regions || r->snapshots != e->summary.snapshots ||
		    r->bytes != e->summary.snapshot_bytes)
			fail(r, REASON_COUNT, TRACE_INCOMPLETE);
		for (__u32 i = 0; i < r->region_count; i++)
			if (!r->regions[i].dead)
				fail(r, REASON_REFERENCE, TRACE_INCOMPLETE);
		finish_run(r);
		break;
	default:
		fail(r, REASON_EVENT, TRACE_INCOMPLETE);
	}
	return output_error ? -output_error : 0;
}

int trace_consumer_open(FILE *fp)
{
	output = fp;
	first_run = true;
	output_error = 0;
	return fprintf(output, "[\n") < 0 ? -EIO : 0;
}

int trace_consumer_close(void)
{
	while (runs)
		finish_run(runs);
	if (fprintf(output, "\n]\n") < 0 || fflush(output) || ferror(output))
		output_error = EIO;
	return -output_error;
}
