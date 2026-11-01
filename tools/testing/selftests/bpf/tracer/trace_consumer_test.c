// SPDX-License-Identifier: GPL-2.0
#include <assert.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>
#include "trace_common.h"
#include "trace_consumer.h"

static void send_event(struct bpf_trace_event *event)
{
	assert(trace_consumer_event(NULL, event, sizeof(*event)) == 0);
}

static void map_run(unsigned int id)
{
	struct evt_code code = {};
	struct evt_memory memory = {};
	struct bpf_trace_event event = {};
	struct trace_region map = {
		.region_id = 1, .type = TRACE_MAP_FD, .base_addr = 0x1000,
	};
	struct trace_region value = {
		.region_id = 2, .type = TRACE_MAP_VALUE, .base_addr = 0x2000,
		.size = 4, .map_id = 1, .entry_id = 1,
		.permissions = TRACE_READ | TRACE_WRITE,
	};

	code.event.hdr = (struct trace_hdr) {
		.run_id = id, .seq = 1, .type = TRACE_START,
	};
	code.event.code.time_ns = 100;
	code.prog_id = 42;
	code.insn_cnt = 1;
	code.insns[0].code = BPF_JMP | BPF_EXIT;
	assert(trace_consumer_event(NULL, &code, sizeof(code)) == 0);
	event.hdr = (struct trace_hdr) {
		.run_id = id, .seq = 2, .type = TRACE_REGION,
	};
	event.region = map;
	send_event(&event);
	event.hdr.seq = 3;
	event.hdr.type = TRACE_MAP;
	event.map = (struct trace_map) {
		.map_id = 1, .kernel_map_id = id, .map_region_id = 1,
		.address = 0x1000, .map_type = BPF_MAP_TYPE_ARRAY,
		.max_entries = 1, .key_size = 4, .value_size = 4,
		.value_stride = 8, .supported = 1,
	};
	send_event(&event);
	event.hdr.seq = 4;
	event.hdr.type = TRACE_REGION;
	event.region = value;
	send_event(&event);
	memory.event.hdr = (struct trace_hdr) {
		.run_id = id, .seq = 5, .type = TRACE_MEMORY,
	};
	memory.event.memory = (struct trace_memory) {
		.address = 0x2000, .read_address = 0x2000,
		.region_id = 2, .snapshot_id = 1, .map_id = 1,
		.phase = TRACE_INITIAL_MEMORY, .length = 4, .valid_length = 4,
	};
	memcpy(memory.bytes, "abcd", 4);
	assert(trace_consumer_event(NULL, &memory, sizeof(memory)) == 0);
	event.hdr.seq = 6;
	event.hdr.type = TRACE_REGION_END;
	event.region = value;
	send_event(&event);
	event.hdr.seq = 7;
	event.region = map;
	send_event(&event);
	event.hdr.seq = 8;
	event.hdr.type = TRACE_END;
	event.summary = (struct trace_summary) {
		.events = 8, .regions = 2, .snapshots = 1,
		.snapshot_bytes = 4, .time_ns = 200, .ret = 42,
	};
	send_event(&event);
}

static void check_results(FILE *fp, unsigned int count, const char *status)
{
	char line[512], expected[80];
	unsigned int statuses = 0, assumptions = 0;

	snprintf(expected, sizeof(expected), "\"capture_status\": \"%s\"", status);
	rewind(fp);
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "\"capture_status\": ")) {
			assert(strstr(line, expected));
			statuses++;
		}
		if (strstr(line, "\"execution_assumption\": \"exclusive_fixture\""))
			assumptions++;
	}
	assert(!ferror(fp));
	assert(statuses == count);
	assert(assumptions == (!strcmp(status, "complete") ? count : 0));
}

static void completed_maps(bool manifest_matches)
{
	char path[] = "/tmp/trace-consumer-fixture-XXXXXX";
	struct rlimit old_limit, limit;
	FILE *output = tmpfile(), *manifest;
	int fd = mkstemp(path);

	assert(output && fd >= 0);
	assert(close(fd) == 0);
	assert(setenv("TRACE_FIXTURE_FILE", path, 1) == 0);
	assert(getrlimit(RLIMIT_NOFILE, &old_limit) == 0);
	limit = old_limit;
	if (limit.rlim_cur > 64)
		limit.rlim_cur = 64;
	assert(setrlimit(RLIMIT_NOFILE, &limit) == 0);
	assert(trace_consumer_open(output) == 0);
	for (unsigned int id = 1; id <= 40; id++)
		map_run(id);
	/* Match the real fixture: publish only after every run has ended. */
	manifest = fopen(path, "w");
	assert(manifest);
	for (unsigned int id = 1; id <= 40; id++)
		fprintf(manifest, "%u %u 50 250 1 ordinary_array\n",
			manifest_matches ? 42 : 43, id);
	assert(fclose(manifest) == 0);
	assert(trace_consumer_close() == 0);
	assert(setrlimit(RLIMIT_NOFILE, &old_limit) == 0);
	check_results(output, 40, manifest_matches ? "complete" : "unsupported");
	assert(fclose(output) == 0);
	assert(unlink(path) == 0);
	assert(unsetenv("TRACE_FIXTURE_FILE") == 0);
}

static void missing_end(void)
{
	struct evt_code code = {};
	FILE *output = tmpfile();

	assert(output);
	assert(trace_consumer_open(output) == 0);
	code.event.hdr = (struct trace_hdr) {
		.run_id = 1, .seq = 1, .type = TRACE_START,
	};
	code.insn_cnt = 1;
	code.insns[0].code = BPF_JMP | BPF_EXIT;
	assert(trace_consumer_event(NULL, &code, sizeof(code)) == 0);
	assert(trace_consumer_close() == 0);
	check_results(output, 1, "incomplete");
	assert(fclose(output) == 0);
}

static void unused_tail_map(void)
{
	struct evt_code code = {};
	struct bpf_trace_event event = {};
	FILE *output = tmpfile();
	char line[512];
	bool map_ptr = false, max_entries = false;

	assert(output);
	assert(trace_consumer_open(output) == 0);
	code.event.hdr = (struct trace_hdr) {
		.run_id = 1, .seq = 1, .type = TRACE_START,
	};
	code.insn_cnt = 1;
	code.insns[0].code = BPF_JMP | BPF_EXIT;
	assert(trace_consumer_event(NULL, &code, sizeof(code)) == 0);
	event.hdr = (struct trace_hdr) {
		.run_id = 1, .seq = 2, .type = TRACE_REGION,
	};
	event.region = (struct trace_region) {
		.region_id = 1, .type = TRACE_MAP_FD, .base_addr = 0x4000,
	};
	send_event(&event);
	event.hdr.seq = 3;
	event.hdr.type = TRACE_MAP;
	event.map = (struct trace_map) {
		.map_id = 1, .kernel_map_id = 1, .map_region_id = 1,
		.address = 0x4000, .map_type = BPF_MAP_TYPE_PROG_ARRAY,
		.max_entries = 8,
	};
	send_event(&event);
	assert(trace_consumer_close() == 0);
	rewind(output);
	while (fgets(line, sizeof(line), output)) {
		map_ptr |= strstr(line, "\"jmp_map_ptr\": \"0x4000\"") != NULL;
		max_entries |= strstr(line, "\"jmp_max_entries\": 8") != NULL;
	}
	assert(!ferror(output));
	assert(map_ptr && max_entries);
	assert(fclose(output) == 0);
}

int main(void)
{
	completed_maps(true);
	completed_maps(false);
	missing_end();
	unused_tail_map();
	puts("trace_consumer tests passed");
	return 0;
}
