// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <time.h>
#include <linux/filter.h>
#include "map_helpers.skel.h"

static unsigned long long now_ns(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (unsigned long long)t.tv_sec * 1000000000 + t.tv_nsec;
}

static void run_case(const char *name)
{
	struct map_helpers *skel;
	struct bpf_program *prog, *selected;
	struct bpf_map *map;
	struct bpf_prog_info pi = {};
	struct bpf_map_info mi[8] = {};
	unsigned int map_count = 0;
	unsigned int len, key, size;
	unsigned char input[1023], actual[1023];
	unsigned long long begin = 0, end = 0;
	const char *path = getenv("TRACE_FIXTURE_FILE");
	char packet[64] = {};
	FILE *fp;
	int err;
	bool tail = !strcmp(name, "array_tail");
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = packet, .data_size_in = sizeof(packet), .repeat = 1,
	);

	skel = map_helpers__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;
	bpf_object__for_each_program(prog, skel->obj)
		bpf_program__set_autoload(prog, !strcmp(bpf_program__name(prog), name) ||
			(tail && prog == skel->progs.array_tail_target));
	/* An accidental constant-pool map would invalidate this fixture's
	 * ordinary-array-only premise, including for unrelated subtests.
	 */
	bpf_object__for_each_map(map, skel->obj)
		if (!ASSERT_FALSE(bpf_map__is_internal(map), "no_global_data_maps"))
			goto out;
	err = map_helpers__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto out;
	selected = bpf_object__find_program_by_name(skel->obj, name);
	bpf_object__for_each_map(map, skel->obj) {
		if (bpf_map__type(map) == BPF_MAP_TYPE_PROG_ARRAY) {
			if (tail) {
				int target = bpf_program__fd(skel->progs.array_tail_target);

				key = 0;
				if (!ASSERT_OK(bpf_map_update_elem(bpf_map__fd(map), &key, &target, BPF_ANY), "tail_target"))
					goto out;
			}
		} else {
			size = bpf_map__value_size(map);
			for (key = 0; key < bpf_map__max_entries(map); key++) {
				memset(input, 49 + key, size);
				if (!ASSERT_OK(bpf_map_update_elem(bpf_map__fd(map), &key, input, BPF_ANY), "initialize"))
					goto out;
			}
		}
		len = sizeof(mi[0]);
		if (!ASSERT_LT(map_count, ARRAY_SIZE(mi), "manifest_capacity") ||
		    !ASSERT_OK(bpf_map_get_info_by_fd(bpf_map__fd(map), &mi[map_count], &len), "map_identity"))
			goto out;
		map_count++;
	}
	len = sizeof(pi);
	if (!ASSERT_OK(bpf_prog_get_info_by_fd(bpf_program__fd(selected), &pi, &len), "prog_identity"))
		goto out;
	begin = now_ns();
	err = bpf_prog_test_run_opts(bpf_program__fd(selected), &opts);
	end = now_ns();
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(opts.retval, 42, "independent_bpf_assertions");
	map = !strcmp(name, "array_1022") ? skel->maps.boundary_ok :
		!strcmp(name, "array_1023") ? skel->maps.boundary_over : skel->maps.values;
	size = bpf_map__value_size(map);
	key = 0;
	memset(input, !strcmp(name, "array_alias") || tail ? 49 : 50, size);
	if (tail)
		input[0] = 77;
	if (!strcmp(name, "array_overlap"))
		memset(input, 0, size);
	if (!strcmp(name, "array_key_alias") || !strcmp(name, "array_map_key")) {
		memset(input, 0, size);
		input[0] = 9; input[1] = 8; input[2] = 7;
	}
	if (ASSERT_OK(bpf_map_lookup_elem(bpf_map__fd(map), &key, actual), "final_value"))
		ASSERT_OK(memcmp(input, actual, size), "independent_final_bytes");
	if (tail) {
		memset(input, 49, 13);
		input[12] = 99;
		if (ASSERT_OK(bpf_map_lookup_elem(bpf_map__fd(skel->maps.fresh_values), &key, actual), "tail_fresh_value"))
			ASSERT_OK(memcmp(input, actual, 13), "independent_fresh_bytes");
	}
out:
	map_helpers__destroy(skel);
	if (path && begin && end) {
		fp = fopen(path, "a");
		if (ASSERT_OK_PTR(fp, "manifest")) {
			for (key = 0; key < map_count; key++)
				fprintf(fp, "%u %u %llu %llu 1 %s\n", pi.id, mi[key].id, begin, end,
					mi[key].type == BPF_MAP_TYPE_PROG_ARRAY ? "tail_call" : "ordinary_array");
			ASSERT_OK(fclose(fp), "manifest_close");
		}
	}
}

/* A single-element ordinary ARRAY reached through BPF_PSEUDO_MAP_VALUE,
 * without a preceding lookup or a global-data map.
 */
static void run_direct(void)
{
	struct bpf_insn insns[] = {
		BPF_LD_MAP_VALUE(BPF_REG_1, 0, 0),
		BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, 0),
		BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 49, 3),
		BPF_ST_MEM(BPF_B, BPF_REG_1, 12, 77),
		BPF_MOV64_IMM(BPF_REG_0, 42),
		BPF_EXIT_INSN(),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_EXIT_INSN(),
	};
	struct bpf_prog_info pi = {};
	struct bpf_map_info mi = {};
	unsigned int key = 0, len;
	unsigned char value[13];
	char packet[64] = {};
	unsigned long long begin = 0, end = 0;
	const char *path = getenv("TRACE_FIXTURE_FILE");
	int map_fd = -1, prog_fd = -1;
	FILE *fp;
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = packet, .data_size_in = sizeof(packet), .repeat = 1,
	);

	map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "direct_array", 4, 13, 1, NULL);
	if (!ASSERT_GE(map_fd, 0, "direct_map"))
		goto out;
	memset(value, 49, sizeof(value));
	if (!ASSERT_OK(bpf_map_update_elem(map_fd, &key, value, BPF_ANY), "direct_initialize"))
		goto out;
	insns[0].imm = map_fd;
	prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, "array_direct", "GPL", insns, ARRAY_SIZE(insns), NULL);
	if (!ASSERT_GE(prog_fd, 0, "direct_load"))
		goto out;
	len = sizeof(pi);
	if (!ASSERT_OK(bpf_prog_get_info_by_fd(prog_fd, &pi, &len), "direct_program_identity"))
		goto out;
	len = sizeof(mi);
	if (!ASSERT_OK(bpf_map_get_info_by_fd(map_fd, &mi, &len), "direct_map_identity"))
		goto out;
	begin = now_ns();
	ASSERT_OK(bpf_prog_test_run_opts(prog_fd, &opts), "direct_run");
	end = now_ns();
	ASSERT_EQ(opts.retval, 42, "direct_result");
	if (ASSERT_OK(bpf_map_lookup_elem(map_fd, &key, value), "direct_final_value")) {
		ASSERT_EQ(value[0], 49, "direct_initial_byte");
		ASSERT_EQ(value[12], 77, "direct_written_byte");
	}
out:
	if (prog_fd >= 0)
		close(prog_fd);
	if (map_fd >= 0)
		close(map_fd);
	if (path && begin && end) {
		fp = fopen(path, "a");
		if (ASSERT_OK_PTR(fp, "direct_manifest")) {
			fprintf(fp, "%u %u %llu %llu 1 ordinary_array\n", pi.id, mi.id, begin, end);
			ASSERT_OK(fclose(fp), "direct_manifest_close");
		}
	}
}

void test_map_helpers(void)
{
	const char *names[] = {"array_ops", "array_alias", "array_1022", "array_1023",
		"array_tail", "array_overlap", "array_map_key", "array_key_alias"};
	int i;

	for (i = 0; i < ARRAY_SIZE(names); i++)
		if (test__start_subtest(names[i]))
			run_case(names[i]);
	if (test__start_subtest("array_direct"))
		run_direct();
}
