// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "helper_memory.skel.h"

static void run_case(const char *name)
{
	struct helper_memory *skel;
	struct bpf_program *prog, *selected;
	int key = 0, target, err;
	char packet[64] = {};
	bool needs_tail_target = !strcmp(name, "memory_tail_entry");

	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = packet,
		.data_size_in = sizeof(packet),
		.repeat = 1,
	);

	skel = helper_memory__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;
	/* Filtering must happen before load: a denied budget subtest must not
	 * be verified as a dependency of every ordinary memory subtest.
	 */
	bpf_object__for_each_program(prog, skel->obj) {
		bool enabled = !strcmp(bpf_program__name(prog), name) ||
			(needs_tail_target && prog == skel->progs.memory_tail_target);

		bpf_program__set_autoload(prog, enabled);
	}
	err = helper_memory__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto out;
	if (needs_tail_target) {
		target = bpf_program__fd(skel->progs.memory_tail_target);
		err = bpf_map_update_elem(bpf_map__fd(skel->maps.helper_targets),
					  &key, &target, BPF_ANY);
		if (!ASSERT_OK(err, "tail_target"))
			goto out;
	}
	selected = bpf_object__find_program_by_name(skel->obj, name);
	if (!ASSERT_OK_PTR(selected, "selected_program"))
		goto out;
	err = bpf_prog_test_run_opts(bpf_program__fd(selected), &opts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(opts.retval, 42, "independent_result_and_guards");
out:
	helper_memory__destroy(skel);
}

void test_helper_memory(void)
{
	static const char * const names[] = {
		"memory_no_helper",
		"memory_first_helper",
		"memory_conversions",
		"memory_caller",
		"memory_probe",
		"memory_tail_entry",
		"memory_tail_target",
		"memory_budget",
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(names); i++)
		if (test__start_subtest(names[i]))
			run_case(names[i]);
}
