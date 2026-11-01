// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define ARRAY(name, size, count) \
struct { \
	__uint(type, BPF_MAP_TYPE_ARRAY); \
	__uint(max_entries, count); \
	__type(key, __u32); \
	__type(value, unsigned char[size]); \
} name SEC(".maps")

ARRAY(values, 13, 3);
ARRAY(boundary_ok, 1022, 2);
ARRAY(boundary_over, 1023, 2);
ARRAY(fresh_values, 13, 2);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} map_targets SEC(".maps");

/* Volatile byte stores prevent LLVM from materializing a .rodata map for
 * this stack initializer. Global data is outside the ordinary ARRAY fixture.
 */
static __always_inline void fill_input(unsigned char *input)
{
	int i;

#pragma unroll
	for (i = 0; i < 13; i++)
		*(volatile unsigned char *)&input[i] = i < 3 ? 9 - i : 0;
}

static __noinline int change(unsigned char *old)
{
	__u32 key = 0;
	unsigned char input[13];

	fill_input(input);
	old[12] = 77;
	if (bpf_map_update_elem(&values, &key, input, BPF_ANY))
		return 1;
	return old[0] != 9 || old[12] != 0;
}

SEC("socket")
int array_ops(void *ctx)
{
	__u32 key = 0, other = 1, bad = 3;
	unsigned char input[13];
	unsigned char *p = bpf_map_lookup_elem(&values, &key);
	unsigned char *q;

	fill_input(input);
	if (!p || p[0] != 49 || p[12] != 49 || change(p))
		return 1;
	q = bpf_map_lookup_elem(&values, &key);
	if (!q || q[0] != 9 || p[0] != 9)
		return 2;
	if (bpf_map_update_elem(&values, &key, input, BPF_EXIST) ||
	    bpf_map_update_elem(&values, &key, input, BPF_NOEXIST) != -17 ||
	    bpf_map_update_elem(&values, &key, input, 8) != -22 ||
	    bpf_map_update_elem(&values, &bad, input, BPF_ANY) != -7 ||
	    bpf_map_delete_elem(&values, &key) != -22 ||
	    bpf_map_lookup_elem(&values, &bad))
		return 3;
	q = bpf_map_lookup_elem(&values, &other);
	if (!q || bpf_map_update_elem(&values, &key, q, BPF_ANY) || p[0] != 50)
		return 4;
	return 42;
}

SEC("socket")
int array_alias(void *ctx)
{
	__u32 key = 0;
	unsigned char *p = bpf_map_lookup_elem(&values, &key);

	if (!p || bpf_map_update_elem(&values, &key, p, BPF_ANY))
		return 1;
	return 42;
}

#define BOUNDARY(prog, map) \
SEC("socket") int prog(void *ctx) \
{ \
	__u32 key = 1, target = 0; \
	void *p = bpf_map_lookup_elem(&map, &key); \
	if (!p || bpf_map_update_elem(&map, &target, p, BPF_ANY)) \
		return 1; \
	return 42; \
}
BOUNDARY(array_1022, boundary_ok)
BOUNDARY(array_1023, boundary_over)
SEC("socket")
int array_tail_target(void *ctx)
{
	__u32 key = 0;
	unsigned char *shared = bpf_map_lookup_elem(&values, &key);
	unsigned char *fresh = bpf_map_lookup_elem(&fresh_values, &key);

	if (!shared || !fresh || shared[0] != 77 || fresh[0] != 49)
		return 1;
	fresh[12] = 99;
	return 42;
}

SEC("socket")
int array_tail(void *ctx)
{
	__u32 key = 0;
	unsigned char *p = bpf_map_lookup_elem(&values, &key);

	if (!p || p[0] != 49)
		return 1;
	p[0] = 77;
	bpf_tail_call(ctx, &map_targets, 0);
	return 2;
}

/* Key/input overlap is supported when neither buffer overlaps the target. */
SEC("socket")
int array_overlap(void *ctx)
{
	unsigned char input[13];
	__u32 key = 0;
	unsigned char *p;

	fill_input(input);
	*(volatile unsigned char *)&input[0] = 0;
	*(volatile unsigned char *)&input[1] = 0;
	*(volatile unsigned char *)&input[2] = 0;
	if (bpf_map_update_elem(&values, input, input, BPF_ANY))
		return 1;
	p = bpf_map_lookup_elem(&values, &key);
	return p && p[0] == 0 && p[12] == 0 ? 42 : 2;
}

/* The key comes from a different registered element. */
SEC("socket")
int array_map_key(void *ctx)
{
	__u32 key = 1, target = 0;
	unsigned char input[13];
	unsigned char *p = bpf_map_lookup_elem(&values, &key);
	unsigned char *q;

	if (!p)
		return 1;
	fill_input(input);
	/* The byte array's BTF alignment is one, so use byte stores. */
	p[0] = 0; p[1] = 0; p[2] = 0; p[3] = 0;
	if (bpf_map_update_elem(&values, p, input, BPF_ANY))
		return 2;
	q = bpf_map_lookup_elem(&values, &target);
	return q && q[0] == 9 && q[12] == 0 ? 42 : 3;
}

/* Even with a separate stack input, a key inside the target is unsupported. */
SEC("socket")
int array_key_alias(void *ctx)
{
	__u32 key = 0;
	unsigned char input[13];
	unsigned char *p = bpf_map_lookup_elem(&values, &key);

	if (!p)
		return 1;
	fill_input(input);
	p[0] = 0; p[1] = 0; p[2] = 0; p[3] = 0;
	return bpf_map_update_elem(&values, p, input, BPF_ANY) ? 2 : 42;
}

char LICENSE[] SEC("license") = "GPL";
