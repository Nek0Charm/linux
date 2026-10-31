// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} helper_targets SEC(".maps");

SEC("tc")
int memory_no_helper(void *ctx)
{
	return 42;
}

SEC("tc")
__attribute__((naked)) int memory_first_helper(void)
{
	asm volatile("call 7; r0 = 42; exit;" ::: "memory");
}

SEC("tc")
int memory_conversions(void *ctx)
{
	char decimal[8] = "42", negative[8] = "-42", hex[8] = "0x2a";
	char invalid[8] = "x", zero[8] = "0";
	long result;
	unsigned long unsigned_result = 0xaaaa;

	if (bpf_strtol(decimal, sizeof(decimal), 10, &result) != 2 || result != 42)
		return 1;
	if (bpf_strtol(negative, sizeof(negative), 10, &result) != 3 || result != -42)
		return 2;
	if (bpf_strtoul(hex, sizeof(hex), 0, &unsigned_result) != 4 || unsigned_result != 42)
		return 3;
	if (bpf_strtol(invalid, sizeof(invalid), 10, &result) >= 0 || result)
		return 4;
	if (bpf_strtoul(zero, sizeof(zero), 10, &unsigned_result) != 1 || unsigned_result)
		return 5;
	unsigned_result = 0xaaaa;
	if (bpf_strtoul(invalid, sizeof(invalid), 10, &unsigned_result) >= 0 || unsigned_result)
		return 6;
	return 42;
}

/* Initialized stack bytes are an independent oracle for probe_read_kernel.
 * No second invocation of the helper supplies the expected result.
 */
static __noinline int copy_caller_buffer(__u64 *dst, const __u64 *src)
{
	return bpf_probe_read_kernel(dst, 8, src);
}

SEC("tc")
int memory_caller(void *ctx)
{
	__u64 src = 0x123456789abcdef0ULL, dst = 0;

	if (copy_caller_buffer(&dst, &src) || dst != 0x123456789abcdef0ULL)
		return 1;
	/* Reuse the callee stack address with a fresh frame lifetime. */
	src = 0x0123456789abcdefULL;
	if (copy_caller_buffer(&dst, &src) || dst != 0x0123456789abcdefULL)
		return 2;
	return 42;
}

SEC("tc")
int memory_probe(void *ctx)
{
	volatile __u64 src[2];
	volatile struct {
		__u64 before;
		__u64 dst[2];
		__u64 after;
	} output;
	int i;

	/* Individual volatile stores keep the fixture entirely on the stack.
	 * Aggregate initialization can introduce .rodata.cst* maps, which
	 * libbpf binds to every program and capture mode does not support.
	 */
	src[0] = 0x123456789abcdef0ULL;
	src[1] = 0xfedcba9876543210ULL;
	output.before = 0x11223344;
	output.dst[0] = ~0ULL;
	output.dst[1] = ~0ULL;
	output.after = 0x55667788;

#pragma clang loop unroll(disable)
	for (i = 0; i < 4; i++) {
		if (bpf_probe_read_kernel((void *)output.dst, sizeof(src), (const void *)src))
			return 1;
		if (output.dst[0] != 0x123456789abcdef0ULL || output.dst[1] != 0xfedcba9876543210ULL)
			return 2;
	}
	if (bpf_probe_read_kernel((void *)output.dst, 4, (char *)src + 4))
		return 3;
	if ((__u32)output.dst[0] != (__u32)(src[0] >> 32))
		return 4;
	if (bpf_probe_read_kernel((void *)output.dst, sizeof(output.dst), (const void *)0) >= 0)
		return 5;
	if (output.dst[0] || output.dst[1])
		return 6;
	/* A zero length does not bypass the architecture's source-address
	 * checks. Use a valid source to test success and preservation.
	 */
	output.dst[0] = 0xaabbccdd;
	output.dst[1] = 0x11223344;
	if (bpf_probe_read_kernel((void *)output.dst, 0, (const void *)src))
		return 7;
	if (output.dst[0] != 0xaabbccdd || output.dst[1] != 0x11223344)
		return 9;
	if (output.before != 0x11223344 || output.after != 0x55667788)
		return 8;
	return 42;
}

SEC("tc")
int memory_tail_entry(void *ctx)
{
	bpf_tail_call(ctx, &helper_targets, 0);
	return 1;
}

SEC("tc")
int memory_tail_target(void *ctx)
{
	__u64 src = 0x123456789abcdef0ULL, dst;

	if (bpf_probe_read_kernel(&dst, sizeof(dst), &src) || dst != 0x123456789abcdef0ULL)
		return 1;
	return 42;
}

SEC("tc")
__attribute__((naked)) int memory_budget(void)
{
	/* Exercise the dynamic capture limit without a verifier loop. Even a
	 * bounded increasing loop exceeds the verifier's complexity budget
	 * with the capture mode's strict speculation checks. 1102 static
	 * instruction slots still fit TRACE_MAX_INSNS (2048).
	 */
	asm volatile(".rept 1100;"
		     "call 7;"
		     ".endr;"
		     "r0 = 42;"
		     "exit;" ::: "memory");
}
