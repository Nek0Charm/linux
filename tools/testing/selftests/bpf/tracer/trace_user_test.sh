#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
set -Eeuo pipefail

TRACER_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TEMP_DIR}"' EXIT

# Compile the real main and consumer with a fake BPF transport. Copy main so
# its quoted skeleton include resolves to the stub even in a built tree.
cp "${TRACE_USER_SOURCE:-${TRACER_DIR}/trace_user.c}" "${TEMP_DIR}/trace_user.c"
mkdir -p "${TEMP_DIR}/bpf"
touch "${TEMP_DIR}/bpf/libbpf.h" "${TEMP_DIR}/bpf/bpf.h"
cat > "${TEMP_DIR}/trace_prog.skel.h" <<'EOF'
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

struct bpf_map { int fd; };
struct ring_buffer { int fd; };
struct trace_prog_bpf { struct { struct bpf_map *rb; } maps; };

static inline struct trace_prog_bpf *trace_prog_bpf__open_and_load(void)
{
	static struct bpf_map map;
	static struct trace_prog_bpf skel = { .maps.rb = &map };

	return &skel;
}

static inline int trace_prog_bpf__attach(struct trace_prog_bpf *skel)
{
	(void)skel;
	return 0;
}

static inline void trace_prog_bpf__destroy(struct trace_prog_bpf *skel)
{
	(void)skel;
}

static inline int bpf_map__fd(const struct bpf_map *map)
{
	(void)map;
	return 1;
}

static inline struct ring_buffer *ring_buffer__new(int fd,
	int (*callback)(void *, void *, size_t), void *ctx, const void *opts)
{
	static struct ring_buffer rb;

	(void)fd;
	(void)callback;
	(void)ctx;
	(void)opts;
	return &rb;
}

static inline int ring_buffer__poll(struct ring_buffer *rb, int timeout)
{
	const char *scenario = getenv("TRACE_TEST_CASE");
	static unsigned int calls;

	(void)rb;
	(void)timeout;
	if (!strcmp(scenario, "error"))
		return -EIO;
	if (!strcmp(scenario, "retry") && !calls++)
		return -EINTR;
	/* Deliver SIGINT during the last poll, before its result is handled. */
	raise(SIGINT);
	if (!strcmp(scenario, "interrupted"))
		return -EINTR;
	return !strcmp(scenario, "zero") ? 0 : 3077;
}

static inline int ring_buffer__consume(struct ring_buffer *rb)
{
	(void)rb;
	return 0;
}

static inline void ring_buffer__free(struct ring_buffer *rb)
{
	(void)rb;
}
EOF

read -r -a compiler <<< "${CC:-cc}"
read -r -a flags <<< "${CFLAGS:--g -O2 -Wall -Wextra -Werror}"
"${compiler[@]}" -I"${TEMP_DIR}" -I"${TRACER_DIR}" "${flags[@]}" \
	"${TEMP_DIR}/trace_user.c" "${TRACER_DIR}/trace_consumer.c" -o "${TEMP_DIR}/trace_user"
printf '[\n\n]\n' > "${TEMP_DIR}/expected.json"
for scenario in positive zero interrupted retry; do
	output="${TEMP_DIR}/${scenario}.json"
	TRACE_TEST_CASE="${scenario}" "${TEMP_DIR}/trace_user" "${output}" > "${output}.log" 2>&1
	test ! -e "${output}.tmp"
	cmp "${TEMP_DIR}/expected.json" "${output}"
done

output="${TEMP_DIR}/error.json"
if TRACE_TEST_CASE=error "${TEMP_DIR}/trace_user" "${output}" > "${output}.log" 2>&1; then
	echo "Expected a failed poll to preserve a nonzero exit status" >&2
	exit 1
else
	test "$?" -eq 5
fi
test ! -e "${output}"
cmp "${TEMP_DIR}/expected.json" "${output}.tmp"
echo "trace_user shutdown tests passed"
