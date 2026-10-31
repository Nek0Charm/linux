// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "trace_prog.skel.h"
#include "trace_consumer.h"

#define MAIN_JSON_FILE "bpf_trace_results.json"
static volatile sig_atomic_t exiting;
static FILE *output_fp;

static void sig_handler(int sig)
{
	(void)sig;
	exiting = 1;
}

int main(int argc, char **argv)
{
	struct trace_prog_bpf *skel;
	struct ring_buffer *rb = NULL;
	const char *ready_file;
	char *tmp_out_file;
	FILE *ready_fp;
	int err = 0;

	/* 1. Allow the output file to be specified on the command line. */
	const char *out_file = MAIN_JSON_FILE;
	if (argc > 1) {
		out_file = argv[1];
	}
	tmp_out_file = malloc(strlen(out_file) + sizeof(".tmp"));
	if (!tmp_out_file) {
		fprintf(stderr, "Failed to allocate temporary output path\n");
		return 1;
	}
	sprintf(tmp_out_file, "%s.tmp", out_file);

	/* 2. Handle Ctrl+C (SIGINT) and kill (SIGTERM). */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* 1. Initialize the main JSON file. */
	output_fp = fopen(tmp_out_file, "w");
	if (!output_fp) {
		fprintf(stderr, "Failed to open %s: %s\n",
			tmp_out_file, strerror(errno));
		free(tmp_out_file);
		return 1;
	}
	trace_consumer_open(output_fp);

	/* 2. Open and load the eBPF skeleton. */
	skel = trace_prog_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to load eBPF skeleton\n");
		err = -EINVAL;
		goto cleanup;
	}

	/* 3. Attach to the kernel fentry/fexit points. */
	err = trace_prog_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach eBPF skeleton\n");
		goto cleanup;
	}

	/* 4. Set up the ring buffer and register the callback. */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), trace_consumer_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		err = -ENOMEM;
		goto cleanup;
	}

	ready_file = getenv("TRACE_READY_FILE");
	if (ready_file) {
		ready_fp = fopen(ready_file, "w");
		if (!ready_fp) {
			fprintf(stderr, "Failed to create ready file %s: %s\n",
				ready_file, strerror(errno));
			err = -errno;
			goto cleanup;
		}
		fprintf(ready_fp, "ready\n");
		fclose(ready_fp);
	}

	printf("Tracing BPF programs... Outputting to %s. Hit Ctrl-C to stop.\n", out_file);

	/* 5. Poll continuously and consume data emitted by the kernel. */
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err < 0) {
			if (err == -EINTR) {
				if (exiting) {
					err = 0;
					break;
				}
				continue;
			}
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* After leaving the loop, drain all data remaining in the ring buffer. */
	if (rb) {
		ring_buffer__consume(rb);
	}

	/* Shut down cleanly by closing the JSON array. */
	if (output_fp) {
		if (trace_consumer_close()) {
			fprintf(stderr, "Failed to finish %s: %s\n",
				tmp_out_file, strerror(errno));
			if (!err)
				err = -EIO;
		}
		if (fclose(output_fp) != 0 && !err) {
			fprintf(stderr, "Failed to close %s: %s\n",
				tmp_out_file, strerror(errno));
			err = -errno;
		}
	}
	ring_buffer__free(rb);
	trace_prog_bpf__destroy(skel);
	if (!err && rename(tmp_out_file, out_file) != 0) {
		fprintf(stderr, "Failed to rename %s to %s: %s\n",
			tmp_out_file, out_file, strerror(errno));
		err = -errno;
	}
	free(tmp_out_file);
	return err < 0 ? -err : err;
}
