#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "trace_common.h"
#include "trace_prog.skel.h" // 由 bpftool gen skeleton 生成

#define MAIN_JSON_FILE "bpf_trace_results.json"

/* 用链表维护当前正在活跃的 run_id 会话 */
struct active_run {
	__u64 run_id;
	FILE *tmp_fp;
	char tmp_filename[64];
	bool is_first_step;
	struct active_run *next;
};

static struct active_run *run_list_head = NULL;
static FILE *main_json_fp = NULL;
static bool is_first_run_in_main = true;

/* 查找或创建活跃会话 */
static struct active_run *get_or_create_run(__u64 run_id) {
	struct active_run *curr = run_list_head;
	while (curr) {
		if (curr->run_id == run_id) return curr;
		curr = curr->next;
	}
	
	// 创建新会话
	struct active_run *new_run = malloc(sizeof(*new_run));
	new_run->run_id = run_id;
	new_run->is_first_step = true;
	snprintf(new_run->tmp_filename, sizeof(new_run->tmp_filename), "/tmp/bpf_run_%llu.tmp", run_id);
	new_run->tmp_fp = fopen(new_run->tmp_filename, "w+");
	
	new_run->next = run_list_head;
	run_list_head = new_run;
	return new_run;
}

/* 移除并销毁活跃会话 */
static void remove_run(__u64 run_id) {
	struct active_run *curr = run_list_head, *prev = NULL;
	while (curr) {
		if (curr->run_id == run_id) {
			if (prev) prev->next = curr->next;
			else run_list_head = curr->next;
			
			fclose(curr->tmp_fp);
			unlink(curr->tmp_filename); // 删除临时文件
			free(curr);
			return;
		}
		prev = curr;
		curr = curr->next;
	}
}

/* 核心回调：处理 Ring Buffer 中的每一个事件 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct trace_hdr *hdr = data;
	struct active_run *run = NULL;

	if (hdr->type == EVT_PROG_START) {
		struct evt_prog_start *evt = data;
		run = get_or_create_run(hdr->run_id);
		
		/* 2. 将这次执行的基础信息和静态指令写入它的专属临时文件 */
		fprintf(run->tmp_fp, "  {\n");
		fprintf(run->tmp_fp, "    \"run_id\": %llu,\n", hdr->run_id);
		fprintf(run->tmp_fp, "    \"prog_id\": %u,\n", evt->prog_id);
		fprintf(run->tmp_fp, "    \"prog_name\": \"%s\",\n", evt->prog_name);
		fprintf(run->tmp_fp, "    \"prog_insn_cnt\": %u,\n", evt->insn_cnt);
		
		// 打印静态指令数组 (prog_insn)
		fprintf(run->tmp_fp, "    \"prog_insn\": [\n");
		__u32 print_cnt = (evt->insn_cnt > MAX_INSN_DUMP) ? MAX_INSN_DUMP : evt->insn_cnt;
		for (__u32 i = 0; i < print_cnt; i++) {
			fprintf(run->tmp_fp, "      \"0x%llX\"%s\n",
				evt->insns[i], (i == print_cnt - 1) ? "" : ",");
		}
		fprintf(run->tmp_fp, "    ],\n");
		fprintf(run->tmp_fp, "    \"trace\": [\n");
		
	} else if (hdr->type == EVT_TRACE_STEP) {
		struct evt_trace_step *evt = data;
		run = get_or_create_run(hdr->run_id); // 以防万一 START 丢包
		
		if (!run->is_first_step) {
			fprintf(run->tmp_fp, ",\n");
		}
		run->is_first_step = false;
		
		/* 打印寄存器快照 */
		fprintf(run->tmp_fp, "      [");
		for (int i = 0; i <= 11; i++) {
			fprintf(run->tmp_fp, "\"0x%llX\"%s", evt->regs[i], (i == 11) ? "" : ", ");
		}
		fprintf(run->tmp_fp, "]");

	} else if (hdr->type == EVT_PROG_END) {
		struct evt_prog_end *evt = data;
		run = get_or_create_run(hdr->run_id);
		
		/* 1. 闭合当前 run 的 JSON 结构 */
		fprintf(run->tmp_fp, "\n    ]\n  }");
		fflush(run->tmp_fp);
		
		/* 2. 将完整的这个 Run 合并到总 JSON 文件中 */
		if (!is_first_run_in_main) {
			fprintf(main_json_fp, ",\n");
		}
		is_first_run_in_main = false;
		
		rewind(run->tmp_fp); // 回到临时文件开头
		char buffer[4096];
		size_t bytes;
		while ((bytes = fread(buffer, 1, sizeof(buffer), run->tmp_fp)) > 0) {
			fwrite(buffer, 1, bytes, main_json_fp);
		}
		fflush(main_json_fp);
		
		/* 3. 清理会话和临时文件 */
		remove_run(hdr->run_id);
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct trace_prog_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;

	/* 1. 初始化总 JSON 文件 */
	main_json_fp = fopen(MAIN_JSON_FILE, "w");
	fprintf(main_json_fp, "[\n"); // 数组开头

	/* 2. 打开并加载 eBPF 骨架 */
	skel = trace_prog_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to load eBPF skeleton\n");
		return 1;
	}

	/* 3. 挂载 (Attach) 到内核的 fentry/fexit 点 */
	err = trace_prog_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach eBPF skeleton\n");
		goto cleanup;
	}

	/* 4. 设置 Ring Buffer，注册回调函数 */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	printf("Tracing BPF programs... Outputting to %s. Hit Ctrl-C to stop.\n", MAIN_JSON_FILE);

	/* 5. 持续轮询，消费内核吐出的数据 */
	while (1) {
		err = ring_buffer__poll(rb, 100 /* 超时时间 ms */);
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* 优雅退出：闭合 JSON 数组 */
	if (main_json_fp) {
		fprintf(main_json_fp, "\n]\n");
		fclose(main_json_fp);
	}
	ring_buffer__free(rb);
	trace_prog_bpf__destroy(skel);
	return -err;
}