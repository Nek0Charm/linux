#include <errno.h>
#include <signal.h>
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
#define MAX_CALL_RECORD 64
#define MAX_TAILCALL_RECORD 64

struct tailcall_record {
	__u32 pc;
	__u64 map_ptr;
	__u32 index;
	__u64 prog_ptr;
	__u32 insn_cnt;
	struct bpf_insn insns[MAX_INSN_DUMP];
};

/* 用链表维护当前正在活跃的 run_id 会话 */
struct active_run {
	__u64 run_id;
	FILE *tmp_fp;
	char tmp_filename[64];
	bool is_first_step;
	/* 新增：状态机追踪标志 */
	bool has_started;
	bool is_corrupted;
	/* 新增：缓存当前执行流中的所有 bpf2bpf call SP */
	__u64 sp_list[MAX_CALL_RECORD];
	int sp_cnt;
	/* 新增：缓存所有的尾调用信息 */
	struct tailcall_record jmp_table[MAX_TAILCALL_RECORD];
	int jmp_cnt;
	int jmp_max_entries; // 临时
	__u64 jmp_map_ptr;   // 临时
	struct active_run *next;
};

static struct active_run *run_list_head = NULL;
static FILE *main_json_fp = NULL;
static bool is_first_run_in_main = true;
static volatile bool exiting = false;

static const char *drop_reason_name(__u32 reason)
{
	switch (reason) {
	case TRACE_DROP_UNSUPPORTED_TAIL_TARGET:
		return "unsupported tail-call target";
	case TRACE_DROP_TAIL_COUNT_DIVERGENCE:
		return "tail-call counter divergence";
	case TRACE_DROP_CTX_INDIRECTION:
		return "unmodeled context-pointer indirection";
	case TRACE_DROP_HELPER_MEMORY_SIDE_EFFECT:
		return "unmodeled helper memory side effect";
	case TRACE_DROP_CTX_INTERNAL_STATE:
		return "unmodeled kernel context state";
	default:
		return "unknown";
	}
}

static void sig_handler(int sig)
{
	exiting = true;
}

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
	new_run->has_started = false;  // <--- 新增
	new_run->is_corrupted = false; // <--- 新增
	new_run->sp_cnt = 0; // 初始化内部调用计数
	new_run->jmp_cnt = 0;
	new_run->jmp_max_entries = 0;
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
		
		run->has_started = true; // 标记正常启动

		/* 2. 将这次执行的基础信息和静态指令写入它的专属临时文件 */
		fprintf(run->tmp_fp, "  {\n");
		fprintf(run->tmp_fp, "    \"run_id\": %llu,\n", hdr->run_id);
		fprintf(run->tmp_fp, "    \"prog_id\": %u,\n", evt->prog_id);
		fprintf(run->tmp_fp, "    \"prog_name\": \"%s\",\n", evt->prog_name);
		fprintf(run->tmp_fp, "    \"prog_insn_cnt\": %u,\n", evt->insn_cnt);
		fprintf(run->tmp_fp, "    \"ctx_ptr\": \"0x%llX\",\n", evt->ctx_ptr);
		/* 记录内部调用的 SP 到内存数组，拦截其进入 trace 流 */
		if (run->sp_cnt < MAX_CALL_RECORD) {
			run->sp_list[run->sp_cnt++] = evt->sp;
		}

		/* ================= 新增：输出 mem_blocks ================= */
		fprintf(run->tmp_fp, "    \"mem_blocks\": [\n");
		for (__u32 i = 0; i < evt->block_cnt; i++) {
			fprintf(run->tmp_fp, "      {\n");
			fprintf(run->tmp_fp, "        \"base_addr\": \"0x%llX\",\n", (unsigned long long)evt->blocks[i].base_addr);
			fprintf(run->tmp_fp, "        \"size\": %u,\n", evt->blocks[i].size);
			fprintf(run->tmp_fp, "        \"type\": \"%s\"\n", evt->blocks[i].is_direct_value ? "map_value" : "map_fd");
			fprintf(run->tmp_fp, "      }%s\n", (i == evt->block_cnt - 1) ? "" : ",");
		}
		fprintf(run->tmp_fp, "    ],\n");
		/* ========================================================= */

		// 打印静态指令数组 (prog_insn)
		fprintf(run->tmp_fp, "    \"prog_insn\": [\n");
		__u32 print_cnt = (evt->insn_cnt > MAX_INSN_DUMP) ? MAX_INSN_DUMP : evt->insn_cnt;
		for (__u32 i = 0; i < print_cnt; i++) {
			__u64 raw_insn;

			memcpy(&raw_insn, &evt->insns[i], sizeof(raw_insn));
			fprintf(run->tmp_fp, "      \"0x%llX\"%s\n",
				(unsigned long long)raw_insn,
				(i == print_cnt - 1) ? "" : ",");
		}
		fprintf(run->tmp_fp, "    ],\n");
		fprintf(run->tmp_fp, "    \"trace\": [\n");
		
	} else if (hdr->type == EVT_TRACE_STEP) {
		struct evt_trace_step *evt = data;
		run = get_or_create_run(hdr->run_id); // 以防万一 START 丢包
		
		/* 容错：如果未收到过 START，说明丢包了，标记损坏并跳过 */
		if (!run->has_started) {
			if (!run->is_corrupted) {
				fprintf(stderr, "[Warning] RingBuf Overflow: run_id %llu missing START. Trace will be discarded.\n", hdr->run_id);
				run->is_corrupted = true;
			}
			return 0;
		}
		if (run->is_corrupted) return 0;

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
		run = get_or_create_run(hdr->run_id);

		/* 如果整个生命周期没有 START，或者已经被标记损坏 */
		if (!run->has_started) run->is_corrupted = true;
		
		if (run->is_corrupted) {
			/* 致命错误隔离：绝对不写入闭合标签，绝对不合并到主 JSON */
			fprintf(stderr, "[Drop] Corrupted trace for run_id %llu discarded cleanly.\n", hdr->run_id);
			remove_run(hdr->run_id); // 这会关闭并 unlink 临时文件
			return 0;
		}
		
		/* 1. 先闭合 trace 的纯净数组 */
		fprintf(run->tmp_fp, "\n    ],\n");
		
		/* 2. 生成平级的 sp_list 数组 */
		fprintf(run->tmp_fp, "    \"sp_list\": [");
		for (int i = 0; i < run->sp_cnt; i++) {
			fprintf(run->tmp_fp, "\"0x%llX\"%s", 
				run->sp_list[i], 
				(i == run->sp_cnt - 1) ? "" : ", ");
		}
		
		fprintf(run->tmp_fp, "],\n"); // 注意这里加了逗号
		
		/* 3. 生成平级的 jmp_table 数组 */
		fprintf(run->tmp_fp, "    \"jmp_max_entries\": %d,\n", run->jmp_max_entries);
		fprintf(run->tmp_fp, "    \"jmp_map_ptr\": \"0x%llX\",\n", run->jmp_map_ptr);
		fprintf(run->tmp_fp, "    \"jmp_table\": [\n");
		for (int i = 0; i < run->jmp_cnt; i++) {
			struct tailcall_record *rec = &run->jmp_table[i];
			
			fprintf(run->tmp_fp, "      {\n");
			fprintf(run->tmp_fp, "        \"pc\": %u,\n", rec->pc);
			// fprintf(run->tmp_fp, "        \"map_ptr\": \"0x%llX\",\n", (unsigned long long)rec->map_ptr);
			fprintf(run->tmp_fp, "        \"index\": %u,\n", rec->index);
			fprintf(run->tmp_fp, "        \"target\": \"0x%llX\",\n", (unsigned long long)rec->prog_ptr);
			fprintf(run->tmp_fp, "        \"insns\": [\n");
			        
			__u32 print_cnt = rec->insn_cnt > MAX_INSN_DUMP ? MAX_INSN_DUMP : rec->insn_cnt;
			for (__u32 j = 0; j < print_cnt; j++) {
				__u64 raw_insn;

				memcpy(&raw_insn, &rec->insns[j], sizeof(raw_insn));
				fprintf(run->tmp_fp, "          \"0x%llX\"%s\n", 
				        (unsigned long long)raw_insn, 
				        (j == print_cnt - 1) ? "" : ",");
			}
			/* 闭合 insns 数组和对象 */
			fprintf(run->tmp_fp, "        ]\n      }%s\n", (i == run->jmp_cnt - 1) ? "" : ",");
		}
		fprintf(run->tmp_fp, "    ]\n  }");
		fflush(run->tmp_fp);
		
		/* 3. 将完整的这个 Run 合并到总 JSON 文件中 */
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
	} else if (hdr->type == EVT_PROG_CALL) {
		struct evt_prog_call *evt = data;
		run = get_or_create_run(hdr->run_id); 
		
		if (!run->has_started) run->is_corrupted = true;
		if (run->is_corrupted) return 0;

		/* 记录内部调用的 SP 到内存数组，拦截其进入 trace 流 */
		if (run->sp_cnt < MAX_CALL_RECORD) {
			run->sp_list[run->sp_cnt++] = evt->sp;
		}
	} else if (hdr->type == EVT_PROG_TAILCALL) {
		struct evt_prog_tailcall *evt = data;
		run = get_or_create_run(hdr->run_id); 
		
		if (!run->has_started) run->is_corrupted = true;
		if (run->is_corrupted) return 0;
		
		/* 记录 Tail Call 目标到内存数组 */
		if (run->jmp_cnt < MAX_TAILCALL_RECORD) {
			struct tailcall_record *rec = &run->jmp_table[run->jmp_cnt++];
			rec->pc = evt->pc;
			rec->map_ptr = evt->map_ptr;
			rec->index = evt->index;
			rec->prog_ptr = evt->prog_ptr;
			rec->insn_cnt = evt->insn_cnt;
			__u32 copy_cnt = evt->insn_cnt > MAX_INSN_DUMP ? MAX_INSN_DUMP : evt->insn_cnt;
			memcpy(rec->insns, evt->insns, copy_cnt * sizeof(struct bpf_insn));
		}
	} else if (hdr->type == EVT_PROG_TAILCALL_MAP) {
		struct evt_prog_tailcall_map *evt = data;
		run = get_or_create_run(hdr->run_id);
		
		if (!run->has_started) run->is_corrupted = true;
		if (run->is_corrupted) return 0;
		
		run->jmp_map_ptr = evt->map_ptr;
		run->jmp_max_entries = evt->max_entries;
	} else if (hdr->type == EVT_PROG_DROP) {
		struct evt_prog_drop *evt = data;

		fprintf(stderr,
			"[Drop] run_id %llu skipped by observer: %s (reason %u).\n",
			(unsigned long long)hdr->run_id,
			drop_reason_name(evt->reason), evt->reason);
		remove_run(hdr->run_id);
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct trace_prog_bpf *skel;
	struct ring_buffer *rb = NULL;
	const char *ready_file;
	char *tmp_out_file;
	FILE *ready_fp;
	int err = 0;

	/* 1. 支持通过命令行参数指定输出文件 */
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

	/* 2. 捕获 Ctrl+C (SIGINT) 和 kill (SIGTERM) 信号 */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* 1. 初始化总 JSON 文件 */
	main_json_fp = fopen(tmp_out_file, "w");
	if (!main_json_fp) {
		fprintf(stderr, "Failed to open %s: %s\n",
			tmp_out_file, strerror(errno));
		free(tmp_out_file);
		return 1;
	}
	fprintf(main_json_fp, "[\n"); // 数组开头

	/* 2. 打开并加载 eBPF 骨架 */
	skel = trace_prog_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to load eBPF skeleton\n");
		err = -EINVAL;
		goto cleanup;
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

	/* 5. 持续轮询，消费内核吐出的数据 */
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
	/* 核心修复：退出循环后，一口气把 Ring Buffer 里残留的数据全部强行拉取完 */
	if (rb) {
		ring_buffer__consume(rb);
	}

	/* 优雅退出：闭合 JSON 数组 */
	if (main_json_fp) {
		if (fprintf(main_json_fp, "\n]\n") < 0 ||
		    fflush(main_json_fp) != 0) {
			fprintf(stderr, "Failed to finish %s: %s\n",
				tmp_out_file, strerror(errno));
			if (!err)
				err = -EIO;
		}
		if (fclose(main_json_fp) != 0 && !err) {
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
