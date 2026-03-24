# BPF Trace Recorder

## How to use

1. First, goto the `tools/testing/selftests/bpf/tracer` directory and build.

```shell
cd tools/testing/selftests/bpf/tracer
make
```

2. Then, press `F5` to start the VM.

3. Finally in VM, goto the directory.

```bash
cd /host/home/tyz/Workspace/.../tools/testing/selftests/bpf/tracer
chmod +x ./run_traces.sh
./run_traces.sh
chmod +x ./run_test_bpf.sh
./run_test_bpf.sh
```

## Overview

This project is composed of kernel part and user part.

### Kernel part: define BPF hooks

The following 4 hooks are defined and used in `core.c`.

```c
void bpf_interp_hook_start(u64 run_id, const struct bpf_prog *prog, u64 ctx_ptr, u64 fp);
void bpf_interp_hook_step(u64 run_id, const u64 *regs);
void bpf_interp_hook_end(u64 run_id, u64 ret);
void bpf_interp_hook_call(u64 run_id, u64 fp);
```

The following 2 hooks need to be removed later.

```c
void bpf_interp_hook_tailcall(u64 run_id, const struct bpf_prog *prog, u32 pc, u64 map_ptr, u32 index);
void bpf_interp_hook_tailcall_map(u64 run_id, const struct bpf_map * map_ptr); // 临时解决方案
```

### User part

* `trace_common.h`: Struct and constant definition.
* `trace_prog.bpf.c`: Define BPF programs, which would be attached to the new-added hooks.
  * When executed, emit an event to ring buffer.
* `trace_user.c`: Load and attach BPF programs in `trace_prog.bpf.c`.
  * Receive the events in ring buffer and print json files.

### Scripts

* `run_traces.sh`: Automatically generate traces for `./tools/testing/selftests/bpf/test_progs.c`.
* `run_test_bpf.sh`: Automatically generate traces for `./lib/test_bpf.c`.

## TODO

- [ ] 将测试程序名称的长度上限调大（目前为16个字符）

- [ ] 增加测试程序对应c代码所在文件和行数的信息

- [ ] 将测试程序的指令上限调大（目前为2048条指令，预计要支持几万条）

- [ ] 异步的json打印：先保存到文件，然后离线解析并打印json

- [ ] 修改json文件结构，保存所有bpf_map