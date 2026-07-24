# BPF Trace Recorder

## One-command VM workflow

The host workflow builds the kernel, BPF selftests, tracer, and
`lib/test_bpf.ko`; installs them into a libbpf CI rootfs; boots the kernel with
QEMU; runs the selected experiment; and writes JSON files directly to a host
directory.

```shell
./tools/testing/selftests/bpf/tracer/run_vmtest.sh --suite smoke
```

The first invocation downloads a libbpf CI rootfs unless a cached
`$HOME/.bpf_selftests/root.img` already exists. A local rootfs archive can be
specified explicitly:

```shell
./tools/testing/selftests/bpf/tracer/run_vmtest.sh \
  --rootfs /path/to/libbpf-vmtest-rootfs.tar.zst \
  --suite smoke
```

Available suites:

```shell
# A few automatically selected test_progs tests.
./tools/testing/selftests/bpf/tracer/run_vmtest.sh --suite smoke

# Selected test_progs tests.
./tools/testing/selftests/bpf/tracer/run_vmtest.sh \
  --suite test_progs --test tailcalls

# All non-blacklisted test_progs tests.
./tools/testing/selftests/bpf/tracer/run_vmtest.sh --suite test_progs

# The test_bpf experiment.
./tools/testing/selftests/bpf/tracer/run_vmtest.sh --suite test_bpf

# Both complete experiments.
./tools/testing/selftests/bpf/tracer/run_vmtest.sh --suite all
```

Results are placed under `tracer/results/<timestamp>-<suite>/` by default.
Pass `--output <directory>` to select another location. The directory contains
the JSON traces, VM console logs, guest kernel information, the tested Git
commit, the guest exit status, and `json-validation.tsv`. JSON validation runs
on the host after the VM exits. Valid non-empty traces remain in their suite
directory, empty arrays are moved to `empty/`, and invalid or incomplete
outputs are moved to `error/`.

KVM is required by default. `--allow-tcg` permits QEMU emulation for a smoke
run, but complete suites are expected to be prohibitively slow without KVM.

Host dependencies include a Linux kernel build toolchain, clang/LLVM,
`bpftool`, `pahole`, libbpf development files, QEMU, zstd, `jq`, and sudo
access for mounting the rootfs image. A missing `jq` is reported before the
build starts. Run `run_vmtest.sh --help` for all options.

The lower-level `vmtest.sh` interface remains available:

```shell
tools/testing/selftests/bpf/vmtest.sh \
  -r /absolute/path/to/results \
  -- ./tracer/guest_run.sh smoke
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
