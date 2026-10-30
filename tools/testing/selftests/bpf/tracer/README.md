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
void bpf_interp_hook_start(u64 run_id, const struct bpf_prog *prog, u64 ctx_ptr, u64 fp, u32 stack_size);
void bpf_interp_hook_step(u64 run_id, const u64 *regs, u32 stack_size);
void bpf_interp_hook_end(u64 run_id, u64 ret);
void bpf_interp_hook_call(u64 run_id, u64 fp, u32 stack_size);
```

The following 2 hooks need to be removed later.

```c
void bpf_interp_hook_tailcall(u64 run_id, const struct bpf_prog *prog, u32 pc, u64 map_ptr, u32 index);
void bpf_interp_hook_tailcall_map(u64 run_id, const struct bpf_map * map_ptr); // Temporary workaround
```

### User part

* `trace_common.h`: Struct and constant definition.
* `trace_prog.bpf.c`: Define BPF programs, which would be attached to the new-added hooks.
  * When executed, emit an event to ring buffer.
* `trace_user.c`: Load and attach BPF programs in `trace_prog.bpf.c`.
  * Receive the events in ring buffer and print json files.

### Stack memory

`mem_blocks` also contains `type: "stack"` entries for the main and BPF
subprogram stacks. Each entry describes the actual interpreter allocation:
`base_addr = R10 - size`, with `size` between 32 and 512 bytes. Repeated
calls using the same base address and size share a descriptor; `sp_list`
continues to record individual calls.

`stack_trace[i]` is captured together with `trace[i]`, after the same
instruction, and describes the **current frame**:

```json
{ "base_addr": "0x1000", "size": 32, "bytes": "0000000000000000000000000000000000000000000000002a00000000000000" }
```

`bytes` contains exactly `size` bytes, in increasing address order, encoded
as two hexadecimal digits per byte. The last byte is at `R10 - 1`. Stack
read failures discard the run instead of supplying zero-filled snapshots.
Snapshots are streamed to a temporary file to avoid retaining all steps in
userspace memory.

These are raw observations: unused or uninitialized stack bytes can contain
arbitrary values and must not be imported as initialized semantic memory.
There is no entry-time snapshot or simultaneous snapshot of suspended caller
frames. A helper's writes into the current frame appear in its post-call
step if the run remains traceable; existing helper-memory filters still apply.

Consumers must distinguish `stack` from map blocks and avoid allocating a
second semantic stack for descriptors already represented by `sp_list`.
The kernel and tracer must be rebuilt together because hook signatures and
ring-buffer event layouts have changed. Per-step events now carry up to
512 additional bytes, increasing output size and ring-buffer traffic.

After building, `make -C tools/testing/selftests/bpf/tracer test` runs host
tests for snapshot serialization, frame sizes, byte order, and read failures.

### Scripts

* `run_traces.sh`: Automatically generate traces for `./tools/testing/selftests/bpf/test_progs.c`.
* `run_test_bpf.sh`: Automatically generate traces for `./lib/test_bpf.c`.
