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

# Helper memory capture, including budget diagnostics.
./tools/testing/selftests/bpf/tracer/run_vmtest.sh --suite helper-memory

# Array-map helpers, aliases, tail calls, and helper memory capture.
./tools/testing/selftests/bpf/tracer/run_vmtest.sh --suite map-helper

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
the JSON traces, VM console logs, guest kernel information, the suite name,
and the guest exit status. Record the tested Git commit separately; the host
script currently does not write it automatically. JSON status checks run on
the host after the VM exits and leave all files in place. Primary outputs
are under `test_progs/` and `test_bpf/`; expected unsupported and incomplete
fixtures from the helper suites are under `diagnostics/`.

The host status check examines primary output files and requires at least
one non-empty file whose runs all have complete capture status. It does not
check the expected program set or diagnostic contents. Those require separate
content checks; the status summary alone does not establish suite coverage
or successful semantic replay.

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

## JSON reader compatibility

The sequenced event format keeps the legacy validator's mandatory fields:
`sp_list` lists frame pointers in frame-entry order (including reused stack
addresses), and `jmp_map_ptr` and `jmp_max_entries` describe the first
successful tail call's map. If no tail call succeeds, the first declared
program-array map supplies those fields; programs without one use zero.
Each `jmp_table` entry includes its target's `insns` as well as its `code_id`.
The `codes`, region lifetimes, helper events, and memory snapshots remain
available to readers of the extended format.

These fields preserve the existing OCaml reader's input shape. A complete
capture does not imply that the legacy replay semantics supports every
captured feature: replaying helper memory effects and initial map contents
requires a validator that consumes the extended fields. The legacy jump-table
model also represents only one program-array map. Parse compatibility is
checked by `make check`; semantic replay must be tested separately.

## Overview

### Kernel producer and transport

The interpreter in [core.c](../../../../../kernel/bpf/core.c) uses
[interp_trace.h](../../../../../kernel/bpf/interp_trace.h) to track each
invocation, its code declarations, stack frames, helpers, and map memory.
The shared records and limits are defined in
[bpf_interp_trace.h](../../../../../include/linux/bpf_interp_trace.h).

Events are emitted through the `bpf_interp` tracepoint. The observer in
[trace_prog.bpf.c](trace_prog.bpf.c) attaches at `raw_tp/bpf_interp` and
copies them into a ring buffer. Code declarations include the final
interpreter instructions and helper identities. Memory records contain
bounded chunks read while the producer's source address is live.

Capture uses the interpreter with JIT disabled and selects tasks whose
names begin with `test_progs` or `insmod`. The legacy `bpf_interp_hook_*`
fentry interface has been replaced by this event protocol. The kernel and
observer share a private ABI and must be rebuilt together.

### User-space consumer and JSON

[trace_user.c](trace_user.c) loads the observer, polls the ring buffer, and
passes records to [trace_consumer.c](trace_consumer.c). Transport wrappers
are defined in [trace_common.h](trace_common.h). The consumer checks event
sequence numbers, code and region references, helper pre/post pairs, memory
chunks, and the final producer counts.

Each output is an array of runs. A run contains:

* `prog_insn` and `codes`: the main program and additional code declarations.
* `trace`: register snapshots after recorded interpreter instructions.
* `mem_blocks`: region identities, addresses, sizes, permissions, and lifetimes.
* `helper_events`: helper identities, arguments, return values, memory snapshots,
  and map effects when applicable.
* `maps` and `initial_memory`: map declarations and captured initial value bytes.
* `capture_status` and `capture_reasons`: capture completeness and limitations.

The consumer streams register and helper records into temporary files.
Completed runs are serialized into a shared spool and their per-run resources
are released. Fixture assumptions are checked when the consumer closes, so a
fixture may publish its manifest after execution and object cleanup.
The tracer writes to an output path ending in `.tmp` and publishes the final
path after successful shutdown and output finalization.

### Stack frames and memory snapshots

Each `type: "stack"` region describes one frame lifetime. Its address is
`base_addr = R10 - size`, where the interpreter allocation is between 32
and 512 bytes. A frame has its own `region_id`, `born_seq`, `dead_seq`, and
`parent_region_id`. Later calls that reuse an address get new region identities.
`sp_list` is the legacy projection of frame pointers in entry order.

Memory is captured for supported helper accesses and map initial values.
Helper `premem` and `postmem` snapshots identify their region and offset;
their `bytes` strings contain hexadecimal bytes in increasing address order.
A snapshot also records its sequence interval and read status. Read failures
are reported explicitly, including expected fault cases, and are not supplied
as zero-filled initialized memory.

The output does not contain a `stack_trace` snapshot for every instruction.
Unused stack bytes must not be inferred to be initialized from the existence
of a stack region. A reader must use region lifetimes and the actual snapshot
records, and avoid allocating a duplicate stack for both a region descriptor
and its legacy `sp_list` entry.

### Capture status and fixture assumptions

`complete` means that the observed records satisfy the consumer's capture
checks. `unsupported` identifies an operation or assumption outside the
supported capture model. `incomplete` identifies missing or inconsistent
records, failed reads, or an exceeded capture budget. Reason strings describe
the affected run. These statuses describe capture fidelity, not a proof of
the execution's semantics.

Ordinary array-map captures use `TRACE_FIXTURE_FILE` to bind program/map IDs
and an execution time window to an exclusive fixture that has released its
object references. Without matching evidence, the consumer marks the
concurrency assumption unsupported. This fixture model does not establish
general capture correctness for maps shared with concurrent writers.

### Host checks and VM suites

`make -C tools/testing/selftests/bpf/tracer check` needs a host C compiler,
Python 3, and Bash, without BTF, libbpf, or root privileges. It runs consumer
resource/fixture tests, JSON compatibility tests, and shell syntax checks.
These checks exercise user-space behavior and do not boot a kernel.

The `helper-memory` VM suite checks helper results and canaries with and
without capture, and produces a memory-budget diagnostic. The `map-helper`
suite adds array-map helper effects, alias and budget diagnostics, and then
runs the helper-memory suite. Initial values and helper snapshots should be
checked separately from both the host status summary and semantic replay.

### Scripts

* [run_traces.sh](run_traces.sh): capture selected or unblacklisted `test_progs` tests.
* [run_test_bpf.sh](run_test_bpf.sh): capture the `test_bpf` module experiment.
* [helper_memory_smoke.sh](helper_memory_smoke.sh): run helper-memory fixtures.
* [map_helper_smoke.sh](map_helper_smoke.sh): run map fixtures and helper-memory fixtures.
