# Output artifact names
APP = trace_user
BPF_C = trace_prog.bpf.c
BPF_OBJ = trace_prog.bpf.o
SKEL_H = trace_prog.skel.h
USER_C = trace_user.c

# Compiler settings (clang, LLVM, bpftool, and libbpf-dev must be installed)
CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool
VMLINUX_BTF ?= ../../../../../vmlinux

# Use the architecture of the kernel being booted, which can differ from the
# build host for cross-platform vmtest runs.
BPF_TARGET_ARCH ?= $(ARCH)
ifeq ($(strip $(BPF_TARGET_ARCH)),)
BPF_TARGET_ARCH := $(shell uname -m)
endif
BPF_TARGET_ARCH := $(patsubst x86_64,x86,$(BPF_TARGET_ARCH))
BPF_TARGET_ARCH := $(patsubst aarch64,arm64,$(BPF_TARGET_ARCH))
ifeq ($(filter x86 arm64,$(BPF_TARGET_ARCH)),)
$(error Unsupported BPF target architecture: $(BPF_TARGET_ARCH))
endif

# libbpf built by tools/testing/selftests/bpf/Makefile
SELFTEST_BPF_DIR := $(abspath ..)
LIBBPF_INCLUDE := $(SELFTEST_BPF_DIR)/tools/include
LIBBPF_A := $(SELFTEST_BPF_DIR)/tools/build/libbpf/libbpf.a

# Compiler flags
CFLAGS := -g -O2 -Wall \
	-I. \
	-I$(LIBBPF_INCLUDE)

BPF_CFLAGS := -g -O2 \
	-target bpf \
	-D__TARGET_ARCH_$(BPF_TARGET_ARCH) \
	-I. \
	-I$(LIBBPF_INCLUDE)

# Libraries
LIBS := $(LIBBPF_A) -lelf -lz

.PHONY: all clean test check

all: $(APP)

# Step 1: Export the complete vmlinux.h from the kernel that will run in the VM
vmlinux.h: $(VMLINUX_BTF)
	@echo "  GEN      vmlinux.h"
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > vmlinux.h

# Step 2: Compile the eBPF C code into BPF bytecode (an .o file)
$(BPF_OBJ): $(BPF_C) vmlinux.h trace_common.h ../../../../../include/linux/bpf_interp_trace.h
	@echo "  CLANG    $@"
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_C) -o $@

# Step 3: Use bpftool to generate the BPF program's C skeleton header (.skel.h)
$(SKEL_H): $(BPF_OBJ)
	@echo "  BPFTOOL  $@"
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $@

# Step 4: Compile the final user-space C program
$(APP): $(USER_C) trace_consumer.c trace_consumer.h $(SKEL_H) trace_common.h ../../../../../include/linux/bpf_interp_trace.h
	@echo "  CC       $@"
	$(CC) $(CFLAGS) $(USER_C) trace_consumer.c -o $(APP) $(LIBS)

clean:
	@echo "  CLEAN"
	rm -f $(APP) $(BPF_OBJ) $(SKEL_H) vmlinux.h

# Check the consumer and scripts without libbpf, BTF, or root privileges.
test check:
	$(CC) $(CFLAGS) -Wextra -Werror -fsyntax-only trace_consumer.c
	@for script in run_vmtest.sh guest_run.sh run_traces.sh run_test_bpf.sh helper_memory_smoke.sh map_helper_smoke.sh; do \
		bash -n $$script || exit; \
	done
