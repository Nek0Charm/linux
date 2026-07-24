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

# Compiler flags
CFLAGS := -g -O2 -Wall -I.
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 -I.

# Libraries
LIBS := -lbpf -lelf -lz

.PHONY: all clean

all: $(APP)

# Step 1: Export the complete vmlinux.h from the kernel that will run in the VM
vmlinux.h: $(VMLINUX_BTF)
	@echo "  GEN      vmlinux.h"
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > vmlinux.h

# Step 2: Compile the eBPF C code into BPF bytecode (an .o file)
$(BPF_OBJ): $(BPF_C) vmlinux.h trace_common.h
	@echo "  CLANG    $@"
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_C) -o $@

# Step 3: Use bpftool to generate the BPF program's C skeleton header (.skel.h)
$(SKEL_H): $(BPF_OBJ)
	@echo "  BPFTOOL  $@"
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $@

# Step 4: Compile the final user-space C program
$(APP): $(USER_C) $(SKEL_H) trace_common.h
	@echo "  CC       $@"
	$(CC) $(CFLAGS) $(USER_C) -o $(APP) $(LIBS)

clean:
	@echo "  CLEAN"
	rm -f $(APP) $(BPF_OBJ) $(SKEL_H) vmlinux.h
