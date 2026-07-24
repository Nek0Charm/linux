# 目标产物名称
APP = trace_user
BPF_C = trace_prog.bpf.c
BPF_OBJ = trace_prog.bpf.o
SKEL_H = trace_prog.skel.h
USER_C = trace_user.c

# 编译器设置 (需确保系统中已安装 clang, llvm, bpftool 和 libbpf-dev)
CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool
VMLINUX_BTF ?= ../../../../../vmlinux

# 编译参数
CFLAGS := -g -O2 -Wall -I.
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 -I.

# 依赖库
LIBS := -lbpf -lelf -lz

.PHONY: all clean

all: $(APP)

# 步骤 1: 从将要在 VM 中运行的内核导出完整的 vmlinux.h
vmlinux.h: $(VMLINUX_BTF)
	@echo "  GEN      vmlinux.h"
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > vmlinux.h

# 步骤 2: 将 eBPF C 代码编译为 BPF 字节码 (.o 文件)
$(BPF_OBJ): $(BPF_C) vmlinux.h trace_common.h
	@echo "  CLANG    $@"
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_C) -o $@

# 步骤 3: 使用 bpftool 生成 BPF 程序的 C 语言骨架头文件 (.skel.h)
$(SKEL_H): $(BPF_OBJ)
	@echo "  BPFTOOL  $@"
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $@

# 步骤 4: 编译最终的用户态 C 程序
$(APP): $(USER_C) $(SKEL_H) trace_common.h
	@echo "  CC       $@"
	$(CC) $(CFLAGS) $(USER_C) -o $(APP) $(LIBS)

clean:
	@echo "  CLEAN"
	rm -f $(APP) $(BPF_OBJ) $(SKEL_H) vmlinux.h
