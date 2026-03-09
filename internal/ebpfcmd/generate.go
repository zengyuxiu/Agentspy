package ebpfcmd

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86" -target bpfel,bpfeb claudeCmd ../../bpf/claude_cmd.bpf.c -- -I../../bpf
