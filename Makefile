# Makefile

BPF_CLANG=clang
BPF_CFLAGS=-O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH)

# ARCHを取得（x86_64またはaarch64）
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
    ARCH := x86
else ifeq ($(UNAME_M),aarch64)
    ARCH := arm64
else
    $(error Unsupported architecture)
endif

all: socket_filter_kern.o kprobe_inet_bind_kern.o

socket_filter_kern.o: socket_filter.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c socket_filter.c -o socket_filter_kern.o

kprobe_inet_bind_kern.o: kprobe_inet_bind.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c kprobe_inet_bind.c -o kprobe_inet_bind_kern.o

clean:
	rm -f *.o