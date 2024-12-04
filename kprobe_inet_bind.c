// bpf/kprobe_inet_bind.c

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>    // 追加
#include <linux/ptrace.h>      // 追加
#include <linux/net.h>
#include <linux/in.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} port_events SEC(".maps");

SEC("kprobe/inet_bind")
int kprobe_inet_bind(struct pt_regs *ctx) {
    struct sockaddr_in addr = {};

    // アーキテクチャによって関数引数の取得方法が異なる
#ifdef __aarch64__
    // arm64の場合、関数引数は x0, x1, x2... に格納されています
    struct sockaddr *uaddr = (struct sockaddr *)ctx->regs[1];
#else
    // 他のアーキテクチャの場合
    struct sockaddr *uaddr = (struct sockaddr *)PT_REGS_PARM2(ctx);
#endif

    // sockaddr_in 構造体を読み取る
    if (bpf_probe_read_kernel(&addr, sizeof(addr), uaddr) < 0)
        return 0;

    // ポート番号を取得
    unsigned short port = bpf_ntohs(addr.sin_port);

    // ユーザー空間に送信
    bpf_perf_event_output(ctx, &port_events, BPF_F_CURRENT_CPU, &port, sizeof(port));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";