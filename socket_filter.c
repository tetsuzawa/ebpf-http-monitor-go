// bpf/socket_filter.c

#include <linux/in.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h> // 追加
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} http_events SEC(".maps");

SEC("socket")
int http_filter(struct __sk_buff *skb) {
    // Ethernetヘッダの処理
    struct ethhdr eth;
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
        return 0;
    
    if (eth.h_proto != bpf_htons(ETH_P_IP))
        return 0;

    // IPヘッダの処理
    struct iphdr ip;
    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &ip, sizeof(ip)) < 0)
        return 0;

    if (ip.protocol != IPPROTO_TCP)
        return 0;

    // TCPヘッダの処理
    struct tcphdr tcp;
    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr), 
                          &tcp, sizeof(tcp)) < 0)
        return 0;

    // ペイロードオフセットの計算
    unsigned int ip_header_len = ip.ihl * 4;
    unsigned int tcp_header_len = tcp.doff * 4;
    unsigned int payload_offset = sizeof(struct ethhdr) + ip_header_len + tcp_header_len;

    // パケット長を超えないかチェック
    if (payload_offset + 4 > skb->len)
        return 0;

    // HTTPメソッドの確認
    char http_method[4] = {0};
    if (bpf_skb_load_bytes(skb, payload_offset, http_method, sizeof(http_method)) < 0)
        return 0;

    if (http_method[0] == 'G' && http_method[1] == 'E' &&
        http_method[2] == 'T' && http_method[3] == ' ') {

        // パスの抽出
        char path[256] = {0};
        int path_len = 0;

        #pragma unroll
        for (int i = 0; i < 255; i++) {
            // パケット長を超えないかチェック
            if (payload_offset + 4 + i + 1 > skb->len)
                break;

            char c;
            if (bpf_skb_load_bytes(skb, payload_offset + 4 + i, &c, 1) < 0)
                break;
            if (c == ' ')
                break;
            path[i] = c;
            path_len = i + 1;
        }

        // イベントの送信
        bpf_perf_event_output(skb, &http_events, BPF_F_CURRENT_CPU, path, path_len);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";