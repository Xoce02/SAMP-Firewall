#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#define PORT 7777
struct ip_state {
    __u64 last_reset;
    __u64 last_query;
    __u32 queries;
    __u32 heavy;
    __u32 score;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, struct ip_state);
} state_map SEC(".maps");
static inline int heavy(char c)
{
    return c == 'c' || c == 'd' || c == 'x';
}
static inline int bogon(__u32 a)
{
    __u8 b0 = (a >> 24) & 0xff;
    __u8 b1 = (a >> 16) & 0xff;
    if (b0 == 0 || b0 == 127 || b0 == 10) return 1;
    if (b0 == 169 && b1 == 254) return 1;
    if (b0 == 172 && b1 >= 16 && b1 <= 31) return 1;
    if (b0 == 192 && b1 == 168) return 1;
    if (b0 == 100 && b1 >= 64 && b1 <= 127) return 1;
    if (b0 >= 224) return 1;
    return 0;
}
SEC("xdp")
int samp_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->ihl < 5) return XDP_DROP;
    if (ip->frag_off & bpf_htons(0x2000 | 0x1fff)) return XDP_DROP;
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
    if (bogon(bpf_ntohl(ip->saddr))) return XDP_DROP;
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    __u16 ulen = bpf_ntohs(udp->len);
    if (ulen < sizeof(*udp)) return XDP_DROP;
    __u16 plen = ulen - sizeof(*udp);
    if ((void *)udp + ulen > data_end) return XDP_DROP;
    if (bpf_ntohs(udp->dest) != PORT) return XDP_PASS;
    __u16 sport = bpf_ntohs(udp->source);
    if (sport < 49152 || sport > 65535) return XDP_DROP;
    if (plen < 11 || plen > 64) return XDP_DROP;
    unsigned char *p = (unsigned char *)(udp + 1);
    if (p + 11 > (unsigned char *)data_end) return XDP_DROP;
    if (p[0] != 'S' || p[1] != 'A' || p[2] != 'M' || p[3] != 'P')
        return XDP_DROP;
    char op = p[10];
    if (op != 'i' && op != 'r' && op != 'c' &&
        op != 'd' && op != 'p' && op != 'x')
        return XDP_DROP;
    __u32 src = ip->saddr;
    __u64 ts = bpf_ktime_get_ns();
    struct ip_state *st = bpf_map_lookup_elem(&state_map, &src);
    if (!st) {
        struct ip_state n = {
            .last_reset = ts,
            .last_query = ts,
            .queries = 1,
            .heavy = heavy(op) ? 1 : 0,
            .score = heavy(op) ? 12 : 3
        };
        bpf_map_update_elem(&state_map, &src, &n, BPF_ANY);
        return XDP_PASS;
    }
    if ((ts - st->last_reset) > 2000000000ULL) {
        st->last_reset = ts;
        st->queries = 0;
        st->heavy = 0;
        st->score = (st->score > 6) ? st->score - 6 : 0;
    }
    if ((ts - st->last_query) < 50000000ULL)
        st->score += 6;
    st->last_query = ts;
    st->queries++;
    if (heavy(op)) {
        st->heavy++;
        st->score += 12;
    } else {
        st->score += 3;
    }
    if (st->queries > 7 || st->heavy > 2 || st->score > 40)
        return XDP_DROP;
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
