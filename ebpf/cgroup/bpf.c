#include <linux/bpf.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include "bpf_helpers.h"

typedef struct {
    __u32 saddr;
    __u32 daddr;
    __u8  proto;
    __u8  bitmap;
} pkt;

struct bpf_map_def SEC("maps") ingress_blacklist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(_Bool),
    .max_entries = 1000,
};

struct bpf_map_def SEC("maps") egress_blacklist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(_Bool),
    .max_entries = 1000,
};

struct bpf_map_def SEC("maps") data_flow = {
    .type = BPF_MAP_TYPE_QUEUE,
    .key_size = 0,
    .value_size = sizeof(pkt),
    .max_entries = 10000,
};

static inline int filter_packet(struct __sk_buff *skb, bool isIngress) {
    struct iphdr iphd;
    bpf_skb_load_bytes(skb, 0, &iphd, sizeof(struct iphdr));

    bool isBanned;
    if (isIngress) {
        bpf_printk("Ingress from %lu",iphd.saddr);
        isBanned = bpf_map_lookup_elem(&ingress_blacklist, &iphd.saddr);
    }else{
        bpf_printk("Egress to %lu",iphd.daddr);
        isBanned = bpf_map_lookup_elem(&egress_blacklist, &iphd.daddr);
    }

    pkt p = {
        .saddr = iphd.saddr,
	.daddr = iphd.daddr,
	.proto = iphd.protocol,
	.bitmap = isBanned | (isIngress << 1)
    };

    bpf_map_push_elem(&data_flow, &p, BPF_ANY);

    // return 0 => drop
    return !isBanned;
}

SEC("cgroup_skb/ingress")
int ingress_filter(struct __sk_buff *skb) {
    return filter_packet(skb, true);
}

SEC("cgroup_skb/egress")
int egress_filter(struct __sk_buff *skb) {
    return filter_packet(skb, false);
}

char __license[] SEC("license") = "Dual MIT/GPL";
