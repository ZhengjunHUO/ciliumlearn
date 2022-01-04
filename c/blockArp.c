#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <netinet/in.h>

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

SEC("ingress")
int drop_arp(struct __sk_buff *skb) {
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    // avoid verifier's complain
    if (data + ETH_HLEN > data_end)
        return TC_ACT_OK;

    struct ethhdr *eth_hd = data;
    // Not arp packet, allow to proceed
    if (eth_hd->h_proto != htons(ETH_P_ARP))
       return TC_ACT_OK;

    // drop arp packet
    return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
