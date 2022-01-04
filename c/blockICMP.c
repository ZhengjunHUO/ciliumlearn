#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <netinet/in.h>

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

SEC("ingress")
int drop_icmp(struct __sk_buff *skb) {
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    /* IN ETHER HEADER CHECK UPPER PROTOCOL */
    struct ethhdr *eth_hd = data;
    // avoid verifier's complain
    if (data + ETH_HLEN > data_end)
        return TC_ACT_OK;
    // Not ip packet, allow to proceed
    if (eth_hd->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    /* IN IP HEADER CHECK PAYLOAD'S PROTOCOL */
    struct iphdr *ip_hd = data + ETH_HLEN;
    // avoid verifier's complain
    if ((void *)ip_hd + sizeof(*ip_hd) > data_end)
        return TC_ACT_OK;
    // Not icmp packet, allow to proceed
    if (ip_hd->protocol != IPPROTO_ICMP)
        return TC_ACT_OK;

    // drop icmp packet
    return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
