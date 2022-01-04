#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

SEC("ingress")
int drop_icmp(struct __sk_buff *skb) {
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;

    __u32 tcphdr_offset = ETH_HLEN + sizeof(struct iphdr);
    __u32 payload_offset = tcphdr_offset + sizeof(struct tcphdr);

    // avoid verifier's complain
    if (data + payload_offset > data_end)
        return TC_ACT_OK;

    /* IN ETHER HEADER CHECK UPPER PROTOCOL */
    struct ethhdr *eth_hd = data;
    // Not ip packet, allow to proceed
    if (eth_hd->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    /* IN IP HEADER CHECK UPPER PROTOCOL */
    struct iphdr *ip_hd = data + ETH_HLEN;
    // Not icmp packet, allow to proceed
    if (ip_hd->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    /* IN TCP HEADER CHECK DESTINATION PORT */
    struct tcphdr *tcp_hd = data + tcphdr_offset;
    if (ntohs(tcp_hd->dest) != 80)
	return TC_ACT_OK;

    // drop packet sent to port 80
    return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
