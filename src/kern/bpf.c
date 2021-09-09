#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <asm/byteorder.h>
#include "bpf_helpers.h"
#include "valinor.h"

#include "parsing_helpers.h"

#define TC_ACT_OK       0
#define TC_ACT_SHOT     2


SEC("egress")
int _egress(struct __sk_buff *skb)
{
	int ret = bpf_skb_pull_data(skb, 100);
	void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;

	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int ip_type;
	int tcp_type, udp_type;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct tcphdr *tcphdr;
	struct udphdr *udphdr;
    struct vhdr *v_header;
    __u32   vid;

	nh.pos = data;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	}
	else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	} else {
        bpf_printk("Not Ipproto");
		goto out;
	}

	if(ip_type == IPPROTO_TCP) {
		tcp_type = parse_tcphdr(&nh, data_end, &tcphdr);
		if (tcphdr + 1 > data_end) {
			bpf_printk("TCP err");
			goto out;
		}
	}
	else if(ip_type == IPPROTO_UDP) {
		udp_type = parse_udphdr(&nh, data_end, &udphdr);
		if (udphdr + 1 > data_end) {
			bpf_printk("UDP err");
			goto out;
		}
	}
	else {
		bpf_printk("Not supported transport protocol");
		goto out;
	}

	if(nh.pos + sizeof(struct vhdr) > data_end) {
		bpf_printk("valid check!");

	}

    vid = parse_vhdr(&nh, data_end, &v_header);
    // if(vid == -1)
    // {
    //     bpf_printk("failed to parse vhdr");
    //     goto out;
    // }
    if(v_header + 1 > data_end) {
        bpf_printk("V err!");
        goto out;
    }

    // timestamp
    bpf_printk("timestamping %x", bpf_ntohl(v_header->id));
    v_header->t[0] = bpf_cpu_to_be64(0xABCDABCD12345678);
    // v_header->t[3] = bpf_cpu_to_be64(0xABCDABCD12345678);
    // v_header->t[4] = bpf_cpu_to_be64(0xABCDABCD12345678);


 out:
    bpf_printk("out");
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
