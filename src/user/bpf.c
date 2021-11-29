#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <asm/byteorder.h>
#include "bpf_api.h"
#include "valinor.h"

#include "parsing_helpers.h"

#define TC_ACT_OK       0
#define TC_ACT_SHOT     2

#define MAP_MAX_ENTRIES	1 << 24

// struct bpf_elf_map SEC("maps") flow_map = {
// 	.type           =       BPF_MAP_TYPE_ARRAY,
// 	.id             =       1,
// 	.size_key       =       sizeof(__u32),
// 	.size_value     =       sizeof(__u64),
// 	.max_elem       =       256,
// 	.pinning        =       PIN_OBJECT_NS,
// };

struct data_entry {
	__u64	ts;
	__u64	length;
};

struct ebpf_ts_map_def {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);	/* or LIBBPF_PIN_NONE */
} idx_map __section(".maps");

struct ebpf_idx_map_def {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct data_entry));
	__uint(max_entries, MAP_MAX_ENTRIES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);	/* or LIBBPF_PIN_NONE */
} ts_map __section(".maps");

// __section("egress")
// int emain(struct __sk_buff *skb)
// {
// 	int key = 0, *val;

// 	val = map_lookup_elem(&map_sh, &key);
// 	if (val)
// 		lock_xadd(val, 1);

// 	return BPF_H_DEFAULT;
// }

__section("egress")
int _egress(struct __sk_buff *skb)
{
	int ret = skb_pull_data(skb, 100);
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
	struct data_entry	value;
	__u32 *write_ptr;
	__u64 timestamp;
	__u32 write_ptr_index = 0;

	timestamp = ktime_get_ns();
	nh.pos = data;


	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	}
	else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	} else {
        printt("Not Ipproto");
		goto out;
	}

	if(ip_type == IPPROTO_TCP) {
		tcp_type = parse_tcphdr(&nh, data_end, &tcphdr);
		if (tcphdr + 1 > data_end) {
			printt("TCP err");
			goto out;
		}
	}
	else if(ip_type == IPPROTO_UDP) {
		udp_type = parse_udphdr(&nh, data_end, &udphdr);
		if (udphdr + 1 > data_end) {
			printt("UDP err");
			goto out;
		}
	}
	else {
		printt("Not supported transport protocol");
		goto out;
	}

	if(nh.pos + sizeof(struct vhdr) > data_end) {
		printt("valid check!");

	}
	write_ptr = map_lookup_elem((void *)&idx_map, &write_ptr_index);
	if (!write_ptr) {
		printt("Error accessing the index pointer. Exitting ...");
		goto out;
	}
	if(*write_ptr == MAP_MAX_ENTRIES-1){
		*write_ptr = 0;
		printt("resetting the ptr");
		ret = map_update_elem((void *)&idx_map, &write_ptr_index, write_ptr, 0);
		if (ret < 0)
			printt("failed to reset write_ptr to %lu", *write_ptr);
	} else
		lock_xadd(write_ptr, 1);

	value.ts = timestamp;
	value.length = skb->len;
	ret = map_update_elem((void *)&ts_map, write_ptr, &value, 0);
	if (ret < 0)
		printt("failed to update %lu", *write_ptr);
	// printt("updated %lu", *write_ptr);

 out:
    // printt("out: %llu", timestamp);
	return TC_ACT_OK;
}

char _license[] __section("license") = "GPL";
