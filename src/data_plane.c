#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <asm/byteorder.h>
#include <errno.h>
#include "bpf_api.h"
#include "valinor.h"

#include "parsing_helpers.h"

#define TC_ACT_OK       0
#define TC_ACT_SHOT     2

#define MAP_MAX_ENTRIES	1 << 24

struct data_entry {
	__u64   ts;
    __u32   saddr;
    __u32   daddr;
    __u32   key;
   	__u16   length;
    __u16   sport;
    __u16   dport;
    
};

struct ebpf_idx_map_def {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);	/* or LIBBPF_PIN_NONE */
} idx_map __section(".maps");

struct ebpf_stat_map_def {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 2);
	__uint(pinning, LIBBPF_PIN_BY_NAME);	/* or LIBBPF_PIN_NONE */
} stat_map __section(".maps");

struct ebpf_ts_map_def {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct data_entry));
	__uint(max_entries, MAP_MAX_ENTRIES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);	/* or LIBBPF_PIN_NONE */
} ts_map __section(".maps");

struct ebpf_enb_map_def {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);	/* or LIBBPF_PIN_NONE */
} enb_map __section(".maps");

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
	struct data_entry	value = {0};
	__u32 *write_ptr, *stat_ptr, *enb_ptr;
	__u64 timestamp;
	__u32 write_ptr_index = 0, stat_ptr_success = 0, stat_ptr_fail = 1;
	__u32 window = 0;

	timestamp = ktime_get_ns();
	nh.pos = data;


	enb_ptr = map_lookup_elem((void *)&enb_map, &write_ptr_index);
	if (!enb_ptr) {
		printt("Error accessing the enable pointer. Exitting ...");
		goto out_f;
	}
	if(*enb_ptr == 0 || *enb_ptr == -1){
		return TC_ACT_OK;
	}

	write_ptr = map_lookup_elem((void *)&idx_map, &write_ptr_index);
	if (!write_ptr) {
		printt("Error accessing the index pointer. Exitting ...");
		goto out_f;
	}
		

	value.ts = timestamp;
	value.length = skb->len;
	value.key = skb->hash;
	value.saddr = skb->mark; // skb->local_ip4;
	skb->mark = 0;
	// value.daddr = 0; // skb->remote_ip4;
	//value.sport = 0; // skb->local_port;
	// value.dport = 0; // skb->remote_port;
	ret = map_update_elem((void *)&ts_map, write_ptr, &value, 0);
	if (ret < 0){
		printt("failed to update (ret:%d,) %lu", ret, *write_ptr);
		goto out_f;
	}

out_s:
	lock_xadd(write_ptr, 1);
    stat_ptr = map_lookup_elem((void *)&stat_map, &stat_ptr_success);
	if (stat_ptr) {
		lock_xadd(stat_ptr, 1);
	}
	return TC_ACT_OK;

out_f:
	stat_ptr = map_lookup_elem((void *)&stat_map, &stat_ptr_fail);
	if (stat_ptr) {
		lock_xadd(stat_ptr, 1);
	}
	return TC_ACT_OK;

}

char _license[] __section("license") = "GPL";
