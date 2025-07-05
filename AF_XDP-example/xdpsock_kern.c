// SPDX-License-Identifier: GPL-2.0
#include "vmlinux_6.14.h"
#include "bpf_endian.h"

// #include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "xdpsock.h"

/* This XDP program is only needed for multi-buffer and XDP_SHARED_UMEM modes.
 * If you do not use these modes, libbpf can supply an XDP program for you.
 */

struct
{
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, MAX_SOCKS);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

int num_socks = 0;
static unsigned int rr;

// -------------------------------------

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook		*/
#endif

// likely optimization
#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

struct hdr_cursor
{
	void *pos;
	void *data;
	void *data_end;
};

static __always_inline int parse_ethhdr(struct hdr_cursor *nh, struct ethhdr **ethhdr_l2)
{
	*ethhdr_l2 = nh->pos;

	if (unlikely((void *)((*ethhdr_l2) + 1) > nh->data_end))
	{
		return -1;
	}

	nh->pos += sizeof(struct ethhdr);

	return (*ethhdr_l2)->h_proto;
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh, struct iphdr **iphdr_l3)
{
	*iphdr_l3 = nh->pos;

	if (unlikely((void *)((*iphdr_l3) + 1) > nh->data_end))
	{
		return -1;
	}

	if (unlikely((*iphdr_l3)->version != 4))
	{
		return -1;
	}

	int hdrsize = ((*iphdr_l3)->ihl) << 2;					 // * 4     // 20
	int l3_len = nh->data_end - nh->pos;					 // 74
	int tot_len_in_hdr_l3 = bpf_ntohs((*iphdr_l3)->tot_len); // 83

	if (unlikely(l3_len != tot_len_in_hdr_l3 || l3_len < hdrsize || tot_len_in_hdr_l3 < hdrsize))
	{
		return -1;
	}

	nh->pos += hdrsize;

	return (*iphdr_l3)->protocol;
}

static __always_inline int parse_ipv6hdr(struct hdr_cursor *nh, struct ipv6hdr **ipv6hdr_l3)
{
	*ipv6hdr_l3 = nh->pos;

	if (unlikely((void *)((*ipv6hdr_l3) + 1) > nh->data_end))
	{
		return -1;
	}

	nh->pos += sizeof(struct ipv6hdr);

	return (*ipv6hdr_l3)->nexthdr;
}

// -------------------------------------

SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
	struct hdr_cursor nh = {.pos = (void *)(long)ctx->data, .data = (void *)(long)ctx->data, .data_end = (void *)(long)ctx->data_end};

	struct ethhdr *ethhdr_l2 = NULL;
	struct iphdr *iphdr_l3 = NULL;
	struct ipv6hdr *ipv6hdr_l3 = NULL;

	int proto_type = parse_ethhdr(&nh, &ethhdr_l2);
	if (unlikely(proto_type < 0))
	{
		return XDP_DROP;
	}
	else if (likely(bpf_htons(ETH_P_IP) == proto_type))
	{
		int proto_l4 = parse_iphdr(&nh, &iphdr_l3);
		if (unlikely(proto_l4 < 0))
		{
			return XDP_DROP;
		}

		if (unlikely(IPPROTO_UDP != proto_l4 && IPPROTO_TCP != proto_l4))
		{
			return XDP_PASS;
		}

		// redirect
	}
	else if (bpf_htons(ETH_P_IPV6) == proto_type)
	{
		int proto_l4 = parse_ipv6hdr(&nh, &ipv6hdr_l3);
		if (unlikely(proto_l4 < 0))
		{
			return XDP_DROP;
		}

		if (unlikely(IPPROTO_UDP != proto_l4 && IPPROTO_TCP != proto_l4))
		{
			return XDP_PASS;
		}

		// redirect
	}
	else
	{
		// Unknown;
		return XDP_PASS;
	}

	rr = (rr + 1) & (num_socks - 1);
	// bpf_printk("----------------rr: %d", rr);

	return bpf_redirect_map(&xsks_map, rr, XDP_DROP);
}

char _license[] SEC("license") = "GPL";