// SPDX-License-Identifier: MIT
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "unpa.h"

_Static_assert(sizeof(struct flow_key) == 44, "flow_key ABI");
_Static_assert(sizeof(struct counters) == 24, "counters ABI");
_Static_assert(sizeof(struct link_key) == 8, "link_key ABI");
_Static_assert(sizeof(struct link_counters) == 48, "link_counters ABI");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct flow_key);
	__type(value, struct counters);
} flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2048);
	__type(key, struct link_key);
	__type(value, struct link_counters);
} links SEC(".maps");

#define MAX_VLAN_TAGS 2
#define MAX_IPV6_EXT_HEADERS 6
#define IPV4_FRAG_OFFSET 0x1fff
#define IPV4_MORE_FRAGS 0x2000
#define IPV6_FRAG_OFFSET 0xfff8
#define IPV6_MORE_FRAGS 0x0001
#define UNPA_IPPROTO_HIP 139
#define UNPA_IPPROTO_SHIM6 140

struct vlan_header {
	__be16 tci;
	__be16 protocol;
};

struct ipv6_fragment_header {
	__u8 next;
	__u8 reserved;
	__be16 offset_flags;
	__be32 identification;
};

static __always_inline int fits(__u32 off, __u32 size, __u32 end)
{
	return off <= end && size <= end - off;
}

static __always_inline int parse_ports(struct __sk_buff *skb, __u32 off,
				       __u32 end, int more_frags,
				       struct flow_key *key)
{
	if (key->proto == IPPROTO_TCP) {
		struct tcphdr tcp;

		if (!fits(off, sizeof(tcp), end)) {
			/* A first IPv4 fragment may split the TCP header. IPv6
			 * requires the entire header in the first fragment.
			 */
			__be16 ports[2];

			if (key->family != 4 || !more_frags || !fits(off, 8, end) ||
			    bpf_skb_load_bytes(skb, off, ports, sizeof(ports)))
				return -1;
			key->sport = bpf_ntohs(ports[0]);
			key->dport = bpf_ntohs(ports[1]);
			return 0;
		}
		if (bpf_skb_load_bytes(skb, off, &tcp, sizeof(tcp)) ||
		    tcp.doff < 5 ||
		    ((!more_frags || key->family == 6) &&
		     !fits(off, (__u32)tcp.doff * 4, end)))
			return -1;
		key->sport = bpf_ntohs(tcp.source);
		key->dport = bpf_ntohs(tcp.dest);
	} else if (key->proto == IPPROTO_UDP) {
		struct udphdr udp;
		__u16 udp_len;

		if (!fits(off, sizeof(udp), end) ||
		    bpf_skb_load_bytes(skb, off, &udp, sizeof(udp)))
			return -1;
		udp_len = bpf_ntohs(udp.len);
		if (udp_len < sizeof(udp) ||
		    (!more_frags && !fits(off, udp_len, end)))
			return -1;
		key->sport = bpf_ntohs(udp.source);
		key->dport = bpf_ntohs(udp.dest);
	}
	return 0;
}

static __always_inline int parse_ipv4(struct __sk_buff *skb, __u32 off,
				      struct flow_key *key)
{
	struct iphdr ip;
	__u32 ihl, total;
	__u16 frag;

	if (bpf_skb_load_bytes(skb, off, &ip, sizeof(ip)))
		return -1;
	ihl = (__u32)ip.ihl * 4;
	total = bpf_ntohs(ip.tot_len);
	if (ip.version != 4 || ihl < sizeof(ip) || total < ihl ||
	    !fits(off, total, skb->len))
		return -1;

	key->family = 4;
	key->proto = ip.protocol;
	__builtin_memcpy(key->src, &ip.saddr, sizeof(ip.saddr));
	__builtin_memcpy(key->dst, &ip.daddr, sizeof(ip.daddr));
	frag = bpf_ntohs(ip.frag_off);
	/* Non-initial fragments have no usable transport header. */
	if (frag & IPV4_FRAG_OFFSET)
		return 0;
	return parse_ports(skb, off + ihl, off + total,
			   frag & IPV4_MORE_FRAGS, key);
}

static __always_inline int ipv6_is_ext(__u8 proto)
{
	return proto == IPPROTO_HOPOPTS || proto == IPPROTO_ROUTING ||
	       proto == IPPROTO_DSTOPTS || proto == IPPROTO_FRAGMENT ||
	       proto == IPPROTO_AH || proto == IPPROTO_MH ||
	       proto == UNPA_IPPROTO_HIP || proto == UNPA_IPPROTO_SHIM6;
}

static __always_inline int parse_ipv6(struct __sk_buff *skb, __u32 off,
				      struct flow_key *key)
{
	struct ipv6hdr ip;
	__u32 payload, end;
	__u8 next;
	int saw_fragment = 0, more_frags = 0;

	if (bpf_skb_load_bytes(skb, off, &ip, sizeof(ip)) || ip.version != 6)
		return -1;
	off += sizeof(ip);
	payload = bpf_ntohs(ip.payload_len);
	/* IPv6 jumbograms (a Hop-by-Hop option with zero payload_len) are
	 * unsupported. A zero-length payload with No Next Header is valid.
	 */
	if (!fits(off, payload, skb->len) ||
	    (!payload && ip.nexthdr != IPPROTO_NONE))
		return -1;
	end = off + payload;
	next = ip.nexthdr;
	key->family = 6;
	__builtin_memcpy(key->src, &ip.saddr, sizeof(ip.saddr));
	__builtin_memcpy(key->dst, &ip.daddr, sizeof(ip.daddr));

	/* Bound the walk; each read must also fit the IP payload, not just the
	 * SKB (which can include padding). ESP is opaque and ends the walk.
	 */
	for (int i = 0; i < MAX_IPV6_EXT_HEADERS; i++) {
		if (!ipv6_is_ext(next))
			break;
		if (next == IPPROTO_FRAGMENT) {
			struct ipv6_fragment_header frag;
			__u16 flags;

			if (saw_fragment || !fits(off, sizeof(frag), end) ||
			    bpf_skb_load_bytes(skb, off, &frag, sizeof(frag)))
				return -1;
			saw_fragment = 1;
			flags = bpf_ntohs(frag.offset_flags);
			next = frag.next;
			/* The Fragment header's next-header value is all that is
			 * available in a non-initial fragment. Do not walk further.
			 */
			if (flags & IPV6_FRAG_OFFSET) {
				key->proto = next;
				return 0;
			}
			more_frags = flags & IPV6_MORE_FRAGS;
			off += sizeof(frag);
		} else {
			struct ipv6_opt_hdr ext;
			__u32 size;

			if (next == IPPROTO_HOPOPTS && i != 0)
				return -1;
			if (!fits(off, sizeof(ext), end) ||
			    bpf_skb_load_bytes(skb, off, &ext, sizeof(ext)))
				return -1;
			if (next == IPPROTO_AH) {
				size = ((__u32)ext.hdrlen + 2) * 4;
				if (size < 12)
					return -1;
			} else {
				size = ((__u32)ext.hdrlen + 1) * 8;
			}
			if (!fits(off, size, end))
				return -1;
			next = ext.nexthdr;
			off += size;
		}
	}
	if (ipv6_is_ext(next))
		return -1;
	key->proto = next;
	return parse_ports(skb, off, end, more_frags, key);
}

static __always_inline int parse_frame(struct __sk_buff *skb,
				       struct flow_key *key, int l3)
{
	struct ethhdr eth;
	__u32 off = sizeof(eth);
	__u16 proto;

	if (l3) {
		/* No link-layer header (tun, wireguard, ...). */
		off = 0;
		proto = bpf_ntohs(skb->protocol);
	} else {
		if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)))
			return -1;
		proto = bpf_ntohs(eth.h_proto);
	}
	/* Only in-band VLAN tags take up SKB bytes; a hardware-stripped tag
	 * is already absent from the Ethernet header and needs no offset.
	 */
	for (int i = 0; i < MAX_VLAN_TAGS; i++) {
		struct vlan_header vlan;

		if (proto != ETH_P_8021Q && proto != ETH_P_8021AD)
			break;
		if (bpf_skb_load_bytes(skb, off, &vlan, sizeof(vlan)))
			return -1;
		proto = bpf_ntohs(vlan.protocol);
		off += sizeof(vlan);
	}
	if (proto == ETH_P_IP)
		return parse_ipv4(skb, off, key);
	if (proto == ETH_P_IPV6)
		return parse_ipv6(skb, off, key);
	return -1;
}

static __always_inline void count_flow(struct flow_key *key, __u64 bytes,
				       struct link_counters *link)
{
	struct counters initial = { .packets = 1, .bytes = bytes };
	struct counters *existing;

	existing = bpf_map_lookup_elem(&flows, key);
	if (!existing) {
		initial.created_ns = bpf_ktime_get_ns();
		if (!bpf_map_update_elem(&flows, key, &initial, BPF_NOEXIST)) {
			__sync_fetch_and_add(&link->flow_creates, 1);
			return;
		}
		/* An insertion on another CPU may have won the race. */
		existing = bpf_map_lookup_elem(&flows, key);
	}
	if (!existing) {
		__sync_fetch_and_add(&link->flow_errors, 1);
		return;
	}
	__sync_fetch_and_add(&existing->packets, 1);
	__sync_fetch_and_add(&existing->bytes, bytes);
}

static __always_inline int observe(struct __sk_buff *skb, __u8 direction)
{
	struct link_key link_key = { .ifindex = skb->ifindex,
				     .direction = direction };
	struct flow_key key = { .ifindex = link_key.ifindex,
				.direction = direction };
	struct link_counters *link;
	__u64 bytes = skb->len;

	link = bpf_map_lookup_elem(&links, &link_key);
	if (!link)
		return TC_ACT_UNSPEC;
	__sync_fetch_and_add(&link->packets, 1);
	__sync_fetch_and_add(&link->bytes, bytes);
	if (parse_frame(skb, &key, link->l3))
		__sync_fetch_and_add(&link->unparsed, 1);
	else
		count_flow(&key, bytes, link);
	return TC_ACT_UNSPEC;
}

SEC("tc")
int unpa_ingress(struct __sk_buff *skb)
{
	return observe(skb, UNPA_GUEST_TX);
}

SEC("tc")
int unpa_egress(struct __sk_buff *skb)
{
	return observe(skb, UNPA_GUEST_RX);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
