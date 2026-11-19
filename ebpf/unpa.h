/* SPDX-License-Identifier: MIT */
#ifndef UNPA_H
#define UNPA_H

#include <linux/types.h>

#define UNPA_GUEST_TX 0 /* Host TAP ingress */
#define UNPA_GUEST_RX 1 /* Host TAP egress */

/* 44 bytes. Integers are host byte order; addresses are network-order bytes.
 * IPv4 uses the first four bytes of each address, with the other bytes zero.
 * Ports are zero when unavailable; all reserved bytes must be zero.
 */
struct flow_key {
	__u32 ifindex;
	__u8 family, proto, direction, reserved; /* family is 4 or 6 */
	__u16 sport, dport;
	__u8 src[16], dst[16];
};

/* 24 bytes. created_ns is the monotonic BPF clock at insertion. */
struct counters {
	__u64 packets, bytes, created_ns;
};

/* 8 bytes. Userspace must preseed each monitored interface and direction. */
struct link_key {
	__u32 ifindex;
	__u8 direction;
	__u8 reserved[3];
};

/* 48 bytes. Both maps count observed SKBs and skb->len, not wire packets or
 * bytes; offloads (e.g., GSO/GRO) can change these observations.
 * unparsed counts observations without a flow key (e.g., non-IP, malformed,
 * or unsupported headers). flow_errors counts failed flow accounting;
 * flow_creates counts successful new insertions, including after eviction.
 */
struct link_counters {
	__u64 packets, bytes, unparsed, flow_errors, flow_creates;
	__u32 l3;	/* set by userspace: device has no Ethernet header */
	__u32 reserved;
};

#endif /* UNPA_H */
