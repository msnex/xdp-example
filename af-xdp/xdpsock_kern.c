// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * Build: clang -g -O2 -target bpf -c xdpsock_kern.c -o xdpsock_kern.o
 * Attach: ip link set dev ens192 xdpgeneric obj xdpsock_kern.o sec xdp_sock
 * Detach: ip link set dev ens192 xdpgeneric off
 * Status: ip link show dev ens192
 */

/* This XDP program is only needed for multi-buffer and XDP_SHARED_UMEM modes.
 * If you do not use these modes, libbpf can supply an XDP program for you.
 */

#define DEFAULT_QUEUE_IDS 64

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, DEFAULT_QUEUE_IDS);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

int num_socks = 0;
// static unsigned int rr = 0;

// SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx)
// {
//     rr = (rr + 1) & (num_socks - 1);
//     bpf_printk("iface rx queue index: %u\n", rr);
//     return bpf_redirect_map(&xsks_map, rr, XDP_DROP);
// }

SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx)
{
    __u32 index = ctx->rx_queue_index;
    // bpf_printk("iface rx queue index: %u\n", index);

    if (bpf_map_lookup_elem(&xsks_map, &index))
        return bpf_redirect_map(&xsks_map, index, XDP_DROP);

    return XDP_PASS;
}
