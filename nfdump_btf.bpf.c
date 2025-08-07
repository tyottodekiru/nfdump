#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define MAX_TABLE_NAME 32
#define MAX_CHAIN_NAME 32
#define ETH_HLEN 14
#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF

// xt_table structure for reading table names
// Using CO-RE for better compatibility
struct xt_table_compat {
    char name[32];
} __attribute__((preserve_access_index));

// Packet information structure for events
struct packet_info {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 hook_num;
    __u8 pf;
    __u8 verdict;
    __u64 timestamp;
    __u16 packet_len;
    char table_name[MAX_TABLE_NAME];
    char chain_name[MAX_CHAIN_NAME];
};

// Maps for data communication and filtering
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} packet_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u32);
} filter_config SEC(".maps");

// Filter configuration keys
#define FILTER_HOST_IP_KEY      0
#define FILTER_SRC_IP_KEY       1
#define FILTER_DST_IP_KEY       2
#define FILTER_SRC_PORT_KEY     3
#define FILTER_DST_PORT_KEY     4
#define FILTER_PROTOCOL_KEY     5
#define FILTER_ENABLE_KEY       6

// Enhanced filter function with comprehensive filtering options
static __always_inline int packet_matches_filter(struct packet_info *info) {
    __u32 key = FILTER_ENABLE_KEY;
    __u32 *enabled = bpf_map_lookup_elem(&filter_config, &key);
    if (!enabled || *enabled == 0) {
        return 1; // No filter enabled, pass all packets
    }
    
    // Host filter (source or destination must match)
    key = FILTER_HOST_IP_KEY;
    __u32 *host_ip = bpf_map_lookup_elem(&filter_config, &key);
    if (host_ip && *host_ip != 0) {
        if (info->src_ip != *host_ip && info->dst_ip != *host_ip) {
            return 0;
        }
    }
    
    // Source IP filter
    key = FILTER_SRC_IP_KEY;
    __u32 *src_ip = bpf_map_lookup_elem(&filter_config, &key);
    if (src_ip && *src_ip != 0) {
        if (info->src_ip != *src_ip) {
            return 0;
        }
    }
    
    // Destination IP filter
    key = FILTER_DST_IP_KEY;
    __u32 *dst_ip = bpf_map_lookup_elem(&filter_config, &key);
    if (dst_ip && *dst_ip != 0) {
        if (info->dst_ip != *dst_ip) {
            return 0;
        }
    }
    
    // Source port filter
    key = FILTER_SRC_PORT_KEY;
    __u32 *src_port = bpf_map_lookup_elem(&filter_config, &key);
    if (src_port && *src_port != 0) {
        if (info->src_port != (__u16)*src_port) {
            return 0;
        }
    }
    
    // Destination port filter
    key = FILTER_DST_PORT_KEY;
    __u32 *dst_port = bpf_map_lookup_elem(&filter_config, &key);
    if (dst_port && *dst_port != 0) {
        if (info->dst_port != (__u16)*dst_port) {
            return 0;
        }
    }
    
    // Protocol filter
    key = FILTER_PROTOCOL_KEY;
    __u32 *protocol = bpf_map_lookup_elem(&filter_config, &key);
    if (protocol && *protocol != 0) {
        if (info->protocol != (__u8)*protocol) {
            return 0;
        }
    }
    
    return 1; // All filters passed
}

static __always_inline void set_chain_name(struct packet_info *info, __u8 hook) {
    switch (hook) {
        case NF_INET_PRE_ROUTING:
            __builtin_memcpy(info->chain_name, "PREROUTING", 11);
            break;
        case NF_INET_LOCAL_IN:
            __builtin_memcpy(info->chain_name, "INPUT", 6);
            break;
        case NF_INET_FORWARD:
            __builtin_memcpy(info->chain_name, "FORWARD", 8);
            break;
        case NF_INET_LOCAL_OUT:
            __builtin_memcpy(info->chain_name, "OUTPUT", 7);
            break;
        case NF_INET_POST_ROUTING:
            __builtin_memcpy(info->chain_name, "POSTROUTING", 12);
            break;
        default:
            __builtin_memcpy(info->chain_name, "UNKNOWN", 8);
            break;
    }
}

// Enhanced packet parsing with better CO-RE support
static __always_inline int parse_ip_packet(struct sk_buff *skb, struct packet_info *info) {
    void *data_start = NULL;
    __u32 data_len = 0;
    
    // Use BPF CO-RE to read sk_buff fields
    if (bpf_core_read(&data_start, sizeof(data_start), &skb->data) < 0)
        return -1;
        
    if (bpf_core_read(&data_len, sizeof(data_len), &skb->len) < 0)
        return -1;

    info->packet_len = data_len;
    
    // Validate packet size - at IP layer, no Ethernet header
    if (data_len < sizeof(struct iphdr))
        return -1;

    // Parse IP header using CO-RE - data_start already points to IP header
    struct iphdr ip_hdr = {};
    if (bpf_core_read(&ip_hdr, sizeof(ip_hdr), data_start) < 0)
        return -1;

    // Validate IP version
    if (ip_hdr.version != 4)
        return -1;

    // Extract IP addresses and protocol
    info->src_ip = ip_hdr.saddr;
    info->dst_ip = ip_hdr.daddr;
    info->protocol = ip_hdr.protocol;

    // Calculate IP header length
    __u8 ip_hdr_len = ip_hdr.ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return -1;

    // Skip fragmented packets for transport header parsing
    if (ip_hdr.frag_off & bpf_htons(IP_MF | IP_OFFSET))
        return 0;

    // Parse transport layer headers
    void *l4_hdr = data_start + ip_hdr_len;
    
    if (ip_hdr.protocol == IPPROTO_TCP) {
        struct tcphdr tcp_hdr = {};
        if (bpf_core_read(&tcp_hdr, sizeof(tcp_hdr), l4_hdr) == 0) {
            info->src_port = bpf_ntohs(tcp_hdr.source);
            info->dst_port = bpf_ntohs(tcp_hdr.dest);
        }
    } else if (ip_hdr.protocol == IPPROTO_UDP) {
        struct udphdr udp_hdr = {};
        if (bpf_core_read(&udp_hdr, sizeof(udp_hdr), l4_hdr) == 0) {
            info->src_port = bpf_ntohs(udp_hdr.source);
            info->dst_port = bpf_ntohs(udp_hdr.dest);
        }
    } else if (ip_hdr.protocol == IPPROTO_ICMP) {
        struct icmphdr icmp_hdr = {};
        if (bpf_core_read(&icmp_hdr, sizeof(icmp_hdr), l4_hdr) == 0) {
            info->src_port = icmp_hdr.type;
            info->dst_port = icmp_hdr.code;
        }
    }

    return 0;
}

// IP receive hook - catches all IPv4 packets
SEC("fentry/ip_rcv")
int BPF_PROG(trace_ip_rcv, struct sk_buff *skb, void *dev, void *pt, void *orig_dev) {
    struct packet_info info = {};
    
    info.timestamp = bpf_ktime_get_ns();
    info.verdict = 0;
    info.hook_num = 1; // INPUT
    info.pf = NFPROTO_IPV4;
    
    // Parse packet
    if (parse_ip_packet(skb, &info) < 0)
        return 0;

    __builtin_memcpy(info.table_name, "ip_rcv", 7);
    __builtin_memcpy(info.chain_name, "INPUT", 6);

    if (!packet_matches_filter(&info))
        return 0;

    bpf_ringbuf_output(&packet_events, &info, sizeof(info), 0);
    return 0;
}

// IP output hook - catches outgoing IPv4 packets  
SEC("fentry/ip_output")
int BPF_PROG(trace_ip_output, void *net, void *sk, struct sk_buff *skb) {
    struct packet_info info = {};
    
    info.timestamp = bpf_ktime_get_ns();
    info.verdict = 0;
    info.hook_num = 3; // OUTPUT
    info.pf = NFPROTO_IPV4;
    
    // Parse packet
    if (parse_ip_packet(skb, &info) < 0)
        return 0;

    __builtin_memcpy(info.table_name, "ip_out", 7);
    __builtin_memcpy(info.chain_name, "OUTPUT", 7);

    if (!packet_matches_filter(&info))
        return 0;

    bpf_ringbuf_output(&packet_events, &info, sizeof(info), 0);
    return 0;
}

// IP forwarding hook  
SEC("fentry/ip_forward")
int BPF_PROG(trace_ip_forward, struct sk_buff *skb) {
    struct packet_info info = {};
    
    info.timestamp = bpf_ktime_get_ns();
    info.verdict = 0;
    info.hook_num = 2; // FORWARD
    info.pf = NFPROTO_IPV4;
    
    // Parse packet
    if (parse_ip_packet(skb, &info) < 0)
        return 0;

    __builtin_memcpy(info.table_name, "ip_forward", 11);
    __builtin_memcpy(info.chain_name, "FORWARD", 8);

    if (!packet_matches_filter(&info))
        return 0;

    bpf_ringbuf_output(&packet_events, &info, sizeof(info), 0);
    return 0;
}

// Local delivery hook
SEC("fentry/ip_local_deliver")
int BPF_PROG(trace_ip_local_deliver, struct sk_buff *skb) {
    struct packet_info info = {};
    
    info.timestamp = bpf_ktime_get_ns();
    info.verdict = 0;
    info.hook_num = 1; // INPUT
    info.pf = NFPROTO_IPV4;
    
    // Parse packet
    if (parse_ip_packet(skb, &info) < 0)
        return 0;

    __builtin_memcpy(info.table_name, "local_deliv", 12);
    __builtin_memcpy(info.chain_name, "FASTPATH", 9);

    if (!packet_matches_filter(&info))
        return 0;

    bpf_ringbuf_output(&packet_events, &info, sizeof(info), 0);
    return 0;
}

// Main netfilter hook tracing - comprehensive coverage
SEC("fentry/nf_hook_slow")
int BPF_PROG(trace_nf_hook_slow, struct sk_buff *skb, struct nf_hook_state *state) {
    struct packet_info info = {};
    
    info.timestamp = bpf_ktime_get_ns();
    info.verdict = 0; // Default verdict
    
    // Read netfilter hook state using CO-RE
    if (bpf_core_read(&info.hook_num, sizeof(info.hook_num), &state->hook) < 0)
        return 0;
    
    if (bpf_core_read(&info.pf, sizeof(info.pf), &state->pf) < 0)
        return 0;

    // Focus on IPv4 packets
    if (info.pf != NFPROTO_IPV4)
        return 0;

    // Parse packet data
    if (parse_ip_packet(skb, &info) < 0)
        return 0;

    // Set table/chain information
    __builtin_memcpy(info.table_name, "netfilter", 10);
    set_chain_name(&info, info.hook_num);

    // Apply filters
    if (!packet_matches_filter(&info))
        return 0;

    // Submit event to userspace
    bpf_ringbuf_output(&packet_events, &info, sizeof(info), 0);
    return 0;
}

// iptables table processing hook
SEC("fentry/ipt_do_table")
int BPF_PROG(trace_ipt_do_table, struct sk_buff *skb, struct nf_hook_state *state, void *table) {
    struct packet_info info = {};
    
    info.timestamp = bpf_ktime_get_ns();
    info.verdict = 0;
    
    // Read hook state
    if (bpf_core_read(&info.hook_num, sizeof(info.hook_num), &state->hook) < 0)
        return 0;
    
    if (bpf_core_read(&info.pf, sizeof(info.pf), &state->pf) < 0)
        return 0;

    // IPv4 only
    if (info.pf != NFPROTO_IPV4)
        return 0;

    // Parse packet
    if (parse_ip_packet(skb, &info) < 0)
        return 0;

    // Simple approach: Mark that we hit ipt_do_table and try to read table name
    __builtin_memcpy(info.table_name, "IPT_CALLED", 11);
    
    // Try to read table name using proper structure access
    if (table) {
        // Try reading first few bytes to see if we can find table name
        char name_attempt[16] = {};
        if (bpf_probe_read_kernel(name_attempt, sizeof(name_attempt), table) == 0) {
            // Check if first bytes look like a table name
            if ((name_attempt[0] == 'f' && name_attempt[1] == 'i' && name_attempt[2] == 'l') || // "filter"
                (name_attempt[0] == 'n' && name_attempt[1] == 'a' && name_attempt[2] == 't') || // "nat"  
                (name_attempt[0] == 'm' && name_attempt[1] == 'a' && name_attempt[2] == 'n') || // "mangle"
                (name_attempt[0] == 'r' && name_attempt[1] == 'a' && name_attempt[2] == 'w') || // "raw"
                (name_attempt[0] == 's' && name_attempt[1] == 'e' && name_attempt[2] == 'c')) { // "security"
                __builtin_memcpy(info.table_name, name_attempt, 15);
                info.table_name[15] = '\0';
            }
        }
    }

    set_chain_name(&info, info.hook_num);

    if (!packet_matches_filter(&info))
        return 0;

    bpf_ringbuf_output(&packet_events, &info, sizeof(info), 0);
    return 0;
}

// IPv6 tables support - commented out due to kernel compatibility
// SEC("fentry/ip6t_do_table")
// int BPF_PROG(trace_ip6t_do_table, struct sk_buff *skb, struct nf_hook_state *state, void *table) {
//     // Implementation removed for compatibility
//     return 0;
// }

// nftables support - commented out due to kernel compatibility
// SEC("fentry/nft_do_chain")
// int BPF_PROG(trace_nft_do_chain, void *pkt, void *priv) {
//     // Implementation removed for compatibility  
//     return 0;
// }

// Connection tracking hook - commented out due to kernel compatibility  
// SEC("fentry/nf_conntrack_in")
// int BPF_PROG(trace_nf_conntrack_in, struct sk_buff *skb, struct nf_hook_state *state) {
//     // Implementation removed for compatibility
//     return 0;
// }

char LICENSE[] SEC("license") = "GPL";