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

// iptables table structure for reading table names (legacy focus)
struct xt_table {
    struct list_head list;
    unsigned int valid_hooks;
    struct xt_table_info *private;
    void *me;
    u_int8_t af;
    int priority;
    const char name[];
} __attribute__((preserve_access_index));

// nftables chain structure for reading chain info
struct nft_chain {
    struct list_head list;
    struct rhltable rules_ht;
    struct list_head rules;
    struct list_head hook_list;
    struct nft_table *table;  // Pointer to table
    u64 handle;
    u32 use;
    u8 flags;
    u8 family;
    char *name;
} __attribute__((preserve_access_index));

// nftables table structure for reading table names
struct nft_table {
    struct list_head list;
    struct rhltable chains_ht;
    struct list_head chains;
    struct list_head sets;
    struct list_head objects;
    struct list_head flowtables;  
    u64 hgeneseq;
    u32 use;
    u16 family;
    u16 flags;
    u32 nlpid;
    char *name;
    u16 udlen;
    u8 *udata;
} __attribute__((preserve_access_index));

// nftables packet info structure
struct nft_pktinfo {
    struct sk_buff *skb;
    struct nf_hook_state *xt;
    bool tprot_set;
    u8 tprot;
    u16 fragoff;
    u16 thoff;
    u16 inneroff;
} __attribute__((preserve_access_index));

// iptables rule target structure
struct xt_entry_target {
    union {
        struct {
            __u16 target_size;
            char name[29];
            __u8 revision;
        } user;
        struct {
            __u16 target_size;
            void *target;
        } kernel;
        __u16 target_size;
    } u;
    unsigned char data[];
} __attribute__((preserve_access_index));

// iptables rule match structure  
struct xt_entry_match {
    union {
        struct {
            __u16 match_size;
            char name[29];
            __u8 revision;
        } user;
        struct {
            __u16 match_size;
            void *match;
        } kernel;
        __u16 match_size;
    } u;
    unsigned char data[];
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
    // Initialize with null terminator for safety
    info->chain_name[0] = '\0';
    
    switch (hook) {
        case NF_INET_PRE_ROUTING:
            __builtin_memcpy(info->chain_name, "PREROUTING\0", 11);
            break;
        case NF_INET_LOCAL_IN:
            __builtin_memcpy(info->chain_name, "INPUT\0", 6);
            break;
        case NF_INET_FORWARD:
            __builtin_memcpy(info->chain_name, "FORWARD\0", 8);
            break;
        case NF_INET_LOCAL_OUT:
            __builtin_memcpy(info->chain_name, "OUTPUT\0", 7);
            break;
        case NF_INET_POST_ROUTING:
            __builtin_memcpy(info->chain_name, "POSTROUTING\0", 12);
            break;
        default:
            __builtin_memcpy(info->chain_name, "UNKNOWN\0", 8);
            break;
    }
}

// Helper function for safe table name extraction (same as nftables version)
static __always_inline int extract_table_name(struct packet_info *info, const char *table_name_ptr, const char *default_name) {
    // Initialize table name to default
    __builtin_memset(info->table_name, 0, MAX_TABLE_NAME);
    if (default_name) {
        int i = 0;
        while (i < (MAX_TABLE_NAME - 1) && default_name[i] != '\0') {
            info->table_name[i] = default_name[i];
            i++;
        }
        info->table_name[MAX_TABLE_NAME - 1] = '\0';
    }
    
    if (!table_name_ptr) {
        return -1;
    }
    
    // Try to read table name string safely
    char table_name_buf[MAX_TABLE_NAME] = {};
    long ret = bpf_probe_read_kernel_str(table_name_buf, sizeof(table_name_buf), table_name_ptr);
    if (ret <= 0) {
        return -1;
    }
    
    // Validate table name (basic sanity check)
    if (table_name_buf[0] == '\0' || table_name_buf[0] < 'a' || table_name_buf[0] > 'z') {
        return -1;
    }
    
    // Copy validated table name
    __builtin_memcpy(info->table_name, table_name_buf, MAX_TABLE_NAME - 1);
    info->table_name[MAX_TABLE_NAME - 1] = '\0';
    
    return 0;
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

// Main netfilter hook tracing - legacy iptables focused
SEC("fentry/nf_hook_slow")
int BPF_PROG(trace_nf_hook_slow_legacy, struct sk_buff *skb, struct nf_hook_state *state) {
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

    // Set table/chain information for legacy - let ipt_do_table set specific names
    __builtin_memcpy(info.table_name, "netfilter", 10);
    set_chain_name(&info, info.hook_num);

    // Apply filters
    if (!packet_matches_filter(&info))
        return 0;

    // Submit event to userspace
    bpf_ringbuf_output(&packet_events, &info, sizeof(info), 0);
    return 0;
}

// iptables table processing hook - enhanced for legacy
SEC("fentry/ipt_do_table")
int BPF_PROG(trace_ipt_do_table_legacy, struct sk_buff *skb, struct nf_hook_state *state, void *table) {
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

    // Enhanced table name detection for iptables legacy
    if (table) {
        struct xt_table *xt_tbl = (struct xt_table *)table;
        const char *table_name_ptr = NULL;
        
        // Use BPF CO-RE to read the name field pointer (same as nftables version)
        if (bpf_core_read(&table_name_ptr, sizeof(table_name_ptr), &xt_tbl->name) == 0) {
            if (extract_table_name(&info, table_name_ptr, "iptables") == 0) {
                // Successfully extracted table name via pointer
            } else {
                // Fallback: try reading the name field as inline array instead of pointer
                char name_buf[MAX_TABLE_NAME] = {};
                if (bpf_probe_read_kernel_str(name_buf, sizeof(name_buf), (char *)&xt_tbl->name) > 0) {
                    if (name_buf[0] != '\0' && name_buf[0] >= 'a' && name_buf[0] <= 'z') {
                        __builtin_memcpy(info.table_name, name_buf, MAX_TABLE_NAME - 1);
                        info.table_name[MAX_TABLE_NAME - 1] = '\0';
                    } else {
                        // Still failed, use debug name
                        __builtin_memcpy(info.table_name, "ipt_debug", 10);
                    }
                } else {
                    __builtin_memcpy(info.table_name, "ipt_fail", 9);
                }
            }
        } else {
            __builtin_memcpy(info.table_name, "ipt_noread", 11);
        }
    } else {
        __builtin_memcpy(info.table_name, "ipt_notbl", 10);
    }

    set_chain_name(&info, info.hook_num);

    if (!packet_matches_filter(&info))
        return 0;

    bpf_ringbuf_output(&packet_events, &info, sizeof(info), 0);
    return 0;
}

// IPv6 tables support - commented out due to kernel compatibility
// SEC("fentry/ip6t_do_table")
// int BPF_PROG(trace_ip6t_do_table_legacy, struct sk_buff *skb, struct nf_hook_state *state, void *table) {
//     // Implementation removed for compatibility
//     return 0;
// }

// nftables support for iptables-nft systems
SEC("fentry/nft_do_chain")
int BPF_PROG(trace_nft_do_chain_legacy, struct nft_pktinfo *pkt, void *priv) {
    struct packet_info info = {};
    struct sk_buff *skb = NULL;
    
    info.timestamp = bpf_ktime_get_ns();
    info.verdict = 0;
    
    // Try to read sk_buff from nft_pktinfo
    if (bpf_probe_read_kernel(&skb, sizeof(skb), pkt) < 0 || !skb)
        return 0;
    
    // Set default values
    info.hook_num = 1; // Default to INPUT
    info.pf = NFPROTO_IPV4;
    
    // Parse packet data
    if (parse_ip_packet(skb, &info) < 0)
        return 0;

    // Extract nftables table name via chain->table->name path (iptables-nft)
    if (priv) {
        struct nft_chain *chain = (struct nft_chain *)priv;
        struct nft_table *table = NULL;
        
        // Read table pointer from nft_chain using BPF CO-RE
        if (bpf_core_read(&table, sizeof(table), &chain->table) == 0 && table) {
            char *table_name_ptr = NULL;
            // Read table name pointer from nft_table using BPF CO-RE
            if (bpf_core_read(&table_name_ptr, sizeof(table_name_ptr), &table->name) == 0 && table_name_ptr) {
                // Successfully got table name via nft_chain->nft_table->name
                if (extract_table_name(&info, table_name_ptr, "nftables") != 0) {
                    // Fallback to iptables-nft indicator
                    __builtin_memcpy(info.table_name, "ipt-nft", 8);
                }
            } else {
                __builtin_memcpy(info.table_name, "nft-noptr", 10);
            }
        } else {
            __builtin_memcpy(info.table_name, "nft-notbl", 10);
        }
    } else {
        __builtin_memcpy(info.table_name, "nft-nop", 8);
    }

    set_chain_name(&info, info.hook_num);

    if (!packet_matches_filter(&info))
        return 0;

    bpf_ringbuf_output(&packet_events, &info, sizeof(info), 0);
    return 0;
}

// Connection tracking hook - legacy focused
SEC("fentry/nf_conntrack_in")
int BPF_PROG(trace_nf_conntrack_in_legacy, struct sk_buff *skb, struct nf_hook_state *state) {
    struct packet_info info = {};
    
    info.timestamp = bpf_ktime_get_ns();
    info.verdict = 0;
    
    // Read hook state
    if (bpf_core_read(&info.hook_num, sizeof(info.hook_num), &state->hook) < 0)
        return 0;
    
    if (bpf_core_read(&info.pf, sizeof(info.pf), &state->pf) < 0)
        return 0;

    // Focus on IPv4 
    if (info.pf != NFPROTO_IPV4)
        return 0;

    // Parse packet
    if (parse_ip_packet(skb, &info) < 0)
        return 0;

    // Mark as conntrack processing
    __builtin_memcpy(info.table_name, "conntrack", 10);
    set_chain_name(&info, info.hook_num);

    if (!packet_matches_filter(&info))
        return 0;

    bpf_ringbuf_output(&packet_events, &info, sizeof(info), 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";