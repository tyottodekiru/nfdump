#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <argp.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "nfdump_legacy.skel.h"

#define MAX_TABLE_NAME 32
#define MAX_CHAIN_NAME 32

// Packet information structure (must match BPF program)
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

// Filter configuration keys (must match BPF program)
#define FILTER_HOST_IP_KEY      0
#define FILTER_SRC_IP_KEY       1
#define FILTER_DST_IP_KEY       2
#define FILTER_SRC_PORT_KEY     3
#define FILTER_DST_PORT_KEY     4
#define FILTER_PROTOCOL_KEY     5
#define FILTER_ENABLE_KEY       6

// Global variables
static struct nfdump_legacy_bpf *skel = NULL;
static volatile bool exiting = false;

// Configuration structure
struct config {
    char *src_ip;
    char *dst_ip;
    char *host;
    int src_port;
    int dst_port;
    char *protocol;
    bool verbose;
};

// Hook names mapping
static const char *hook_names[] = {
    "PREROUTING",
    "INPUT",
    "FORWARD", 
    "OUTPUT",
    "POSTROUTING"
};

// Protocol names mapping
static const char *protocol_names[] = {
    [1] = "ICMP",
    [6] = "TCP", 
    [17] = "UDP"
};

// Signal handler
static void sig_handler(int sig) {
    exiting = true;
}

// Helper function to convert IP string to network byte order
static int parse_ip(const char *ip_str, __u32 *ip_addr) {
    struct in_addr addr;
    if (inet_aton(ip_str, &addr) == 0) {
        return -1;
    }
    *ip_addr = addr.s_addr;
    return 0;
}

// Helper function to get protocol number from name
static int get_protocol_number(const char *proto_name) {
    if (strcasecmp(proto_name, "tcp") == 0) {
        return 6;
    } else if (strcasecmp(proto_name, "udp") == 0) {
        return 17;
    } else if (strcasecmp(proto_name, "icmp") == 0) {
        return 1;
    }
    return atoi(proto_name);
}

// Setup filters in BPF map
static int setup_filters(struct config *cfg) {
    int filter_map_fd = bpf_map__fd(skel->maps.filter_config);
    if (filter_map_fd < 0) {
        fprintf(stderr, "Failed to get filter map fd: %s\n", strerror(errno));
        return -1;
    }

    // Check if any filters are configured
    bool has_filters = cfg->host || cfg->src_ip || cfg->dst_ip || 
                      cfg->src_port > 0 || cfg->dst_port > 0 || cfg->protocol;

    if (!has_filters) {
        // No filters, disable filtering
        __u32 key = FILTER_ENABLE_KEY;
        __u32 value = 0;
        if (bpf_map_update_elem(filter_map_fd, &key, &value, BPF_ANY) < 0) {
            fprintf(stderr, "Failed to disable filters: %s\n", strerror(errno));
            return -1;
        }
        return 0;
    }

    // Enable filtering
    __u32 key = FILTER_ENABLE_KEY;
    __u32 value = 1;
    if (bpf_map_update_elem(filter_map_fd, &key, &value, BPF_ANY) < 0) {
        fprintf(stderr, "Failed to enable filters: %s\n", strerror(errno));
        return -1;
    }

    // Set host filter
    if (cfg->host) {
        __u32 host_ip;
        if (parse_ip(cfg->host, &host_ip) < 0) {
            fprintf(stderr, "Invalid host IP: %s\n", cfg->host);
            return -1;
        }
        key = FILTER_HOST_IP_KEY;
        if (bpf_map_update_elem(filter_map_fd, &key, &host_ip, BPF_ANY) < 0) {
            fprintf(stderr, "Failed to set host filter: %s\n", strerror(errno));
            return -1;
        }
        if (cfg->verbose) {
            printf("Host filter set: %s (0x%08x)\n", cfg->host, host_ip);
        }
    }

    // Set source IP filter
    if (cfg->src_ip) {
        __u32 src_ip;
        if (parse_ip(cfg->src_ip, &src_ip) < 0) {
            fprintf(stderr, "Invalid source IP: %s\n", cfg->src_ip);
            return -1;
        }
        key = FILTER_SRC_IP_KEY;
        if (bpf_map_update_elem(filter_map_fd, &key, &src_ip, BPF_ANY) < 0) {
            fprintf(stderr, "Failed to set source IP filter: %s\n", strerror(errno));
            return -1;
        }
        if (cfg->verbose) {
            printf("Source IP filter set: %s\n", cfg->src_ip);
        }
    }

    // Set destination IP filter  
    if (cfg->dst_ip) {
        __u32 dst_ip;
        if (parse_ip(cfg->dst_ip, &dst_ip) < 0) {
            fprintf(stderr, "Invalid destination IP: %s\n", cfg->dst_ip);
            return -1;
        }
        key = FILTER_DST_IP_KEY;
        if (bpf_map_update_elem(filter_map_fd, &key, &dst_ip, BPF_ANY) < 0) {
            fprintf(stderr, "Failed to set destination IP filter: %s\n", strerror(errno));
            return -1;
        }
        if (cfg->verbose) {
            printf("Destination IP filter set: %s\n", cfg->dst_ip);
        }
    }

    // Set source port filter
    if (cfg->src_port > 0) {
        key = FILTER_SRC_PORT_KEY;
        value = cfg->src_port;
        if (bpf_map_update_elem(filter_map_fd, &key, &value, BPF_ANY) < 0) {
            fprintf(stderr, "Failed to set source port filter: %s\n", strerror(errno));
            return -1;
        }
        if (cfg->verbose) {
            printf("Source port filter set: %d\n", cfg->src_port);
        }
    }

    // Set destination port filter
    if (cfg->dst_port > 0) {
        key = FILTER_DST_PORT_KEY;
        value = cfg->dst_port;
        if (bpf_map_update_elem(filter_map_fd, &key, &value, BPF_ANY) < 0) {
            fprintf(stderr, "Failed to set destination port filter: %s\n", strerror(errno));
            return -1;
        }
        if (cfg->verbose) {
            printf("Destination port filter set: %d\n", cfg->dst_port);
        }
    }

    // Set protocol filter
    if (cfg->protocol) {
        int proto_num = get_protocol_number(cfg->protocol);
        if (proto_num <= 0 || proto_num > 255) {
            fprintf(stderr, "Invalid protocol: %s\n", cfg->protocol);
            return -1;
        }
        key = FILTER_PROTOCOL_KEY;
        value = proto_num;
        if (bpf_map_update_elem(filter_map_fd, &key, &value, BPF_ANY) < 0) {
            fprintf(stderr, "Failed to set protocol filter: %s\n", strerror(errno));
            return -1;
        }
        if (cfg->verbose) {
            printf("Protocol filter set: %s (%d)\n", cfg->protocol, proto_num);
        }
    }

    return 0;
}

// Format IP address for display
static void format_ip(__u32 ip, char *buf, size_t buf_size) {
    struct in_addr addr;
    addr.s_addr = ip;
    snprintf(buf, buf_size, "%s", inet_ntoa(addr));
}

// Get protocol name
static const char *get_protocol_name(__u8 protocol) {
    if (protocol < sizeof(protocol_names)/sizeof(protocol_names[0]) && 
        protocol_names[protocol] != NULL) {
        return protocol_names[protocol];
    }
    static char buf[16];
    snprintf(buf, sizeof(buf), "PROTO_%d", protocol);
    return buf;
}

// Ring buffer callback for handling events
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct packet_info *info = data;
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    
    if (data_sz < sizeof(*info)) {
        fprintf(stderr, "Invalid event size: %zu\n", data_sz);
        return 0;
    }

    // Format IP addresses
    format_ip(info->src_ip, src_ip_str, sizeof(src_ip_str));
    format_ip(info->dst_ip, dst_ip_str, sizeof(dst_ip_str));

    // Get hook name
    const char *hook_name = "UNKNOWN";
    if (info->hook_num < sizeof(hook_names)/sizeof(hook_names[0])) {
        hook_name = hook_names[info->hook_num];
    }

    // Get protocol name
    const char *proto_name = get_protocol_name(info->protocol);

    // Get timestamp
    double timestamp = info->timestamp / 1e9;

    // Determine table type for legacy
    const char *table_type = "LEGACY";
    if (strncmp(info->table_name, "filter", 6) == 0 ||
        strncmp(info->table_name, "nat", 3) == 0 ||
        strncmp(info->table_name, "mangle", 6) == 0 ||
        strncmp(info->table_name, "raw", 3) == 0 ||
        strncmp(info->table_name, "security", 8) == 0) {
        table_type = "IPT";
    } else if (strncmp(info->table_name, "conntrack", 9) == 0) {
        table_type = "CT";
    } else if (strncmp(info->table_name, "ip6", 3) == 0) {
        table_type = "IP6T";
    }

    // Print event
    printf("%17.6f IPv4     %-11s %-11s %-15s %-15s %-5s %5u %5u %5u %s\n",
           timestamp,
           info->table_name,
           hook_name,
           src_ip_str,
           dst_ip_str,
           proto_name,
           info->src_port,
           info->dst_port,
           info->packet_len,
           table_type);

    return 1; // Return 1 to indicate successful event processing
}

// Libbpf print callback
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

// Argp configuration
static char doc[] = "NetFilter Legacy Monitor - Track packets through iptables tables and chains using BPF CO-RE";
static char args_doc[] = "";

static struct argp_option options[] = {
    {"src-ip", 's', "IP", 0, "Filter by source IP address"},
    {"dst-ip", 'd', "IP", 0, "Filter by destination IP address"},
    {"host", 'H', "IP", 0, "Filter by host (source or destination IP)"},
    {"src-port", 'S', "PORT", 0, "Filter by source port"},
    {"dst-port", 'D', "PORT", 0, "Filter by destination port"},
    {"protocol", 'p', "PROTOCOL", 0, "Filter by protocol (tcp, udp, icmp, or number)"},
    {"verbose", 'v', 0, 0, "Verbose output"},
    {0}
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct config *cfg = state->input;

    switch (key) {
        case 's':
            cfg->src_ip = arg;
            break;
        case 'd':
            cfg->dst_ip = arg;
            break;
        case 'H':
            cfg->host = arg;
            break;
        case 'S':
            cfg->src_port = atoi(arg);
            break;
        case 'D':
            cfg->dst_port = atoi(arg);
            break;
        case 'p':
            cfg->protocol = arg;
            break;
        case 'v':
            cfg->verbose = true;
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc, NULL, NULL, NULL};

int main(int argc, char **argv) {
    struct config cfg = {};
    struct ring_buffer *rb = NULL;
    int err;

    // Parse command line arguments
    err = argp_parse(&argp, argc, argv, 0, NULL, &cfg);
    if (err) {
        return err;
    }

    // Check if running as root
    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root\n");
        return 1;
    }

    // Setup signal handlers
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Set up libbpf errors and debug info callback
    if (cfg.verbose) {
        libbpf_set_print(libbpf_print_fn);
    }

    // Open and load BPF application
    skel = nfdump_legacy_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Load & verify BPF program
    err = nfdump_legacy_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // Setup filters
    err = setup_filters(&cfg);
    if (err) {
        fprintf(stderr, "Failed to setup filters\n");
        goto cleanup;
    }

    // Attach BPF programs
    err = nfdump_legacy_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    if (cfg.verbose) {
        printf("Successfully loaded and attached BPF CO-RE programs\n");
        printf("Monitoring netfilter hooks using fentry probes (Legacy IPTables focus)...\n");
    }

    // Set up ring buffer polling
    rb = ring_buffer__new(bpf_map__fd(skel->maps.packet_events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    // Print header
    printf("\nNetFilter Legacy Monitor - BPF CO-RE Implementation (IPTables Focus)\n");
    printf("Time              PF       Table       Chain       Src IP          Dst IP          Proto  SPort  DPort   Len  Type\n");
    printf("------------------------------------------------------------------------------------------------------------------------\n");

    // Main event loop
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    nfdump_legacy_bpf__destroy(skel);

    if (cfg.verbose) {
        printf("\nCleaned up and exiting\n");
    }

    return err < 0 ? -err : 0;
}