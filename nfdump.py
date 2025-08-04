#!/usr/bin/env python3
import sys
import signal
from bcc import BPF
import time
import socket
import struct
import argparse
import ctypes
import os

bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/types.h>
#include <uapi/linux/in.h>

// Simple IP header definition
struct simple_iphdr {
    __u8    ihl:4,
            version:4;
    __u8    tos;
    __u16   tot_len;
    __u16   id;
    __u16   frag_off;
    __u8    ttl;
    __u8    protocol;
    __u16   check;
    __u32   saddr;
    __u32   daddr;
};

struct simple_tcphdr {
    __u16   source;
    __u16   dest;
    __u32   seq;
    __u32   ack_seq;
    __u16   res1:4,
            doff:4,
            fin:1,
            syn:1,
            rst:1,
            psh:1,
            ack:1,
            urg:1,
            ece:1,
            cwr:1;
    __u16   window;
    __u16   check;
    __u16   urg_ptr;
};

struct simple_udphdr {
    __u16   source;
    __u16   dest;
    __u16   len;
    __u16   check;
};

struct packet_info {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
    u32 hooknum;
    u8 pf;
    u64 timestamp;
    u16 packet_len;
    char table_name[32];
    char chain_name[32];
};

BPF_PERF_OUTPUT(packet_events);

struct filter_config {
    u32 filter_src_ip;
    u32 filter_dst_ip;
    u32 filter_host_ip;
    u16 filter_src_port;
    u16 filter_dst_port;
    u8 filter_protocol;
    u8 enable_src_ip_filter;
    u8 enable_dst_ip_filter;
    u8 enable_host_filter;
    u8 enable_src_port_filter;
    u8 enable_dst_port_filter;
    u8 enable_protocol_filter;
};

BPF_HASH(filter_host_ip, u32, u32, 1);
BPF_HASH(filter_enable, u32, u32, 1);

static int packet_matches_filter(struct packet_info *info)
{
    u32 key = 0;
    u32 *enabled = filter_enable.lookup(&key);
    if (!enabled || *enabled == 0) {
        return 1;  // No filter enabled, pass all packets
    }
    
    u32 *host_ip = filter_host_ip.lookup(&key);
    if (!host_ip) {
        return 1;  // No host filter configured
    }
    
    // Host filter: packet must involve the specified host
    if (info->src_ip == *host_ip || info->dst_ip == *host_ip) {
        return 1;  // Host filter matched, pass the packet
    }
    
    return 0;  // No match, drop packet
}

// Structure definitions for netfilter internals
struct nf_hook_state {
    u8 hook;
    u8 pf;
    // Other fields exist but we only need these
};

struct xt_table {
    char name[32];
    // Other fields exist but we only need the name
};

// kprobe for netfilter hooks - comprehensive version
int trace_nf_hook_slow(struct pt_regs *ctx)
{
    struct packet_info info = {};
    
    info.timestamp = bpf_ktime_get_ns();
    info.hooknum = 1;  // Default to INPUT
    info.pf = 2;       // IPv4
    info.protocol = 1; // Default ICMP
    
    // Get sk_buff from first parameter
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    
    // Try to get nf_hook_state from second parameter
    struct nf_hook_state *state = (struct nf_hook_state *)PT_REGS_PARM2(ctx);
    if (state) {
        bpf_probe_read(&info.hooknum, sizeof(info.hooknum), &state->hook);
        bpf_probe_read(&info.pf, sizeof(info.pf), &state->pf);
    }
    
    if (skb) {
        // Direct memory access approach using verified offsets for common kernels
        // Try multiple methods to extract packet data
        
        void *data_ptr = 0;
        u32 len = 0;
        
        // Method 1: Try to read data pointer directly
        bpf_probe_read(&data_ptr, sizeof(data_ptr), (char*)skb + 0xD8);
        bpf_probe_read(&len, sizeof(len), (char*)skb + 0x88);
        
        if (data_ptr && len > 14) { // At least Ethernet header size
            // Try to parse as Ethernet + IP
            struct simple_iphdr ip_hdr;
            
            // Skip Ethernet header (14 bytes) and read IP header
            if (bpf_probe_read(&ip_hdr, sizeof(ip_hdr), data_ptr + 14) == 0) {
                if (ip_hdr.version == 4) {
                    info.src_ip = ip_hdr.saddr;
                    info.dst_ip = ip_hdr.daddr;
                    info.protocol = ip_hdr.protocol;
                    info.packet_len = len;
                    
                    // Parse transport headers
                    u8 ip_hdr_len = ip_hdr.ihl * 4;
                    if (ip_hdr.protocol == 6) { // TCP
                        struct simple_tcphdr tcp_hdr;
                        if (bpf_probe_read(&tcp_hdr, sizeof(tcp_hdr), 
                                         data_ptr + 14 + ip_hdr_len) == 0) {
                            info.src_port = bpf_ntohs(tcp_hdr.source);
                            info.dst_port = bpf_ntohs(tcp_hdr.dest);
                        }
                    } else if (ip_hdr.protocol == 17) { // UDP
                        struct simple_udphdr udp_hdr;
                        if (bpf_probe_read(&udp_hdr, sizeof(udp_hdr), 
                                         data_ptr + 14 + ip_hdr_len) == 0) {
                            info.src_port = bpf_ntohs(udp_hdr.source);
                            info.dst_port = bpf_ntohs(udp_hdr.dest);
                        }
                    }
                    // Success - we have data
                    goto packet_processed;
                }
            }
        }
        
        // Method 2: Try alternative offsets if Method 1 failed
        bpf_probe_read(&data_ptr, sizeof(data_ptr), (char*)skb + 0xC8);
        if (data_ptr && len > 0) {
            struct simple_iphdr ip_hdr;
            if (bpf_probe_read(&ip_hdr, sizeof(ip_hdr), data_ptr) == 0) {
                if (ip_hdr.version == 4) {
                    info.src_ip = ip_hdr.saddr;
                    info.dst_ip = ip_hdr.daddr;
                    info.protocol = ip_hdr.protocol;
                    info.packet_len = len;
                }
            }
        }
        
        packet_processed:;
    }
    
    // Try to get hook number from function parameters (fallback method)
    u32 hooknum = 0;
    bpf_probe_read(&hooknum, sizeof(hooknum), (void *)PT_REGS_PARM3(ctx));
    if (hooknum < 5) {
        info.hooknum = hooknum;
    }
    
    // Set table/chain names
    __builtin_memcpy(info.table_name, "filter", 7);
    
    switch (info.hooknum) {
        case 0:
            __builtin_memcpy(info.chain_name, "PREROUTING", 11);
            break;
        case 1:
            __builtin_memcpy(info.chain_name, "INPUT", 6);
            break;
        case 2:
            __builtin_memcpy(info.chain_name, "FORWARD", 8);
            break;
        case 3:
            __builtin_memcpy(info.chain_name, "OUTPUT", 7);
            break;
        case 4:
            __builtin_memcpy(info.chain_name, "POSTROUTING", 12);
            break;
        default:
            __builtin_memcpy(info.chain_name, "UNKNOWN", 8);
            break;
    }
    
    if (packet_matches_filter(&info)) {
        packet_events.perf_submit(ctx, &info, sizeof(info));
    }
    
    return 0;
}

// Specialized probes for specific table functions
int trace_ipt_do_table(struct pt_regs *ctx)
{
    struct packet_info info = {};
    
    info.timestamp = bpf_ktime_get_ns();
    info.pf = 2;       // IPv4
    info.protocol = 1; // Default ICMP
    
    // Get sk_buff from first parameter
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    
    // Get hook number from second parameter (typically the state)
    struct nf_hook_state *state = (struct nf_hook_state *)PT_REGS_PARM2(ctx);
    if (state) {
        bpf_probe_read(&info.hooknum, sizeof(info.hooknum), &state->hook);
        bpf_probe_read(&info.pf, sizeof(info.pf), &state->pf);
    }
    
    // Get table from third parameter
    struct xt_table *table = (struct xt_table *)PT_REGS_PARM3(ctx);
    if (table) {
        bpf_probe_read_str(info.table_name, sizeof(info.table_name), table->name);
    } else {
        __builtin_memcpy(info.table_name, "iptables", 9);
    }
    
    if (skb) {
        void *data_ptr = 0;
        u32 len = 0;
        
        bpf_probe_read(&data_ptr, sizeof(data_ptr), (char*)skb + 0xD8);
        bpf_probe_read(&len, sizeof(len), (char*)skb + 0x88);
        
        if (data_ptr && len > 14) {
            struct simple_iphdr ip_hdr;
            
            if (bpf_probe_read(&ip_hdr, sizeof(ip_hdr), data_ptr + 14) == 0) {
                if (ip_hdr.version == 4) {
                    info.src_ip = ip_hdr.saddr;
                    info.dst_ip = ip_hdr.daddr;
                    info.protocol = ip_hdr.protocol;
                    info.packet_len = len;
                    
                    u8 ip_hdr_len = ip_hdr.ihl * 4;
                    if (ip_hdr.protocol == 6) { // TCP
                        struct simple_tcphdr tcp_hdr;
                        if (bpf_probe_read(&tcp_hdr, sizeof(tcp_hdr), 
                                         data_ptr + 14 + ip_hdr_len) == 0) {
                            info.src_port = bpf_ntohs(tcp_hdr.source);
                            info.dst_port = bpf_ntohs(tcp_hdr.dest);
                        }
                    } else if (ip_hdr.protocol == 17) { // UDP
                        struct simple_udphdr udp_hdr;
                        if (bpf_probe_read(&udp_hdr, sizeof(udp_hdr), 
                                         data_ptr + 14 + ip_hdr_len) == 0) {
                            info.src_port = bpf_ntohs(udp_hdr.source);
                            info.dst_port = bpf_ntohs(udp_hdr.dest);
                        }
                    }
                }
            }
        }
    }
    
    // Set chain names based on hook number
    switch (info.hooknum) {
        case 0:
            __builtin_memcpy(info.chain_name, "PREROUTING", 11);
            break;
        case 1:
            __builtin_memcpy(info.chain_name, "INPUT", 6);
            break;
        case 2:
            __builtin_memcpy(info.chain_name, "FORWARD", 8);
            break;
        case 3:
            __builtin_memcpy(info.chain_name, "OUTPUT", 7);
            break;
        case 4:
            __builtin_memcpy(info.chain_name, "POSTROUTING", 12);
            break;
        default:
            __builtin_memcpy(info.chain_name, "UNKNOWN", 8);
            break;
    }
    
    if (packet_matches_filter(&info)) {
        packet_events.perf_submit(ctx, &info, sizeof(info));
    }
    
    return 0;
}


"""


class NetFilterMonitor:
    def __init__(self, src_ip=None, dst_ip=None, host=None, src_port=None, dst_port=None, protocol=None, verbose=False):
        self.bpf = None
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.host = host
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.verbose = verbose
        self.hook_names = {
            0: "PREROUTING",
            1: "INPUT",
            2: "FORWARD",
            3: "OUTPUT",
            4: "POSTROUTING"
        }
        self.pf_names = {
            0: "UNSPEC",
            1: "UNIX", 
            2: "IPv4",
            3: "AX25",
            4: "IPX",
            5: "APPLETALK",
            6: "NETROM",
            7: "BRIDGE",
            8: "ATMPVC", 
            9: "X25",
            10: "IPv6",
            11: "ROSE",
            12: "DECnet",
            13: "NETBEUI",
            14: "SECURITY",
            15: "KEY",
            16: "NETLINK",
            17: "PACKET",
            18: "ASH",
            19: "ECONET",
            20: "ATMSVC",
            21: "RDS",
            22: "SNA",
            23: "IRDA",
            24: "PPPOX",
            25: "WANPIPE",
            26: "LLC",
            27: "IB",
            28: "MPLS",
            29: "CAN",
            30: "TIPC",
            31: "BLUETOOTH",
            32: "IUCV",
            33: "RXRPC",
            34: "ISDN",
            35: "PHONET",
            36: "IEEE802154",
            37: "CAIF",
            38: "ALG",
            39: "NFC",
            40: "VSOCK"
        }
        
        # Extended table information
        self.table_info = {
            'filter': 'Packet filtering (default)',
            'nat': 'Network Address Translation',  
            'mangle': 'Packet alteration',
            'raw': 'Connection tracking bypass',
            'security': 'Mandatory Access Control',
            'broute': 'Bridge routing decisions',
            'iptables': 'Generic iptables',
            'ip6tables': 'IPv6 tables',
            'ebtables': 'Ethernet bridge tables',
            'arptables': 'ARP tables',
            'unknown': 'Unknown table'
        }
    def setup_filters(self):
        if not any([self.src_ip, self.dst_ip, self.host, self.src_port, self.dst_port, self.protocol]):
            return
        filter_enable_map = self.bpf["filter_enable"]
        filter_host_ip_map = self.bpf["filter_host_ip"]
        if self.host:
            # Convert IP to integer - use same byte order as packet parsing
            host_ip_int = struct.unpack("I", socket.inet_aton(self.host))[0]
            
            # Set filter maps
            filter_enable_map[ctypes.c_uint32(0)] = ctypes.c_uint32(1)
            filter_host_ip_map[ctypes.c_uint32(0)] = ctypes.c_uint32(host_ip_int)
            
            if self.verbose:
                print(f"Filtering by host: {self.host} (filter value: {host_ip_int:08x})")
                
                # Verify the settings
                try:
                    enabled = filter_enable_map[ctypes.c_uint32(0)].value
                    host_ip = filter_host_ip_map[ctypes.c_uint32(0)].value
                    print(f"BPF filter configured: enabled={enabled}, host_ip={host_ip:08x}")
                except Exception as e:
                    print(f"Error verifying filter: {e}")
            else:
                print(f"Filtering by host: {self.host}")
        

    def protocol_name(self, protocol):
        if protocol == 6:
            return "TCP"
        elif protocol == 17:
            return "UDP"
        elif protocol == 1:
            return "ICMP"
        else:
            return "OTHER"

    def handle_packet(self, cpu, data, size):
        event = self.bpf["packet_events"].event(data)
        
        src_ip = socket.inet_ntoa(struct.pack("I",event.src_ip))
        dst_ip = socket.inet_ntoa(struct.pack("I",event.dst_ip))
        

        chain = self.hook_names.get(event.hooknum, f"HOOK_{event.hooknum}")
        pf_name = self.pf_names.get(event.pf, f"PF_{event.pf}")

        try:
            table_name = event.table_name.decode('utf-8').rstrip('\x00')
        except:
            table_name = "unknown"
            
        try:
            chain_name = event.chain_name.decode('utf-8').rstrip('\x00')
        except:
            chain_name = chain

        timestamp = event.timestamp / 1000000000.0
        print(f"{timestamp:17.6f} {pf_name:7s} {table_name:11s} {chain_name:11s} {src_ip:15s} {dst_ip:15s} {self.protocol_name(event.protocol):5s} {event.src_port:5d} {event.dst_port:5d} {event.packet_len:5d}")

    def start_monitoring(self):
        try:
            if self.verbose:
                print("Loading eBPF program...")
            
            # Suppress BCC compilation warnings and errors unless verbose
            import sys
            import os
            from contextlib import redirect_stderr
            
            if not self.verbose:
                devnull = open(os.devnull, 'w')
                with redirect_stderr(devnull):
                    self.bpf = BPF(text=bpf_source)
                devnull.close()
            else:
                self.bpf = BPF(text=bpf_source)
            
            self.setup_filters()
            
            # kprobesでNetFilterフック関数をトレース (全テーブル対応版)
            attached_count = 0
            
            # 包括的なNetFilterフック関数を試行
            hooks_to_try = [
                # Main netfilter hook functions
                ("nf_hook_slow", "trace_nf_hook_slow"),
                ("nf_hook_thresh", "trace_nf_hook_slow"),
                
                # iptables table-specific functions
                ("ipt_do_table", "trace_ipt_do_table"),
                ("iptable_filter_hook", "trace_ipt_do_table"),
                ("iptable_nat_do_chain", "trace_ipt_do_table"),
                ("iptable_mangle_hook", "trace_ipt_do_table"),
                ("iptable_raw_hook", "trace_ipt_do_table"),
                ("iptable_security_hook", "trace_ipt_do_table"),
                
                # ip6tables functions for IPv6
                ("ip6t_do_table", "trace_ipt_do_table"),
                ("ip6table_filter_hook", "trace_ipt_do_table"),
                ("ip6table_nat_do_chain", "trace_ipt_do_table"),
                ("ip6table_mangle_hook", "trace_ipt_do_table"),
                ("ip6table_raw_hook", "trace_ipt_do_table"), 
                ("ip6table_security_hook", "trace_ipt_do_table"),
                
                # nftables functions
                ("nft_do_chain", "trace_nf_hook_slow"),
                ("nf_tables_core_module", "trace_nf_hook_slow"),
                
                # ebtables for bridge filtering
                ("ebt_do_table", "trace_ipt_do_table"),
                
                # arptables for ARP filtering
                ("arpt_do_table", "trace_ipt_do_table"),
                
                # Connection tracking hooks
                ("nf_conntrack_in", "trace_nf_hook_slow"),
                ("ipv4_conntrack_in", "trace_nf_hook_slow"),
                ("ipv6_conntrack_in", "trace_nf_hook_slow"),
                
                # NAT hooks
                ("nf_nat_ipv4_in", "trace_nf_hook_slow"),
                ("nf_nat_ipv4_out", "trace_nf_hook_slow"),
                ("nf_nat_ipv4_local_in", "trace_nf_hook_slow"),
                ("nf_nat_ipv4_local_out", "trace_nf_hook_slow"),
                
                # Older kernel functions
                ("nf_iterate", "trace_nf_hook_slow"),
                ("nf_hook", "trace_nf_hook_slow")
            ]
            
            # Suppress kprobe attachment errors unless verbose
            if not self.verbose:
                devnull = open(os.devnull, 'w')
                with redirect_stderr(devnull):
                    for event, fn_name in hooks_to_try:
                        try:
                            self.bpf.attach_kprobe(event=event, fn_name=fn_name)
                            attached_count += 1
                        except Exception:
                            pass
                devnull.close()
            else:
                for event, fn_name in hooks_to_try:
                    try:
                        self.bpf.attach_kprobe(event=event, fn_name=fn_name)
                        print(f"Successfully attached to {event}")
                        attached_count += 1
                    except Exception as e:
                        print(f"Info: Could not attach to {event}: {e}")
            
            if attached_count == 0:
                print("Warning: Could not attach to any netfilter hooks")
                print("This may be due to kernel version or netfilter not being active")
            elif self.verbose:
                print(f"\nAttached to {attached_count} netfilter hook points")
            
            print("\nComprehensive NetFilter Tables/Chains Monitor")
            print("Time         PF      Table       Chain       Src IP          Dst IP          Proto   SPort   DPort   Len")
            print("-" * 120)

            self.bpf["packet_events"].open_perf_buffer(self.handle_packet)
            while True:
                try:
                    self.bpf.perf_buffer_poll(timeout=100)
                except KeyboardInterrupt:
                    print("\nReceived interrupt signal, shutting down")
                    break

        except Exception as e:
            print(f"Error: {e}")
            return 1
    def cleanup(self):
        if self.bpf:
            try:
                self.bpf.cleanup()
            except:
                pass     

def signal_handler(sig, frame):
    print("Shutting down..")
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(
            description="NetFilter Tables/Chains monitor",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
    sudo python3 nfdump.py
    sudo python3 nfdump.py --src-ip 192.168.1.100
    sudo python3 nfdump.py --host 1.1.1.1
    sudo python3 nfdump.py --dst-port 80 --protocol tcp
    sudo python3 nfdump.py --host 10.0.0.1 --protocol icmp
            """)
    parser.add_argument('--src-ip',type=str,help='Filter by source IP address')
    parser.add_argument('--dst-ip',type=str,help='Filter by destination IP address')
    parser.add_argument('--host',type=str,help='Filter by host')
    parser.add_argument('--src-port',type=int,help='Filter by source port')
    parser.add_argument('--dst-port',type=int,help='Filter by destination port')
    parser.add_argument('--protocol',type=str,help='Filter by protocol: tcp, udp, icmp or protocol number')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show verbose output including attachment errors')

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("This program must be run as root")
        return 1

    signal.signal(signal.SIGINT,signal_handler)
    
    monitor = NetFilterMonitor(
            src_ip=args.src_ip,
            dst_ip=args.dst_ip,
            host=args.host,
            src_port=args.src_port,
            dst_port=args.dst_port,
            protocol=args.protocol,
            verbose=args.verbose
    )
    try:
        return monitor.start_monitoring()
    finally:
        monitor.cleanup()

if __name__ == "__main__":
    sys.exit(main())

