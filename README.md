# NetFilter CO-RE Monitor

BPF CO-RE (Compile Once, Run Everywhere) version of the NetFilter packet tracing tool. This version uses modern BPF CO-RE technology for better portability across different kernel versions.

## Overview

This tool monitors packets as they traverse through netfilter hooks and tables, showing which tables and chains each packet passes through. The CO-RE version offers several advantages over the original BCC implementation:

- **Better Portability**: Works across different kernel versions without recompilation
- **Better Performance**: Uses fentry probes instead of kprobes for lower overhead  
- **Simplified Deployment**: Single binary with embedded BPF bytecode
- **Modern BPF**: Uses ringbuffers and libbpf for efficient communication

## Variants

This tool provides two specialized implementations for different netfilter environments:

- **nfdump_core**: Modern netfilter implementation with NFTables support and FastPath detection
- **nfdump_core_legacy**: Legacy IPTables implementation with iptables-nft compatibility

Both versions support the same filtering options and command-line interface, but are optimized for their respective netfilter architectures.

## Features

- Track packets through netfilter hooks (PREROUTING, INPUT, FORWARD, OUTPUT, POSTROUTING)
- Monitor multiple netfilter tables (filter, nat, mangle, raw, security, etc.)
- Support for iptables, ip6tables, nftables, and connection tracking
- Comprehensive filtering options (IP, port, protocol)
- Real-time packet analysis with minimal overhead
- BPF CO-RE for cross-kernel compatibility

## Requirements

- Linux kernel >= 5.8 (with BTF support)
- Root privileges
- Dependencies: clang, llvm, libbpf-dev, bpftool

## Installation

### Install Dependencies (Ubuntu/Debian)

```bash
# Install all required dependencies
make -f Makefile.core install-deps

# Or manually:
sudo apt update
sudo apt install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
                    linux-tools-generic build-essential
```

### Build

```bash
# Check dependencies
make -f Makefile.core check-deps

# Build both versions (recommended)
make -f Makefile.core both

# Test build
make -f Makefile.core test-both
```

### Verify BTF Support

```bash
# Check if BTF is available
ls -la /sys/kernel/btf/vmlinux

# Generate vmlinux.h if needed
make -f Makefile.core vmlinux
```

## Usage

### Basic Usage

```bash
# Modern NFTables implementation (default)
sudo ./nfdump_core

# Legacy IPTables implementation 
sudo ./nfdump_core_legacy

# Monitor with verbose output and debug information
sudo ./nfdump_core --verbose
sudo ./nfdump_core_legacy --verbose
```

### Command Line Help

```bash
# Get help for either version
sudo ./nfdump_core --help
sudo ./nfdump_core_legacy --help
```

**Available Options:**
```
  -s, --src-ip=IP            Filter by source IP address
  -d, --dst-ip=IP            Filter by destination IP address
  -H, --host=IP              Filter by host (source or destination IP)
  -S, --src-port=PORT        Filter by source port
  -D, --dst-port=PORT        Filter by destination port
  -p, --protocol=PROTOCOL    Filter by protocol (tcp, udp, icmp, or number)
  -v, --verbose              Verbose output
  -?, --help                 Show help message
```

### Choosing the Right Version

- **Use `nfdump_core`** for:
  - Modern Linux systems with NFTables
  - Systems requiring FastPath detection
  - Enhanced netfilter hook monitoring
  
- **Use `nfdump_core_legacy`** for:
  - Traditional IPTables environments
  - Systems using iptables-nft (modern iptables with nftables backend)
  - Focus on specific IPTables table monitoring (filter, nat, mangle, raw)

### Filtering Examples

Both versions support identical filtering options:

```bash
# Filter by protocol (ICMP packets only)
sudo ./nfdump_core --protocol icmp
sudo ./nfdump_core_legacy --protocol icmp

# Filter by host (any packets involving this IP)
sudo ./nfdump_core --host 192.168.11.28

# Filter by source IP  
sudo ./nfdump_core --src-ip 10.0.0.1

# Filter by destination IP and port
sudo ./nfdump_core_legacy --dst-ip 8.8.8.8 --dst-port 53

# Filter by protocol (TCP only)
sudo ./nfdump_core --protocol tcp

# Multiple filters with verbose output
sudo ./nfdump_core_legacy --host 192.168.11.28 --protocol icmp --verbose
```

### Verbose Output Example

```bash
sudo ./nfdump_core --host 192.168.11.28 --verbose
```

Verbose mode shows:
- Filter configuration confirmation
- BPF program loading status
- Detailed libbpf debug messages
- Real-time packet processing information


## Output Format and Examples

### NFTables Version Output Sample

```bash
sudo ./nfdump_core --protocol icmp
```

```
NetFilter CO-RE Monitor - BPF CO-RE Implementation (with FastPath Detection)
Time              PF       Table       Chain       Src IP          Dst IP          Proto  SPort  DPort   Len  Path
----------------------------------------------------------------------------------------------------------------------
      1221.477344 IPv4     netfilter   OUTPUT      192.168.11.28   8.8.8.8         ICMP      8     0    84 SLOW
      1221.477377 IPv4     nat         INPUT       192.168.11.28   8.8.8.8         ICMP      8     0    84 SLOW
      1221.477384 IPv4     ip_out      OUTPUT      192.168.11.28   8.8.8.8         ICMP      8     0    84 SLOW
      1221.477386 IPv4     netfilter   POSTROUTING 192.168.11.28   8.8.8.8         ICMP      8     0    84 SLOW
      1221.482687 IPv4     netfilter   PREROUTING  8.8.8.8         192.168.11.28   ICMP      0     0    84 SLOW
      1221.482717 IPv4     local_deliv INPUT       8.8.8.8         192.168.11.28   ICMP      0     0    84 FAST
      1221.482718 IPv4     netfilter   INPUT       8.8.8.8         192.168.11.28   ICMP      0     0    84 SLOW
```

**解説 (Explanation):**
- **Time**: Kernel timestamp in seconds since boot (1221.477344 = ~1,221 seconds)
- **PF**: Protocol family (IPv4 for all netfilter traffic)
- **Table**: Mix of table types including IP stack hooks:
  - `netfilter`: Generic netfilter hook processing
  - `nat`: Network Address Translation table
  - `ip_out`: IP output stack hook  
  - `local_deliv`: IP local delivery hook
- **Chain**: NetFilter hook point (OUTPUT for locally generated, INPUT for received, POSTROUTING/PREROUTING for routing)
- **Src/Dst IP**: Source/destination IP addresses
- **Proto**: Protocol (ICMP with type=8/code=0 for ping request/reply)
- **Len**: Packet length in bytes (84 bytes for ICMP ping)
- **Path**: Processing path type (SLOW = standard path, FAST = optimized path)

### Legacy Version Output Sample

```bash
sudo ./nfdump_core_legacy --protocol icmp
```

```
NetFilter Legacy Monitor - BPF CO-RE Implementation (IPTables Focus)
Time              PF       Table       Chain       Src IP          Dst IP          Proto  SPort  DPort   Len  Type
------------------------------------------------------------------------------------------------------------------------
      1234.623700 IPv4     netfilter   OUTPUT      192.168.11.28   8.8.8.8         ICMP      8     0    84 LEGACY
      1234.623712 IPv4     conntrack   OUTPUT      192.168.11.28   8.8.8.8         ICMP      8     0    84 CT
      1234.623719 IPv4     nat         INPUT       192.168.11.28   8.8.8.8         ICMP      8     0    84 IPT
      1234.623723 IPv4     netfilter   POSTROUTING 192.168.11.28   8.8.8.8         ICMP      8     0    84 LEGACY
      1234.629157 IPv4     netfilter   PREROUTING  8.8.8.8         192.168.11.28   ICMP      0     0    84 LEGACY
      1234.629177 IPv4     conntrack   PREROUTING  8.8.8.8         192.168.11.28   ICMP      0     0    84 CT
      1234.629186 IPv4     netfilter   INPUT       8.8.8.8         192.168.11.28   ICMP      0     0    84 LEGACY
```

**解説 (Explanation):**
- **Time**: Same kernel timestamp format as NFTables version
- **Table**: Mix of table types showing different processing paths:
  - `netfilter`: Generic netfilter hook processing (LEGACY type)
  - `nat`: Specific iptables table names (IPT type)
  - `conntrack`: Connection tracking processing (CT type)
- **Chain**: Same hook points (OUTPUT for locally generated, INPUT for received packets)
- **Type**: Processing classification:
  - `LEGACY`: Generic netfilter hook (nf_hook_slow)
  - `IPT`: IPTables table processing (ipt_do_table)
  - `CT`: Connection tracking (nf_conntrack_in)

### Key Differences Between Versions

1. **Table Name Resolution**:
   - **NFTables**: Shows mix of IP stack hooks (`ip_out`, `local_deliv`) and netfilter tables with path indicators
   - **Legacy**: Shows mixed table sources with type classification (`LEGACY`/`IPT`/`CT`)

2. **Processing Path Coverage**:
   - **NFTables**: Includes IP stack hooks (ip_output, ip_local_deliver) plus netfilter hooks with FAST/SLOW path detection
   - **Legacy**: Focuses on netfilter hooks including connection tracking with detailed type classification

3. **Output Format**:
   - **NFTables**: Shows `Path` column indicating FAST/SLOW processing paths
   - **Legacy**: Shows `Type` column classifying hook types (LEGACY/IPT/CT)

4. **System Compatibility**:
   - **NFTables**: Optimized for modern nftables-based systems
   - **Legacy**: Compatible with iptables-nft (modern iptables using nftables backend)

## Monitored Netfilter Components

### Hook Points
- **PREROUTING** - Before routing decision
- **INPUT** - Destined for local system
- **FORWARD** - Routed through system  
- **OUTPUT** - Generated locally
- **POSTROUTING** - After routing decision

### Tables
- **filter** - Packet filtering (default table)
- **nat** - Network Address Translation
- **mangle** - Packet alteration
- **raw** - Connection tracking bypass
- **security** - Mandatory Access Control
- **conntrack** - Connection tracking

### BPF Attachment Points

**NFTables Version (nfdump_core)**:
- `ip_rcv` - IP packet receive hook
- `ip_output` - IP packet output hook
- `ip_forward` - IP packet forwarding hook
- `ip_local_deliver` - IP local delivery hook
- `nf_hook_slow` - Main netfilter hook
- `ipt_do_table` - iptables processing
- `nft_do_chain` - nftables processing

**Legacy Version (nfdump_core_legacy)**:
- `nf_hook_slow` - Main netfilter hook
- `ipt_do_table` - iptables processing
- `nft_do_chain` - nftables processing
- `nf_conntrack_in` - Connection tracking

**Note**: IPv6 support (`ip6t_do_table`) is commented out in both versions for compatibility reasons.

## Troubleshooting

### Build Issues

```bash
# Check all dependencies
make check-deps

# Verify BTF support
ls -la /sys/kernel/btf/vmlinux

# Check kernel version
uname -r

# Verify BPF program
make check-bpf
```

### Runtime Issues

```bash
# Check if running as root
id

# Verify BPF filesystem is mounted
mount | grep bpf

# Check kernel config (if available)
grep -E 'CONFIG_BPF|CONFIG_DEBUG_INFO_BTF' /boot/config-$(uname -r)
```

### No Events Appearing

1. Verify netfilter is active:
   ```bash
   iptables -L -v -n
   ```

2. Generate network traffic:
   ```bash
   ping -c 3 8.8.8.8
   ```

3. Check verbose output:
   ```bash
   sudo ./nfdump_core --verbose
   ```

## Comparison with BCC Version

| Feature | BCC Version | CO-RE Version |
|---------|-------------|---------------|
| Portability | Requires kernel headers | Works across kernels |
| Performance | kprobe overhead | fentry lower overhead |
| Dependencies | BCC, kernel headers | libbpf, clang |
| Binary Size | Python + BCC | Single compiled binary |
| Startup Time | JIT compilation | Pre-compiled |
| Debugging | BCC built-in | Standard debugging tools |

## Development

### Build Variants

```bash
# Build both versions (recommended)
make -f Makefile.core both

# Build NFTables version only
make -f Makefile.core

# Build Legacy version only  
make -f Makefile.core legacy

# Debug build with symbols
make -f Makefile.core debug

# Clean build artifacts  
make -f Makefile.core clean

# Clean everything including vmlinux.h
make -f Makefile.core clean-all

# Show BPF program information
make -f Makefile.core info
```

### File Structure

```
nfdump_btf.bpf.c     - BPF CO-RE program
nfdump_core.c        - Userspace loader  
nfdump_btf.skel.h    - Generated skeleton (build artifact)
Makefile.core        - Build system
vmlinux.h           - Kernel type definitions
```

### Extending the Tool

The CO-RE version is designed for easy extension:

1. **Add new hook points**: Add SEC() sections in the BPF program
2. **Add new filters**: Extend filter_config map and filtering logic
3. **Add IPv6 support**: Extend packet parsing for IPv6 headers
4. **Add new protocols**: Extend transport layer parsing

## License

GPL v2 (same as kernel BPF programs)

## See Also

- Original BCC version: `nfdump.py`
- Kernel documentation: `/Documentation/bpf/`
- BPF CO-RE guide: https://github.com/libbpf/libbpf
- netfilter documentation: https://netfilter.org/
