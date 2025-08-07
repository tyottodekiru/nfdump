# NetFilter CO-RE Monitor

BPF CO-RE (Compile Once, Run Everywhere) version of the NetFilter packet tracing tool. This version uses modern BPF CO-RE technology for better portability across different kernel versions.

## Overview

This tool monitors packets as they traverse through netfilter hooks and tables, showing which tables and chains each packet passes through. The CO-RE version offers several advantages over the original BCC implementation:

- **Better Portability**: Works across different kernel versions without recompilation
- **Better Performance**: Uses fentry probes instead of kprobes for lower overhead  
- **Simplified Deployment**: Single binary with embedded BPF bytecode
- **Modern BPF**: Uses ringbuffers and libbpf for efficient communication

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
make install-deps

# Or manually:
sudo apt update
sudo apt install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
                    linux-tools-generic build-essential
```

### Build

```bash
# Check dependencies
make check-deps

# Build the program
make

# Test build
make test
```

### Verify BTF Support

```bash
# Check if BTF is available
ls -la /sys/kernel/btf/vmlinux

# Generate vmlinux.h if needed
make vmlinux
```

## Usage

### Basic Usage

```bash
# Monitor all netfilter traffic
sudo ./nfdump_core

# Monitor with verbose output
sudo ./nfdump_core --verbose
```

### Filtering Options

```bash
# Filter by host (source or destination)
sudo ./nfdump_core --host 192.168.1.100

# Filter by source IP
sudo ./nfdump_core --src-ip 10.0.0.1

# Filter by destination IP and port
sudo ./nfdump_core --dst-ip 8.8.8.8 --dst-port 53

# Filter by protocol
sudo ./nfdump_core --protocol tcp

# Multiple filters
sudo ./nfdump_core --host 192.168.1.100 --protocol icmp --verbose
```

### Command Line Options

```
  -s, --src-ip=IP        Filter by source IP address
  -d, --dst-ip=IP        Filter by destination IP address
  -H, --host=IP          Filter by host (source or destination IP)  
  -S, --src-port=PORT    Filter by source port
  -D, --dst-port=PORT    Filter by destination port
  -p, --protocol=PROTOCOL Filter by protocol (tcp, udp, icmp, or number)
  -v, --verbose          Verbose output
```

## Output Format

```
Time              PF       Table       Chain       Src IP          Dst IP          Proto  SPort  DPort   Len
------------------------------------------------------------------------------------------------------------------
1640995200.123456 IPv4     filter      INPUT       192.168.1.100   192.168.1.1     TCP       22     54321   1500
1640995200.123789 IPv4     nat         OUTPUT      10.0.0.1        8.8.8.8         UDP      123    53      64
```

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
- `nf_hook_slow` - Main netfilter hook
- `ipt_do_table` - iptables processing
- `ip6t_do_table` - ip6tables processing
- `nft_do_chain` - nftables processing  
- `nf_conntrack_in` - Connection tracking

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
# Debug build with symbols
make debug

# Clean build artifacts  
make clean

# Clean everything including vmlinux.h
make clean-all

# Show BPF program information
make info
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
