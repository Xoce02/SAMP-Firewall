# SAMP-Firewall
 
An XDP/eBPF packet filter for SA-MP (San Andreas Multiplayer) servers. It inspects UDP traffic on the query port at the network driver level, before the packet reaches the kernel's normal networking stack, and drops abusive or malformed traffic in-line.
 
This replaces the earlier raw-socket / C++ implementation. The filter now runs as an XDP program attached directly to a network interface, which is significantly faster and lighter on CPU than a userspace raw-socket capture loop, since packets can be dropped before they're even copied into the socket buffer.
 
## Features
 
- **UDP query filtering** on port `7777` (the default SA-MP query port).
- **Source port validation**: drops packets whose UDP source port falls outside the dynamic/ephemeral range (`49152`–`65535`), since real SA-MP clients always query from that range.
- **Payload validation**: checks the SA-MP query signature (`"SAMP"` header) and payload length (`11`–`64` bytes), dropping anything malformed.
- **Opcode filtering**: only allows the known SA-MP query opcodes (`i`, `r`, `c`, `d`, `p`, `x`); anything else is dropped.
- **Per-IP rate limiting**: tracks each source IP in an LRU hash map over a 2-second sliding window, with a weighted score — "heavy" queries (`c`, `d`, `x`) cost more than light ones (`i`, `r`, `p`). An IP is dropped once it exceeds the query count, heavy-query count, or score thresholds within the window.
- **Basic anti-spoofing**: drops packets whose source IP falls in a bogon/private range (`0.0.0.0/8`, loopback, RFC1918 space, link-local, CGNAT, multicast/reserved) — ranges no real internet client would ever use as a source address.
- **IP fragmentation is rejected outright**, since the query protocol never needs fragmented packets.
## Requirements
 
- Linux kernel with XDP support (4.8+ recommended; this program doesn't require anything beyond basic XDP hooks).
- `clang`/`llvm` with BPF target support.
- `libbpf-dev` (for `bpf/bpf_helpers.h` and `bpf/bpf_endian.h`).
- `bpftool` or `iproute2` (`ip link`) to load and attach the program.
- Root privileges to load/attach XDP programs.
On Debian/Ubuntu:
 
```bash
apt update
apt install clang llvm libbpf-dev linux-headers-$(uname -r) bpftool
```
 
## How to Compile
 
1. Save the filter as `samp-filter.c` on your server.
2. Compile it to a BPF object file:
```bash
   clang -O2 -g -target bpf -c samp-filter.c -o samp-filter.o
```
 
## How to Load
 
Attach the compiled object to your network interface (replace `eth0` with your actual interface name):
 
```bash
ip link set dev eth0 xdp obj samp-filter.o sec xdp
```
 
Verify it's attached:
 
```bash
ip link show dev eth0
```
 
You should see `xdp` listed in the interface flags.
 
### Detaching
 
```bash
ip link set dev eth0 xdp off
```
 
### Loading in native/driver mode vs generic mode
 
If your NIC driver supports native XDP, the kernel will use it automatically for better performance. To force generic (SKB-based) mode, useful for testing on drivers/VMs without native XDP support:
 
```bash
ip link set dev eth0 xdpgeneric obj samp-filter.o sec xdp
```
 
## Notes
 
- This program only filters traffic destined for the SA-MP query port; all other traffic passes through untouched.
- Tuning constants (rate limit thresholds, window size, score weights) are defined at the top of `samp-filter.c` and can be adjusted to fit your server's traffic patterns.
- The bogon filter blocks packets with obviously fake source IPs (private/reserved ranges), but it cannot detect spoofing that uses real, routable IP addresses. That class of spoofing can only be reliably mitigated upstream, at the ISP/transit level (BCP38).
- Questions or issues: please open an issue in this repository.
 

