# TULPAR Technical Architecture

## 1. Design Principles
1. **Zero Server Cost & Zero Central Infrastructure**: All packet processing, DPI circumvention, DNS filtering, ad/tracker blocking, and leak protection run locally on the user's device.
2. **Shared Auditable Core**: One Rust workspace (`core/`) powers Android, iOS, and Windows.
3. **Zero Performance Penalty on Clean Flows**: Only the initial handshake / first packet of a connection is inspected (`TLS ClientHello` or `HTTP Host`); once established, steady-state traffic runs through zero-copy / raw bidirectional forwarding.
4. **Strict Resource Caps**: Designed to run within the strict memory budget of iOS Network Extensions (< 15–50 MB) as well as low-end Android devices and Windows desktops.

---

## 2. Workspace Layout

```
core/
├── Cargo.toml
└── crates/
    ├── yolac-dpi        # IP/TCP/UDP/TLS/HTTP/QUIC parsing + DPI circumvention transforms
    ├── yolac-blocklist  # Contiguous arena suffix blocklist (ads, trackers, malware)
    ├── yolac-dns        # RFC1035 wire parser, poisoning detection, CNAME uncloaking, DoH/DoT, RAM LRU
    ├── yolac-net        # Userspace smoltcp L3 TUN engine, DPI TCP relay, UDP NAT, LeakGuard
    ├── yolac-core       # YolacEngine orchestrator, AdaptiveController, throttling detector
    ├── yolac-ffi        # Panic-safe C-ABI (iOS/C) + JNI (Android) bindings
    └── yolac-cli        # Diagnostic & verification CLI
```

---

## 3. Platform Data Flows

### 3.1 Android (`VpnService`) & iOS (`NEPacketTunnelProvider`)
Both mobile operating systems prohibit raw IP packet spoofing in unprivileged apps and provide a Layer-3 TUN interface instead:

```
[Device Apps]
     │  IPv4 / IPv6 L3 packets
     ▼
[OS TUN Interface] (Android VpnService / iOS NEPacketTunnelProvider)
     │
     ▼
[yolac-net :: TunEngine]
     ├── UDP/53 (IPv4/IPv6) ──► [yolac-dns] ──► Blocklist hit? ─► Instant local 0.0.0.0/::/NXDOMAIN
     │                                      └─► Miss? ─────────► DoH/DoT via bootstrap IP + DPI evasion
     │                                                          + Poisoning check + CNAME uncloaking
     ├── UDP/443 (QUIC) ──────► [yolac-dpi::quic] ─► BlockFallbackToTcp (if throttled) or Protected UDP NAT
     ├── Other UDP ───────────► Bounded Protected UDP NAT (idle-expired, capped)
     └── TCP (443, 80, ...) ──► [smoltcp virtual stack] ──► [DpiTcpRelay (protected OS socket)]
                                                               ├── TLS Record Split (inside SNI)
                                                               ├── TCP Segment Split (TCP_NODELAY)
                                                               └── HTTP Host Split / Case Evasion
```

### 3.2 Windows (`WinDivert 2.2` Kernel Packet Filter)
On Windows, an elevated process can intercept L3/L4 packets in kernel space via `WinDivert.dll` without creating a full userspace TUN stack:

```
[Windows Network Stack]
     │  Outbound IPv4/IPv6 packets (TCP 80/443, UDP 53/443)
     ▼
[WinDivert Kernel Driver]
     │
     ▼
[platforms/windows :: WinDivertEngine]
     ├── UDP/53 ──► [yolac-dns] ─► Craft & inject inbound DNS response packet directly (zero ISP leak)
     ├── UDP/443 (QUIC) ─► [yolac-dpi::quic] ─► Drop/ICMP unreachable for TCP fallback when throttled
     └── TCP 80/443 ─► [yolac-dpi]
                         ├── TLS Record Fragmentation + TCP Segmentation (SNI midpoint)
                         ├── Out-of-Order Segment Transmission (Disorder)
                         ├── Low-TTL / Bad-Checksum Fake ClientHello Injection
                         └── HTTP Host Split
```

---

## 4. Adaptive Strategy & Throttling Detection
`yolac-core::AdaptiveController` stores **salted ephemeral SipHash keys** (never plaintext domains or IPs) in a bounded RAM table:
1. Starts with minimal-overhead evasion (`TlsRecordSplit` / `Passthrough` on clean destinations).
2. Detects DPI interference signals:
   - Immediate `TCP RST` right after ClientHello
   - TLS handshake timeout / early EOF
   - Initial handshake stall / throttling
   - QUIC UDP/443 blackholing
3. Escalates strategy automatically:
   - Mobile/Socket backends: `Passthrough` -> `TlsRecordSplit` -> `TcpSniSplit` -> `TlsAndTcpSplit`
   - Windows Raw Packet backend: `TlsAndTcpSplit` -> `RawDisorder` -> `RawFakeTtl` -> `RawBadChecksum`
   - Automatically enables `QuicPolicy::BlockFallbackToTcp` when QUIC stalls.
   - Automatically fails over encrypted DNS upstream on timeout or detected DNS poisoning.
4. Network transitions (`Wi-Fi <-> Cellular`) trigger `on_network_change()` to re-evaluate cleanly.
