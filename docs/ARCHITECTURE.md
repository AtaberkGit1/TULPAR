# TULPAR Technical Architecture

## 1. Design Principles
1. **Zero Developer-Operated Servers**: All packet processing, DPI circumvention, local domain blocking, and leak protection run on the user's device. Unblocked DNS lookups are sent directly over encrypted DoH/DoT to external public DNS resolvers (Cloudflare, Quad9, Mullvad, Google).
2. **Shared Auditable Core**: One Rust workspace (`core/`) powers Windows, Android, and Linux.
3. **Minimal Fast-Path Overhead**: Only initial connection/DNS packets (`UDP/53`, `UDP/443`, `TLS ClientHello`, or `HTTP Host`) are inspected/transformed; steady-state TCP streams on kernel platforms bypass userspace payload rewriting.
4. **Bounded Memory Footprint**: Designed to run with strict in-memory LRU/flow caps and zero disk logging.

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
    ├── yolac-core       # YolacEngine orchestrator, AdaptiveController, HealthMonitor, ForgeRuntime
    ├── yolac-ffi        # Panic-safe Android JNI bindings (+ C-ABI & Forge package loader)
    └── yolac-cli        # Diagnostic & verification CLI
forge/                   # TULPAR Forge: Safe strategy DSL, .tulpar format, verifier, local lab & CLI
```

---

## 3. Platform Data Flows

### 3.1 Android (`VpnService`)
Android prohibits raw IP packet spoofing in unprivileged apps and provides a Layer-3 TUN interface instead:

```
[Device Apps]
     │  IPv4 / IPv6 L3 packets
     ▼
[OS TUN Interface] (Android VpnService)
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
On Windows, an elevated process intercepts targeted L3/L4 packets via SHA-256-verified `WinDivert.dll` + `WinDivert64.sys`:

```
[Windows Network Stack]
     │  Targeted IPv4/IPv6 packets (TCP 80/443, UDP 53/443/custom game ranges)
     ▼
[WinDivert Kernel Driver]
     │
     ▼
[platforms/windows :: WinDivertEngine]
     ├── UDP/53 ──► [yolac-dns] ─► Craft & inject inbound DNS response packet directly (zero ISP leak)
     ├── UDP/443 (QUIC) ─► [yolac-dpi::quic] ─► Desync or drop for TCP fallback
     └── TCP 80/443 ─► [yolac-dpi]
                         ├── TLS Record Fragmentation + TCP Segmentation (SNI midpoint)
                         ├── Out-of-Order Segment Transmission (Disorder)
                         ├── Low-TTL / Bad-Checksum Decoy ClientHello Injection
                         └── HTTP Host Split
```

### 3.3 Linux (`platforms/linux` — Netlink `NFQUEUE` + `IPPROTO_RAW`)
On Linux, `tulpar` runs as a static zero-dependency binary (`CAP_NET_ADMIN` / `root`) using fail-open `NFQUEUE` (`--queue-bypass`), `SO_MARK` loop protection (`SO_MARK = 0x54554C50`), raw socket re-injection, and a local encrypted DNS proxy (`:5354`) with `nftables` / `iptables` fallback.

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
