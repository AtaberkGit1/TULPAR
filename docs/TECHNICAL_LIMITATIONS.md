# Technical Capabilities & Honest Limitations

TULPAR is an **on-device** censorship circumvention and encrypted-DNS engine that runs **without any TULPAR-operated proxy or VPN relay servers**. Being explicit about what on-device packet manipulation, encrypted DNS, and local filtering can and cannot achieve—and what data leaves the device to public DNS resolvers—is a core engineering requirement.

## 1. What TULPAR CAN Bypass / Protect Against (Verified On-Device)
1. **DNS Poisoning, Hijacking & Transparent DNS Proxies**:
   - Bypassed via encrypted DoH (RFC 8484) and DoT (RFC 7858) using hardcoded bootstrap IPs + poisoning detection + automatic failover.
2. **SNI-Based HTTPS DPI Inspection**:
   - Bypassed via TLS Record Fragmentation (splitting `ClientHello` across multiple valid TLS records inside the SNI field) and TCP Segmentation (splitting TCP payload around SNI with `TCP_NODELAY`).
   - On Windows (`WinDivert`) and Linux (`NFQUEUE` + `IPPROTO_RAW`), additionally supports Out-of-Order (Disorder) TCP segments, low-TTL decoy `ClientHello` injection, and bad-checksum decoy packets.
3. **Plaintext HTTP `Host:` DPI**:
   - Bypassed via TCP split inside the `Host:` header value and case/whitespace normalization.
4. **Protocol / QUIC / UDP-443 Blocking or Selective DPI Throttling**:
   - Detected and mitigated via QUIC Initial UDP desync or clean fallback (`QuicPolicy::BlockFallbackToTcp`) to DPI-protected TLS/TCP.
5. **Ads, Trackers, CNAME Cloaking & Malware Domains**:
   - Blocked locally in RAM via `yolac-blocklist` + CNAME uncloaking in `yolac-dns` before any connection is opened.
6. **DNS & IPv6 Leaks**:
   - Plain port-53 traffic is intercepted locally; IPv6 traffic is either protected identically or blocked (`BlockUnprotectedIpv6` / `AAAA` suppression) so packets never bypass protection.

## 2. Protocol-Based DPI Throttling vs. Physical Line / ISP Speed Limits
TULPAR does **not** magically increase physical internet speed:
- **Protocol / SNI / QUIC-Based Throttling (Solvable On-Device)**: When an ISP leaves your physical link capacity intact but selectively throttles specific applications or domains detected via plaintext DNS, TLS SNI, or QUIC headers, evading DPI classification restores access up to your normal connection capacity.
- **Physical Line / Subscriber-Line Bandwidth Caps (Unsolvable by Client Software)**: No on-device software can exceed your physical ISP subscription rate (e.g., turning a 50 Mbps line into 100 Mbps), eliminate Wi-Fi/cellular radio congestion, or bypass destination-IP/aggregate port-agnostic rate policing.
- **Real Effect of DNS Cache & Domain Blocking**: In-memory LRU/SWR DNS caching only avoids network round-trips during repeated **domain name lookups**; local ad/tracker blocking only suppresses connections to blocked third-party domains. Neither expands physical line throughput.

## 3. What CANNOT Be Bypassed Without External Servers
The following censorship methods **cannot** be circumvented purely on-device because packets are dropped based solely on destination routing or total link termination:
1. **Hard IP Address Blackholing / Null-Routing (BGP/ACL IP Blocks)**:
   - If the ISP drops every packet addressed to a destination IP regardless of payload, local packet splitting cannot reach that IP. Bypassing hard IP blocks requires an external relay/tunnel/VPN server.
2. **ASN-Level / Prefix-Wide Blocks & Total Internet Shutdowns**:
   - Wholesale IP-range blackouts require external connectivity.
3. **Strict Protocol/Destination Whitelisting**:
   - Networks dropping everything except an explicit allowlist cannot be bypassed purely locally.

## 4. External Public DNS Privacy Boundary
- TULPAR runs zero central servers and collects zero telemetry or disk logs.
- However, unblocked DNS queries that miss the local RAM cache **are sent over encrypted DoH/DoT directly to external third-party public DNS providers** (Cloudflare, Quad9, Mullvad, Google). While DoH/DoT hides DNS queries from your local ISP, those external DNS providers see your client IP address and queried domains under their own privacy policies.

## 5. Platform-Specific Constraints
- **Android (`VpnService`)**:
  - Unprivileged mobile apps cannot inject spoofed raw IP headers (`IP_HDRINCL`, arbitrary TTL manipulation, or deliberately invalid TCP checksums). Therefore, Android uses userspace L3 TUN routing (`smoltcp`) with **TLS Record Fragmentation** + **TCP Segmentation** + **Encrypted DNS** + **QUIC fallback**.
- **Windows (`WinDivert`)**:
  - Full L3/L4 packet manipulation (including Disorder, Low-TTL decoy packets, and Bad-Checksum decoy packets) is supported when running elevated with the SHA-256-verified `WinDivert.dll` + `WinDivert64.sys` driver.
- **Linux (`NFQUEUE` + `IPPROTO_RAW`)**:
  - Full L3/L4 packet manipulation via kernel `NFQUEUE` + raw socket re-injection (fail-open `--queue-bypass`) and transparent `:5354` local encrypted DNS redirection via `nftables`/`iptables` when running as `root` / `CAP_NET_ADMIN`.
