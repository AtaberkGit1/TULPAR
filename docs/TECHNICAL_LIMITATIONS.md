# Technical Capabilities & Honest Limitations

TULPAR is strictly **on-device** and uses **zero central servers, proxies, or VPS relays**. Being transparent about what on-device network techniques can and cannot achieve is a core requirement of the project.

## 1. What TULPAR CAN Bypass / Protect Against (Verified On-Device)
1. **DNS Poisoning, Hijacking & Transparent DNS Proxies**:
   - Bypassed via encrypted DoH (RFC 8484) and DoT (RFC 7858) using hardcoded bootstrap IPs + poisoning detection + automatic failover.
2. **SNI-Based HTTPS DPI Inspection**:
   - Bypassed via TLS Record Fragmentation (splitting ClientHello across multiple valid TLS records inside the SNI field) and TCP Segmentation (splitting TCP payload around SNI with `TCP_NODELAY`).
   - On Windows (with WinDivert), additionally supports Out-of-Order (Disorder) TCP segments, low-TTL fake ClientHello injection, and bad-checksum fake packets.
3. **Plaintext HTTP `Host:` DPI**:
   - Bypassed via TCP split inside the `Host:` header value and case/whitespace normalization.
4. **QUIC / UDP-443 Blocking or Throttling**:
   - Detected and mitigated by forcing clean fallback (`QuicPolicy::BlockFallbackToTcp`) to DPI-protected TLS/TCP.
5. **Ads, Trackers, CNAME Cloaking & Malware Domains**:
   - Blocked locally in RAM via `yolac-blocklist` + CNAME uncloaking in `yolac-dns` before any connection is opened.
6. **DNS & IPv6 Leaks**:
   - All port-53 traffic is intercepted locally; IPv6 traffic is either protected identically or blocked (`BlockUnprotectedIpv6` / `AAAA` suppression) so packets never escape around the protection layer.

## 2. What CANNOT Be Bypassed Without External Servers
The following censorship methods **cannot** be circumvented purely on-device because the network drops packets based solely on destination routing or kills the link itself:
1. **Hard IP Address Blackholing / Null-Routing (BGP/ACL IP Blocks)**:
   - If the ISP drops every packet addressed to a server's IP regardless of payload, no local packet-splitting technique can make the packet reach that IP. Circumventing hard IP blocks requires an external relay/tunnel/VPN server.
2. **ASN-Level / Prefix-Wide Blocks & Total Internet Shutdowns**:
   - Complete network blackouts or wholesale blocking of entire IP ranges require out-of-band connectivity or external relays.
3. **Strict Protocol Whitelisting (Drop Everything Except Approved Destinations)**:
   - Networks allowing only a government/corporate allowlist cannot be bypassed locally without an authorized external tunnel.
4. **Subscriber-Line Aggregate Bandwidth Throttling**:
   - If an ISP caps a user's entire physical line (e.g., to 1 Mbps globally), local optimization cannot increase physical link capacity; TULPAR can only mitigate protocol-specific throttling (like QUIC or SNI-matched throttling).

## 3. Platform-Specific Constraints
- **Android (`VpnService`) & iOS (`NEPacketTunnelProvider`)**:
  - Mobile sandboxes do not allow raw IP socket spoofing (`IP_HDRINCL`, arbitrary TTL manipulation, or deliberately invalid TCP checksums). Therefore, mobile relies on **TLS Record Fragmentation** + **TCP Segmentation** + **Encrypted DNS** + **QUIC fallback**.
- **Windows (`WinDivert`)**:
  - Full L3/L4 packet manipulation (including Disorder, Low-TTL fake packets, and Bad-Checksum fake packets) is supported when running elevated with the signed `WinDivert.dll` + `WinDivert64.sys` driver present.
