# iOS Entitlement, Memory & Distribution Guide

Building and distributing a VPN / Network Extension app on iOS has strict Apple platform requirements that cannot be bypassed:

## 1. Required Entitlements
- Both the host app (`YolacApp`) and the Packet Tunnel Extension (`YolacTunnel`) require:
  - `com.apple.developer.networking.networkextension` with array value `packet-tunnel-provider`
- **Important**: A free personal Apple ID signing certificate does **not** grant the `packet-tunnel-provider` entitlement. Compiling and installing onto a physical iOS device with working VPN functionality requires an active **Apple Developer Program** membership ($99/year paid to Apple) and properly provisioned App IDs for both `org.yolac.app` and `org.yolac.app.tunnel`.

## 2. Memory Budget (`NEPacketTunnelProvider`)
- iOS imposes a strict ~15–50 MB memory ceiling on Network Extensions (`jetsam` kills the extension silently if exceeded).
- TULPAR addresses this via `MemoryProfile::LowMemoryIos`:
  - Contiguous byte-arena blocklist (< 512 KB RAM, zero per-domain heap strings).
  - DNS LRU cache capped at 1,024 entries.
  - Concurrent TCP flows capped at 256; UDP NAT sessions capped at 128.
  - Minimal per-socket buffer sizes (16 KB) and immediate state wipe on tunnel stop.

## 3. App Store & Privacy Compliance
- `PrivacyInfo.xcprivacy` declares zero tracking (`NSPrivacyTracking = false`) and zero collected data types.
- `NETunnelProviderProtocol` uses local loopback metadata (`127.0.0.1`) since all processing is on-device (no remote VPN server).
- Note: App Store Guideline 5.4 requires VPN apps to only be distributed by an organization or verified developer account under Apple's current policies. Sideloading/TestFlight requires a paid Apple Developer Program account with Network Extension capability enabled.
