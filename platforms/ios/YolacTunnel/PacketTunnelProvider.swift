import Foundation
import Network
import NetworkExtension
import YolacFfi

final class PacketTunnelProvider: NEPacketTunnelProvider {

    private var yolacHandle: OpaquePointer?
    private var pathMonitor: NWPathMonitor?
    private var lastPathSignature: String?

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.mtu = 1500

        let ipv4 = NEIPv4Settings(addresses: ["10.219.0.1"], subnetMasks: ["255.255.255.252"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        // Preserve local LAN & Captive Portal router reachability while keeping all DNS captured
        ipv4.excludedRoutes = [
            NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0"),
            NEIPv4Route(destinationAddress: "172.16.0.0", subnetMask: "255.240.0.0"),
            NEIPv4Route(destinationAddress: "169.254.0.0", subnetMask: "255.255.0.0"),
        ]
        settings.ipv4Settings = ipv4

        let ipv6 = NEIPv6Settings(addresses: ["fd79:6f6c:6163::1"], networkPrefixLengths: [126])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6

        let dns = NEDNSSettings(servers: ["10.219.0.2", "fd79:6f6c:6163::2"])
        dns.matchDomains = [""] // Capture all DNS queries to prevent DNS leaks
        settings.dnsSettings = dns

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else {
                completionHandler(error)
                return
            }
            if let error {
                completionHandler(error)
                return
            }

            var cfg = YolacFfiConfig(
                profile: UInt8(YOLAC_PROFILE_LOW_MEMORY_IOS.rawValue),
                mtu: 1500,
                block_unprotected_ipv6: 0
            )
            guard let handle = yolac_create(&cfg) else {
                completionHandler(NSError(domain: "org.yolac.app", code: -1))
                return
            }
            self.yolacHandle = handle

            let ctxPtr = Unmanaged.passUnretained(self).toOpaque()
            let sink: YolacPacketSinkFn = { ctx, dataPtr, len in
                guard let ctx, let dataPtr, len > 0 else { return }
                let provider = Unmanaged<PacketTunnelProvider>.fromOpaque(ctx).takeUnretainedValue()
                let pktData = Data(bytes: dataPtr, count: len)
                let proto: NSNumber = (pktData.first ?? 0) >> 4 == 6
                    ? NSNumber(value: AF_INET6)
                    : NSNumber(value: AF_INET)
                provider.packetFlow.writePackets([pktData], withProtocols: [proto])
            }

            let rc = yolac_start_packet_flow(handle, sink, ctxPtr, nil, nil)
            if rc != 0 {
                yolac_destroy(handle)
                self.yolacHandle = nil
                completionHandler(NSError(domain: "org.yolac.app", code: Int(rc)))
                return
            }

            self.startNetworkMonitor()
            self.pumpPacketFlow()
            completionHandler(nil)
        }
    }

    private func pumpPacketFlow() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self, let handle = self.yolacHandle else { return }
            for pkt in packets {
                pkt.withUnsafeBytes { raw in
                    if let base = raw.bindMemory(to: UInt8.self).baseAddress {
                        _ = yolac_push_tun_packet(handle, base, pkt.count)
                    }
                }
            }
            self.pumpPacketFlow()
        }
    }

    private func startNetworkMonitor() {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self, let handle = self.yolacHandle else { return }
            let sig = "\(path.status)-\(path.availableInterfaces.map { $0.name }.joined(separator: ","))"
            if self.lastPathSignature == nil {
                self.lastPathSignature = sig
                return
            }
            if self.lastPathSignature != sig {
                self.lastPathSignature = sig
                _ = yolac_notify_network_change(handle)
            }
        }
        monitor.start(queue: DispatchQueue(label: "org.yolac.path"))
        self.pathMonitor = monitor
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        pathMonitor?.cancel()
        pathMonitor = nil
        if let handle = yolacHandle {
            _ = yolac_stop(handle)
            yolac_destroy(handle)
            yolacHandle = nil
        }
        completionHandler()
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        if let handle = yolacHandle {
            _ = yolac_notify_network_change(handle)
        }
        completionHandler()
    }

    override func wake() {
        if let handle = yolacHandle {
            _ = yolac_notify_network_change(handle)
        }
    }

    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        let cmd = String(data: messageData, encoding: .utf8) ?? ""
        guard let handle = yolacHandle else {
            completionHandler(nil)
            return
        }
        if cmd == "health" {
            var buf = [CChar](repeating: 0, count: 4096)
            let written = yolac_get_health_json(handle, &buf, buf.count)
            if written > 0 {
                let data = Data(bytes: buf, count: Int(written))
                completionHandler(data)
                return
            }
        }
        completionHandler(nil)
    }
}
