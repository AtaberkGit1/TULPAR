import Foundation
import NetworkExtension
import UIKit

enum YolacUiState: Equatable {
    case inactive
    case transition
    case active
    case error
}

enum ModuleHealthStatus: Int, Codable {
    case passiveOrUnchecked = 0 // Gray
    case healthy = 1            // Green
    case error = 2              // Red
}

struct ModuleHealthItem: Identifiable, Decodable, Equatable {
    let id: Int
    let name: String
    let status: Int
    let detail: String

    var healthStatus: ModuleHealthStatus {
        ModuleHealthStatus(rawValue: status) ?? .passiveOrUnchecked
    }

    var systemIconName: String {
        switch id {
        case 0: return "shield.lefthalf.filled"
        case 1: return "globe"
        case 2: return "nosign"
        case 3: return "arrow.triangle.branch"
        case 4: return "lock.shield"
        case 5: return "bolt"
        default: return "arrow.clockwise"
        }
    }
}

enum YolacStrings {
    static let securityWarning =
        "GÜVENLİK UYARISI: TULPAR'ı yalnızca resmî GitHub sayfamızdan indirin! Üçüncü taraf kaynaklardan indirilen dosyalar değiştirilmiş veya zararlı olabilir."
}

@MainActor
final class VpnController: ObservableObject {
    @Published private(set) var uiState: YolacUiState = .inactive
    @Published private(set) var modules: [ModuleHealthItem] = VpnController.passiveModules(
        detail: "Koruma kapalı (pasif).",
        updateStatus: .passiveOrUnchecked,
        updateDetail: "Henüz kontrol edilmedi."
    )
    @Published private(set) var isCheckingUpdates: Bool = false
    @Published private(set) var updateMessage: String?
    @Published private(set) var updateIsError: Bool = false

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var lastUpdateStatus: ModuleHealthStatus = .passiveOrUnchecked
    private var lastUpdateDetail: String = "Henüz kontrol edilmedi."
    private var lastErrorMessage: String?

    init() {
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.syncStatus()
            }
        }
        Task { await loadManager() }
    }

    deinit {
        if let obs = statusObserver {
            NotificationCenter.default.removeObserver(obs)
        }
    }

    func toggle() {
        guard uiState != .transition else { return }

        if uiState == .active {
            if let mgr = manager {
                Task {
                    mgr.isOnDemandEnabled = false
                    try? await mgr.saveToPreferences()
                    mgr.connection.stopVPNTunnel()
                }
            }
            return
        }

        lastErrorMessage = nil
        uiState = .transition
        refreshHealth()
        Task {
            do {
                let mgr = try await ensureManagerConfigured()
                try mgr.connection.startVPNTunnel()
            } catch {
                lastErrorMessage = "VPN izni reddedildi veya tünel başlatılamadı."
                uiState = .error
                refreshHealth()
            }
        }
    }

    func refreshHealth() {
        if let err = lastErrorMessage, uiState == .error {
            modules = VpnController.errorModules(
                errorText: err,
                updateStatus: lastUpdateStatus,
                updateDetail: lastUpdateDetail
            )
            return
        }

        guard uiState == .active,
              let session = manager?.connection as? NETunnelProviderSession else {
            let msg = uiState == .transition ? "Koruma durumu güncelleniyor..." : "Koruma kapalı (pasif)."
            modules = VpnController.passiveModules(
                detail: msg,
                updateStatus: lastUpdateStatus,
                updateDetail: lastUpdateDetail
            )
            return
        }

        // Query REAL live health JSON from the running Rust core inside PacketTunnelProvider
        guard let req = "health".data(using: .utf8) else { return }
        do {
            try session.sendProviderMessage(req) { [weak self] responseData in
                Task { @MainActor in
                    guard let self else { return }
                    guard let data = responseData,
                          var decoded = try? JSONDecoder().decode([ModuleHealthItem].self, from: data),
                          decoded.count == 7 else {
                        self.modules = VpnController.errorModules(
                            errorText: "Ağ uzantısından gerçek sağlık verisi alınamadı.",
                            updateStatus: self.lastUpdateStatus,
                            updateDetail: self.lastUpdateDetail
                        )
                        return
                    }
                    // Preserve user-initiated update status on module 6
                    decoded[6] = ModuleHealthItem(
                        id: 6,
                        name: "Güncellemeler",
                        status: self.lastUpdateStatus.rawValue,
                        detail: self.lastUpdateDetail
                    )
                    self.modules = decoded
                }
            }
        } catch {
            modules = VpnController.errorModules(
                errorText: "Tünel sağlık sorgusu başarısız oldu.",
                updateStatus: lastUpdateStatus,
                updateDetail: lastUpdateDetail
            )
        }
    }

    /// Manual user-triggered GitHub Releases update check. NEVER runs automatically in background.
    func checkUpdatesManually() {
        guard !isCheckingUpdates else { return }
        isCheckingUpdates = true
        updateIsError = false
        updateMessage = "Resmî GitHub sürümleri kontrol ediliyor..."

        Task {
            defer {
                isCheckingUpdates = false
                refreshHealth()
            }

            let rawRepo = (Bundle.main.object(forInfoDictionaryKey: "YolacOfficialGithubRepo") as? String ?? "")
                .trimmingCharacters(in: .whitespacesAndNewlines)
            guard !rawRepo.isEmpty, rawRepo.split(separator: "/").count == 2 else {
                setUpdateError("Resmî GitHub depo adresi yapılandırılmadı (YolacOfficialGithubRepo eksik).")
                return
            }

            guard let apiUrl = URL(string: "https://api.github.com/repos/\(rawRepo)/releases/latest") else {
                setUpdateError("Geçersiz resmî GitHub depo adresi.")
                return
            }

            let currentVersion = (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String) ?? "0.2.0"
            var req = URLRequest(url: apiUrl)
            req.timeoutInterval = 8
            req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
            req.setValue("TULPAR/\(currentVersion)", forHTTPHeaderField: "User-Agent")

            do {
                let (data, resp) = try await URLSession.shared.data(for: req)
                guard let http = resp as? HTTPURLResponse else {
                    setUpdateError("GitHub sunucusundan geçersiz yanıt alındı.")
                    return
                }
                if http.statusCode == 404 {
                    setUpdateError("Resmî depoda yayınlanmış bir sürüm (Release) bulunamadı.")
                    return
                }
                guard http.statusCode == 200 else {
                    setUpdateError("GitHub API hatası: HTTP \(http.statusCode)")
                    return
                }
                guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let tag = obj["tag_name"] as? String else {
                    setUpdateError("Sürüm etiketi (tag_name) okunamadı.")
                    return
                }
                let htmlUrl = (obj["html_url"] as? String) ?? "https://github.com/\(rawRepo)/releases/latest"
                let expectedPrefix = "https://github.com/\(rawRepo)/releases"
                guard htmlUrl.hasPrefix(expectedPrefix), let releaseUrl = URL(string: htmlUrl) else {
                    setUpdateError("Güvenlik ihlali: Yanıt resmî GitHub Releases adresine işaret etmiyor.")
                    return
                }

                if compareSemVer(latest: tag, current: currentVersion) > 0 {
                    lastUpdateStatus = .healthy
                    lastUpdateDetail = "Yeni resmî sürüm mevcut: \(tag)."
                    updateIsError = false
                    updateMessage = "Yeni sürüm bulundu (\(tag)). Resmî GitHub Releases sayfasına yönlendiriliyor."
                    await UIApplication.shared.open(releaseUrl)
                } else {
                    lastUpdateStatus = .healthy
                    lastUpdateDetail = "Uygulama güncel (v\(currentVersion))."
                    updateIsError = false
                    updateMessage = "Uygulama güncel (v\(currentVersion))."
                }
            } catch {
                setUpdateError("GitHub bağlantı hatası: \(error.localizedDescription)")
            }
        }
    }

    private func setUpdateError(_ message: String) {
        lastUpdateStatus = .error
        lastUpdateDetail = message
        updateIsError = true
        updateMessage = message
    }

    private func compareSemVer(latest: String, current: String) -> Int {
        func parts(_ s: String) -> [Int] {
            let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
                .trimmingCharacters(in: CharacterSet(charactersIn: "vV"))
                .split(separator: "-").first.map(String.init) ?? ""
            let nums = trimmed.split(separator: ".").compactMap { Int($0) }
            return [nums.indices.contains(0) ? nums[0] : 0,
                    nums.indices.contains(1) ? nums[1] : 0,
                    nums.indices.contains(2) ? nums[2] : 0]
        }
        let a = parts(latest)
        let b = parts(current)
        for i in 0..<3 {
            if a[i] != b[i] { return a[i] > b[i] ? 1 : -1 }
        }
        return 0
    }

    private func loadManager() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            self.manager = managers.first
            syncStatus()
        } catch {
            self.uiState = .inactive
            refreshHealth()
        }
    }

    private func ensureManagerConfigured() async throws -> NETunnelProviderManager {
        let mgr: NETunnelProviderManager
        if let existing = self.manager {
            mgr = existing
        } else {
            let loaded = try await NETunnelProviderManager.loadAllFromPreferences()
            mgr = loaded.first ?? NETunnelProviderManager()
        }

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "org.yolac.app.tunnel"
        proto.serverAddress = "127.0.0.1"
        mgr.protocolConfiguration = proto
        mgr.localizedDescription = "TULPAR"
        mgr.isEnabled = true

        // Automatic Wi-Fi <-> Cellular recovery while protection is enabled by user
        let connectRule = NEOnDemandRuleConnect()
        connectRule.interfaceTypeMatch = .any
        mgr.onDemandRules = [connectRule]
        mgr.isOnDemandEnabled = true

        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        self.manager = mgr
        return mgr
    }

    private func syncStatus() {
        guard let status = manager?.connection.status else {
            uiState = .inactive
            refreshHealth()
            return
        }
        switch status {
        case .connected:
            lastErrorMessage = nil
            uiState = .active
        case .connecting, .disconnecting, .reasserting:
            uiState = .transition
        case .disconnected, .invalid:
            if uiState != .error {
                uiState = .inactive
            }
        @unknown default:
            uiState = .inactive
        }
        refreshHealth()
    }

    private static func passiveModules(
        detail: String,
        updateStatus: ModuleHealthStatus,
        updateDetail: String
    ) -> [ModuleHealthItem] {
        [
            ModuleHealthItem(id: 0, name: "Akıllı Koruma", status: 0, detail: detail),
            ModuleHealthItem(id: 1, name: "DNS Koruması", status: 0, detail: detail),
            ModuleHealthItem(id: 2, name: "Reklam ve Takip Engelleme", status: 0, detail: detail),
            ModuleHealthItem(id: 3, name: "Gelişmiş Sansür Aşma", status: 0, detail: detail),
            ModuleHealthItem(id: 4, name: "Bağlantı Güvenliği", status: 0, detail: detail),
            ModuleHealthItem(id: 5, name: "Performans", status: 0, detail: detail),
            ModuleHealthItem(id: 6, name: "Güncellemeler", status: updateStatus.rawValue, detail: updateDetail),
        ]
    }

    private static func errorModules(
        errorText: String,
        updateStatus: ModuleHealthStatus,
        updateDetail: String
    ) -> [ModuleHealthItem] {
        [
            ModuleHealthItem(id: 0, name: "Akıllı Koruma", status: 2, detail: errorText),
            ModuleHealthItem(id: 1, name: "DNS Koruması", status: 2, detail: errorText),
            ModuleHealthItem(id: 2, name: "Reklam ve Takip Engelleme", status: 2, detail: "Koruma başlatılamadığı için devre dışı."),
            ModuleHealthItem(id: 3, name: "Gelişmiş Sansür Aşma", status: 2, detail: errorText),
            ModuleHealthItem(id: 4, name: "Bağlantı Güvenliği", status: 2, detail: "Sızıntı koruması aktif değil."),
            ModuleHealthItem(id: 5, name: "Performans", status: 0, detail: "Koruma çalışmıyor."),
            ModuleHealthItem(id: 6, name: "Güncellemeler", status: updateStatus.rawValue, detail: updateDetail),
        ]
    }
}
