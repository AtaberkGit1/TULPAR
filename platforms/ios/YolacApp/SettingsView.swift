import SwiftUI

struct SettingsView: View {
    @ObservedObject var vpn: VpnController
    @Binding var isPresented: Bool
    @State private var selectedModuleId: Int?

    private var failingModules: [ModuleHealthItem] {
        vpn.modules.filter { $0.healthStatus == .error }
    }

    private var selectedModule: ModuleHealthItem? {
        guard let id = selectedModuleId else { return nil }
        return vpn.modules.first { $0.id == id }
    }

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()

            VStack(alignment: .leading, spacing: 18) {
                // Header
                HStack(spacing: 14) {
                    Button(action: { isPresented = false }) {
                        Image(systemName: "chevron.left")
                            .font(.system(size: 18, weight: .medium))
                            .foregroundColor(.white)
                            .frame(width: 36, height: 36)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Geri")

                    Text("Ayarlar")
                        .font(.system(size: 18, weight: .medium))
                        .foregroundColor(.white)

                    Spacer()
                }
                .padding(.top, 8)

                // Single non-wrapping horizontal row of 7 real module status icons
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 10) {
                        ForEach(vpn.modules) { module in
                            Button(action: { selectedModuleId = module.id }) {
                                ZStack {
                                    Circle()
                                        .stroke(
                                            selectedModuleId == module.id
                                                ? Color.white
                                                : Color(red: 0x26 / 255.0, green: 0x26 / 255.0, blue: 0x26 / 255.0),
                                            lineWidth: 1.5
                                        )
                                        .frame(width: 46, height: 46)

                                    Image(systemName: module.systemIconName)
                                        .font(.system(size: 18, weight: .regular))
                                        .foregroundColor(statusColor(module.healthStatus))
                                }
                            }
                            .buttonStyle(.plain)
                            .accessibilityLabel("\(module.name): \(module.detail)")
                        }
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 4)
                }

                // Red error list ONLY when 1 or more modules are in Error state
                if !failingModules.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(failingModules) { mod in
                            Text("\(mod.name): \(mod.detail)")
                                .font(.system(size: 13))
                                .foregroundColor(Color(red: 0xE7 / 255.0, green: 0x4C / 255.0, blue: 0x3C / 255.0))
                        }
                    }
                }

                // Tapped module inspection readout
                if let sel = selectedModule {
                    let stateText: String = {
                        switch sel.healthStatus {
                        case .healthy: return "Aktif"
                        case .error: return "Hata"
                        case .passiveOrUnchecked: return "Pasif / Kontrol edilmedi"
                        }
                    }()
                    Text("\(sel.name) (\(stateText)): \(sel.detail)")
                        .font(.system(size: 13))
                        .foregroundColor(statusColor(sel.healthStatus))
                }

                // Manual update check button (never runs automatically in background)
                Button(action: { vpn.checkUpdatesManually() }) {
                    Text(vpn.isCheckingUpdates ? "Kontrol ediliyor..." : "Güncellemeleri Kontrol Et")
                        .font(.system(size: 14, weight: .medium))
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .frame(height: 48)
                        .background(Color.black)
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(Color(red: 0x55 / 255.0, green: 0x55 / 255.0, blue: 0x55 / 255.0), lineWidth: 1.5)
                        )
                }
                .buttonStyle(.plain)
                .disabled(vpn.isCheckingUpdates)

                if let msg = vpn.updateMessage {
                    Text(msg)
                        .font(.system(size: 13))
                        .foregroundColor(
                            vpn.updateIsError
                                ? Color(red: 0xE7 / 255.0, green: 0x4C / 255.0, blue: 0x3C / 255.0)
                                : Color(red: 0x2E / 255.0, green: 0xCC / 255.0, blue: 0x71 / 255.0)
                        )
                }

                // Prominent minimalist security warning directly below update button
                Text(YolacStrings.securityWarning)
                    .font(.system(size: 12.5))
                    .foregroundColor(Color(red: 0xE6 / 255.0, green: 0xB0 / 255.0, blue: 0xAA / 255.0))
                    .padding(14)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(red: 0x11 / 255.0, green: 0x07 / 255.0, blue: 0x07 / 255.0))
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(Color(red: 0x7A / 255.0, green: 0x2B / 255.0, blue: 0x2B / 255.0), lineWidth: 1)
                    )
                    .cornerRadius(8)

                Spacer()

                Text(YolacStrings.developerCredit)
                    .font(.system(size: 12))
                    .foregroundColor(Color(red: 0x6E / 255.0, green: 0x6E / 255.0, blue: 0x6E / 255.0))
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding(.bottom, 12)
            }
            .padding(.horizontal, 20)
        }
        .onAppear {
            vpn.refreshHealth()
        }
    }

    private func statusColor(_ status: ModuleHealthStatus) -> Color {
        switch status {
        case .healthy:
            return Color(red: 0x2E / 255.0, green: 0xCC / 255.0, blue: 0x71 / 255.0)
        case .error:
            return Color(red: 0xE7 / 255.0, green: 0x4C / 255.0, blue: 0x3C / 255.0)
        case .passiveOrUnchecked:
            return Color(red: 0x6E / 255.0, green: 0x6E / 255.0, blue: 0x6E / 255.0)
        }
    }
}
