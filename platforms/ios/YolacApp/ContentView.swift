import SwiftUI

/// Minimalist UI matching docs/DESIGN_SPEC.md identically across Android, iOS, and Windows.
struct ContentView: View {
    @ObservedObject var vpn: VpnController
    @AppStorage("yolac_security_warning_ack") private var securityAck = false
    @State private var showSettings = false

    var body: some View {
        GeometryReader { geo in
            let diameter = min(max(min(geo.size.width, geo.size.height) * 0.42, 160), 220)
            ZStack {
                Color.black
                    .ignoresSafeArea()

                Button(action: { vpn.toggle() }) {
                    ZStack {
                        Circle()
                            .fill(fillColor)
                            .overlay(
                                Circle()
                                    .stroke(strokeColor, lineWidth: vpn.uiState == .active ? 0 : 2)
                            )

                        PowerGlyph(color: glyphColor)
                            .frame(width: diameter * 0.48, height: diameter * 0.48)
                    }
                    .frame(width: diameter, height: diameter)
                    .contentShape(Circle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(accessibilityText)
                .accessibilityAddTraits(.isButton)

                // Small minimalist settings icon in top-right corner
                VStack {
                    HStack {
                        Spacer()
                        Button(action: {
                            vpn.refreshHealth()
                            showSettings = true
                        }) {
                            Image(systemName: "gearshape")
                                .font(.system(size: 20, weight: .regular))
                                .foregroundColor(Color(red: 0x7A / 255.0, green: 0x7A / 255.0, blue: 0x7A / 255.0))
                                .frame(width: 44, height: 44)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("Ayarlar")
                        .padding(.trailing, 14)
                        .padding(.top, 8)
                    }
                    Spacer()
                }

                // First-launch security warning overlay
                if !securityAck {
                    ZStack {
                        Color.black.ignoresSafeArea()
                        VStack(spacing: 20) {
                            Text(YolacStrings.securityWarning)
                                .font(.system(size: 15))
                                .foregroundColor(.white)
                                .padding(18)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color(red: 0x11 / 255.0, green: 0x07 / 255.0, blue: 0x07 / 255.0))
                                .overlay(
                                    RoundedRectangle(cornerRadius: 10)
                                        .stroke(Color(red: 0x8A / 255.0, green: 0x2E / 255.0, blue: 0x2E / 255.0), lineWidth: 1.5)
                                )
                                .cornerRadius(10)

                            Button(action: { securityAck = true }) {
                                Text("Anladım")
                                    .font(.system(size: 15, weight: .medium))
                                    .foregroundColor(.black)
                                    .frame(maxWidth: .infinity)
                                    .frame(height: 48)
                                    .background(Color.white)
                                    .cornerRadius(8)
                            }
                            .buttonStyle(.plain)
                        }
                        .padding(28)
                    }
                }
            }
        }
        .statusBarHidden(false)
        .fullScreenCover(isPresented: $showSettings) {
            SettingsView(vpn: vpn, isPresented: $showSettings)
                .preferredColorScheme(.dark)
        }
    }

    private var fillColor: Color {
        vpn.uiState == .active ? .white : .black
    }

    private var strokeColor: Color {
        switch vpn.uiState {
        case .inactive:
            return Color(red: 0x44 / 255.0, green: 0x44 / 255.0, blue: 0x44 / 255.0)
        case .transition:
            return Color(red: 0x99 / 255.0, green: 0x99 / 255.0, blue: 0x99 / 255.0)
        case .active:
            return .white
        case .error:
            return Color(red: 0xC9 / 255.0, green: 0x3B / 255.0, blue: 0x3B / 255.0)
        }
    }

    private var glyphColor: Color {
        switch vpn.uiState {
        case .inactive:
            return Color(red: 0x7A / 255.0, green: 0x7A / 255.0, blue: 0x7A / 255.0)
        case .transition:
            return Color(red: 0xCC / 255.0, green: 0xCC / 255.0, blue: 0xCC / 255.0)
        case .active:
            return .black
        case .error:
            return Color(red: 0xC9 / 255.0, green: 0x3B / 255.0, blue: 0x3B / 255.0)
        }
    }

    private var accessibilityText: String {
        switch vpn.uiState {
        case .inactive: return "TULPAR: Pasif. Korumayı açmak için dokunun."
        case .transition: return "TULPAR: İşlem yapılıyor."
        case .active: return "TULPAR: Aktif. Korumayı kapatmak için dokunun."
        case .error: return "TULPAR: Hata veya izin reddedildi. Tekrar deneyin."
        }
    }
}

private struct PowerGlyph: View {
    let color: Color

    var body: some View {
        Canvas { context, size in
            let cx = size.width / 2
            let cy = size.height / 2
            let r = min(size.width, size.height) * 0.38

            var arc = Path()
            arc.addArc(
                center: CGPoint(x: cx, y: cy),
                radius: r,
                startAngle: .degrees(-55),
                endAngle: .degrees(235),
                clockwise: false
            )
            context.stroke(arc, with: .color(color), style: StrokeStyle(lineWidth: 3, lineCap: .round))

            var stem = Path()
            stem.move(to: CGPoint(x: cx, y: cy - r * 1.15))
            stem.addLine(to: CGPoint(x: cx, y: cy - r * 0.15))
            context.stroke(stem, with: .color(color), style: StrokeStyle(lineWidth: 3, lineCap: .round))
        }
    }
}
