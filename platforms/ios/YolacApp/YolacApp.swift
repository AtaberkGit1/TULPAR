import SwiftUI

@main
struct YolacApp: App {
    @StateObject private var vpn = VpnController()

    var body: some Scene {
        WindowGroup {
            ContentView(vpn: vpn)
                .preferredColorScheme(.dark)
        }
    }
}
