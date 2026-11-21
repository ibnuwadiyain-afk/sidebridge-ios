import SwiftUI
import UniformTypeIdentifiers

@main
struct SideBridgeApp: App {
    @StateObject private var viewModel = SideBridgeViewModel()

    var body: some Scene {
        WindowGroup {
            SideBridgeRootView()
                .environmentObject(viewModel)
                .preferredColorScheme(.dark)
                .tint(Color(red: 0.23, green: 0.51, blue: 0.96))
                .onOpenURL { url in
                    viewModel.handleIncomingFileURL(url)
                }
        }
    }
}

struct SideBridgeRootView: View {
    @EnvironmentObject private var vm: SideBridgeViewModel

    var body: some View {
        TabView(selection: $vm.selectedTab) {
            DevicesView()
                .tabItem { Label("Devices", systemImage: "iphone.radiowaves.left.and.right") }
                .tag(SideBridgeTab.devices)

            LibraryView()
                .tabItem { Label("Library", systemImage: "shippingbox") }
                .tag(SideBridgeTab.library)

            AppsView()
                .tabItem { Label("Apps", systemImage: "square.grid.2x2") }
                .tag(SideBridgeTab.apps)

            QueueView()
                .tabItem { Label("Queue", systemImage: "terminal") }
                .tag(SideBridgeTab.queue)

            AccountView()
                .tabItem { Label("Account", systemImage: "person.badge.key") }
                .tag(SideBridgeTab.account)

            SetupWizardView()
                .tabItem { Label("Setup", systemImage: "checklist") }
                .tag(SideBridgeTab.setup)
        }
        .background(Color(red: 0.035, green: 0.043, blue: 0.063).ignoresSafeArea())
        .onAppear {
            vm.startDiscovery()
        }
    }
}

enum SideBridgeTab: Int, Hashable {
    case devices, library, apps, queue, account, setup
}
