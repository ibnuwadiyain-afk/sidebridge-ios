import SwiftUI
import UniformTypeIdentifiers

struct SetupWizardView: View {
    @EnvironmentObject private var vm: SideBridgeViewModel
    @State private var showPairingImporter = false

    var body: some View {
        NavigationStack {
            List {
                // Step 1
                Section("01. Import Pairing Record") {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("Pair This Device (.mobiledevicepairing)")
                                .font(.subheadline.weight(.semibold))
                            Spacer()
                            Text(vm.thisDevice.hasPairingRecord ? "Ready" : "Required")
                                .font(.caption.monospaced())
                                .foregroundStyle(vm.thisDevice.hasPairingRecord ? .green : .orange)
                        }
                        Text("Generate a pairing file with JitterbugPair, idevicepair, or Android SideBridge export and import it into Keychain.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Button("Import .mobiledevicepairing") {
                            showPairingImporter = true
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)
                    }
                    .padding(.vertical, 4)
                }

                // Step 2
                Section("02. Enable Local Loopback VPN") {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("SideBridgeTunnel (10.7.0.1 -> :62078)")
                                .font(.subheadline.weight(.semibold))
                            Spacer()
                            Text(vm.tunnelManager.isConnected ? "Connected" : "Stopped")
                                .font(.caption.monospaced())
                                .foregroundStyle(vm.tunnelManager.isConnected ? .green : .secondary)
                        }
                        Text("Local-only NEPacketTunnelProvider with no external server. Reflects 10.7.0.1 traffic to host lockdownd for on-device installs.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Button(vm.tunnelManager.isConnected ? "Stop Loopback Tunnel" : "Enable Loopback Tunnel") {
                            Task {
                                if vm.tunnelManager.isConnected {
                                    vm.tunnelManager.stopLoopbackTunnel()
                                } else {
                                    try? await vm.tunnelManager.startLoopbackTunnel()
                                }
                            }
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }
                    .padding(.vertical, 4)
                }

                // Step 3
                Section("03. Enable iOS 16+ Developer Mode") {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Open Settings -> Privacy & Security -> Developer Mode, switch it on, and restart your device.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Toggle("I have enabled Developer Mode", isOn: $vm.developerModeConfirmed)
                            .font(.subheadline)
                    }
                }

                // Step 4
                Section("04. Trust Developer Profile") {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("After your first install with a Free Personal Team certificate, open Settings -> General -> VPN & Device Management and tap Trust.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Toggle("Developer Profile Trusted", isOn: $vm.profileTrustedConfirmed)
                            .font(.subheadline)
                    }
                }
            }
            .navigationTitle("Setup Wizard")
            .fileImporter(isPresented: $showPairingImporter, allowedContentTypes: [.propertyList, .data]) { result in
                if case .success(let url) = result {
                    vm.importPairingFile(url: url, forThisDevice: true)
                }
            }
        }
    }
}
