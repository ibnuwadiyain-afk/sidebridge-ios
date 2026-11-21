import SwiftUI
import UniformTypeIdentifiers

struct DevicesView: View {
    @EnvironmentObject private var vm: SideBridgeViewModel
    @State private var showPairingImporter = false
    @State private var importForThisDevice = true

    var body: some View {
        NavigationStack {
            List {
                // Section 1: This Device (Loopback VPN)
                Section("This Device (Loopback VPN)") {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(vm.thisDevice.name)
                                    .font(.headline)
                                Text("10.7.0.1:62078 · \(vm.tunnelManager.isConnected ? "Tunnel Active" : "Tunnel Stopped")")
                                    .font(.caption.monospaced())
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button(vm.tunnelManager.isConnected ? "Stop VPN" : "Start VPN") {
                                Task {
                                    if vm.tunnelManager.isConnected {
                                        vm.tunnelManager.stopLoopbackTunnel()
                                    } else {
                                        try? await vm.tunnelManager.startLoopbackTunnel()
                                    }
                                }
                            }
                            .buttonStyle(.borderedProminent)
                            .controlSize(.small)
                        }

                        HStack(spacing: 12) {
                            Button("Test Connection") {
                                Task { await vm.testConnection(to: vm.thisDevice) }
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)

                            Button("Import Pairing") {
                                importForThisDevice = true
                                showPairingImporter = true
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                        }
                    }
                    .padding(.vertical, 4)
                }

                // Section 2: USB-C / OTG Peer Devices
                Section("USB-C / OTG Peer Devices") {
                    if vm.usbDevices.isEmpty {
                        HStack {
                            Text("No USB Ethernet / NCM peers detected on :62078")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                            Spacer()
                            Button("Scan") { vm.refreshUsbDiscovery() }
                                .font(.footnote)
                        }
                    } else {
                        ForEach(vm.usbDevices) { device in
                            deviceRow(device)
                        }
                    }
                }

                // Section 3: Wi-Fi Bonjour Devices (_apple-mobdev2._tcp)
                Section("Wi-Fi Bonjour (_apple-mobdev2._tcp)") {
                    if vm.wifiDevices.isEmpty {
                        Text("Browsing local network for iOS devices (auto-mapping 32498 -> 62078)...")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(vm.wifiDevices) { device in
                            deviceRow(device)
                        }
                    }
                }

                if let status = vm.connectionTestMessage {
                    Section("Connection Diagnostic") {
                        Text(status)
                            .font(.footnote.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Devices")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        importForThisDevice = false
                        showPairingImporter = true
                    } label: {
                        Label("Import Remote Pairing", systemImage: "doc.badge.plus")
                    }
                }
            }
            .fileImporter(
                isPresented: $showPairingImporter,
                allowedContentTypes: [.propertyList, .data],
                allowsMultipleSelection: false
            ) { result in
                if case .success(let urls) = result, let url = urls.first {
                    vm.importPairingFile(url: url, forThisDevice: importForThisDevice)
                }
            }
        }
    }

    @ViewBuilder
    private func deviceRow(_ device: DiscoveredDevice) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 3) {
                Text(device.name).font(.subheadline.weight(.semibold))
                Text("\(device.host):\(device.port) · \(device.connectionKind.rawValue)\(device.hasPairingRecord ? " · Paired" : " · Unpaired")")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Test") {
                Task { await vm.testConnection(to: device) }
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
        }
    }
}
