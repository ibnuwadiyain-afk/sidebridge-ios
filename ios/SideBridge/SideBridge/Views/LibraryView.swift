import SwiftUI
import UniformTypeIdentifiers

struct LibraryView: View {
    @EnvironmentObject private var vm: SideBridgeViewModel
    @State private var showIPAImporter = false
    @State private var showP12Importer = false
    @State private var showProvisionImporter = false

    var body: some View {
        NavigationStack {
            List {
                // Target Device Selector
                Section("Install Target") {
                    Picker("Target Device", selection: $vm.selectedTargetDeviceId) {
                        ForEach(vm.allDevices) { device in
                            Text("\(device.name) (\(device.connectionKind.rawValue))")
                                .tag(device.id)
                        }
                    }

                    Toggle("Use Custom .p12 & .mobileprovision", isOn: $vm.useCustomP12Signing)

                    if vm.useCustomP12Signing {
                        HStack {
                            Button(vm.customP12Loaded ? "Replace .p12" : "Import .p12") {
                                showP12Importer = true
                            }
                            .buttonStyle(.bordered)
                            Spacer()
                            Button(vm.customProvisionLoaded ? "Replace Profile" : "Import Profile") {
                                showProvisionImporter = true
                            }
                            .buttonStyle(.bordered)
                        }
                        SecureField("PKCS#12 Passphrase", text: $vm.customP12Passphrase)
                            .textInputAutocapitalization(.never)
                    }
                }

                // Local IPA Library
                Section("Local IPA Packages") {
                    if vm.importedIPAs.isEmpty {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("No .ipa packages imported yet.")
                                .font(.subheadline)
                            Text("Import a decrypted .ipa from Files or download one from the Apps tab.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Button("Import .ipa File") { showIPAImporter = true }
                                .buttonStyle(.borderedProminent)
                                .controlSize(.small)
                        }
                        .padding(.vertical, 6)
                    } else {
                        ForEach(vm.importedIPAs) { ipa in
                            HStack {
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(ipa.displayName).font(.subheadline.weight(.semibold))
                                    Text("\(ipa.bundleIdentifier) · \(ByteCountFormatter.string(fromByteCount: ipa.fileSizeBytes, countStyle: .file))")
                                        .font(.caption.monospaced())
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                Button("Install") {
                                    Task { await vm.installIPA(ipa) }
                                }
                                .buttonStyle(.borderedProminent)
                                .controlSize(.small)
                                .disabled(vm.isInstalling)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Library")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showIPAImporter = true
                    } label: {
                        Label("Import IPA", systemImage: "plus")
                    }
                }
            }
            .fileImporter(isPresented: $showIPAImporter, allowedContentTypes: [.data, .zip]) { result in
                if case .success(let url) = result { vm.importIPA(from: url) }
            }
            .fileImporter(isPresented: $showP12Importer, allowedContentTypes: [.pkcs12, .data]) { result in
                if case .success(let url) = result { vm.importCustomP12(from: url) }
            }
            .fileImporter(isPresented: $showProvisionImporter, allowedContentTypes: [.data]) { result in
                if case .success(let url) = result { vm.importCustomMobileProvision(from: url) }
            }
        }
    }
}
