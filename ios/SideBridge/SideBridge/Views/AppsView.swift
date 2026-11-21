import SwiftUI

struct AppsView: View {
    @EnvironmentObject private var vm: SideBridgeViewModel
    @State private var searchText = ""

    var filteredApps: [RepoAppItem] {
        guard !searchText.isEmpty else { return vm.repoApps }
        return vm.repoApps.filter {
            $0.name.localizedCaseInsensitiveContains(searchText) ||
            $0.developer.localizedCaseInsensitiveContains(searchText)
        }
    }

    var body: some View {
        NavigationStack {
            List {
                Section("Direct IPA URL Download") {
                    HStack {
                        TextField("https://example.com/app.ipa", text: $vm.directDownloadURLText)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .keyboardType(.URL)
                        Button("Fetch") {
                            if let url = URL(string: vm.directDownloadURLText.trimmingCharacters(in: .whitespacesAndNewlines)) {
                                Task { await vm.downloadIPA(from: url) }
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)
                        .disabled(vm.directDownloadURLText.isEmpty || vm.activeDownloadProgress != nil)
                    }
                    if let progress = vm.activeDownloadProgress {
                        ProgressView(value: progress)
                    }
                }

                Section("Archive.org Decrypted IPA Feed") {
                    if vm.isLoadingRepo {
                        ProgressView("Loading collection feed...")
                    } else if filteredApps.isEmpty {
                        Button("Load Archive.org IPA Collection") {
                            Task { await vm.loadArchiveOrgFeed() }
                        }
                    } else {
                        ForEach(filteredApps) { item in
                            HStack {
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(item.name).font(.subheadline.weight(.semibold))
                                    Text("\(item.developer) · \(ByteCountFormatter.string(fromByteCount: item.sizeBytes, countStyle: .file))")
                                        .font(.caption.monospaced())
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                Button("Get") {
                                    Task { await vm.downloadIPA(from: item.downloadURL, suggestedName: "\(item.id).ipa") }
                                }
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                            }
                        }
                    }
                }
            }
            .searchable(text: $searchText, prompt: "Filter IPA packages")
            .navigationTitle("Apps")
            .task {
                if vm.repoApps.isEmpty {
                    await vm.loadArchiveOrgFeed()
                }
            }
        }
    }
}
