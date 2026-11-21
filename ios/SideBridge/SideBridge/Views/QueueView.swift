import SwiftUI

struct QueueView: View {
    @EnvironmentObject private var vm: SideBridgeViewModel
    @State private var selectedFilter: LogCategory?

    var filteredLogs: [ProtocolLogEntry] {
        guard let filter = selectedFilter else { return vm.protocolLogs }
        return vm.protocolLogs.filter { $0.category == filter }
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                // 4-Stage Pipeline Stepper
                VStack(alignment: .leading, spacing: 12) {
                    HStack(spacing: 8) {
                        ForEach(InstallStage.allCases, id: \.self) { stage in
                            VStack(alignment: .leading, spacing: 4) {
                                Rectangle()
                                    .fill(stageColor(stage))
                                    .frame(height: 4)
                                    .clipShape(Capsule())
                                Text(stage.title)
                                    .font(.caption2.weight(.semibold))
                                    .foregroundStyle(stage.rawValue <= vm.currentInstallStage.rawValue ? .primary : .secondary)
                                    .lineLimit(1)
                            }
                            .frame(maxWidth: .infinity)
                        }
                    }

                    ProgressView(value: vm.currentStageProgress)
                    Text(vm.currentStageStatus)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)

                    if let error = vm.activeInstallError {
                        Text(error)
                            .font(.caption)
                            .foregroundStyle(.red)
                    }
                }
                .padding()
                .background(Color(white: 0.09))

                Divider()

                // Category Filter Bar
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        filterButton(title: "All", category: nil)
                        ForEach(LogCategory.allCases, id: \.self) { cat in
                            filterButton(title: cat.rawValue, category: cat)
                        }
                    }
                    .padding(.horizontal)
                    .padding(.vertical, 8)
                }

                // Redacted Diagnostic Protocol Log Console
                ScrollViewReader { proxy in
                    List(filteredLogs) { entry in
                        HStack(alignment: .top, spacing: 8) {
                            Text(entry.category.rawValue)
                                .font(.caption2.monospaced().weight(.semibold))
                                .foregroundStyle(entry.isError ? .red : .blue)
                                .frame(width: 88, alignment: .leading)
                            Text(entry.message)
                                .font(.caption2.monospaced())
                                .foregroundStyle(entry.isError ? .red : .primary)
                                .textSelection(.enabled)
                        }
                        .listRowBackground(Color.clear)
                        .id(entry.id)
                    }
                    .listStyle(.plain)
                    .onChange(of: vm.protocolLogs.count) { _ in
                        if let last = filteredLogs.last {
                            proxy.scrollTo(last.id, anchor: .bottom)
                        }
                    }
                }
            }
            .navigationTitle("Queue")
            .toolbar {
                ToolbarItemGroup(placement: .topBarTrailing) {
                    Button("Copy") {
                        UIPasteboard.general.string = vm.exportRedactedLogsText()
                    }
                    ShareLink(item: vm.exportRedactedLogsText()) {
                        Image(systemName: "square.and.arrow.up")
                    }
                    Button("Clear") { vm.clearLogs() }
                }
            }
        }
    }

    private func stageColor(_ stage: InstallStage) -> Color {
        if vm.activeInstallError != nil && stage == vm.currentInstallStage {
            return .red
        }
        if stage.rawValue < vm.currentInstallStage.rawValue {
            return .green
        }
        if stage == vm.currentInstallStage && vm.isInstalling {
            return .blue
        }
        return Color.secondary.opacity(0.25)
    }

    private func filterButton(title: String, category: LogCategory?) -> some View {
        Button(title) {
            selectedFilter = category
        }
        .font(.caption.monospaced())
        .buttonStyle(.bordered)
        .tint(selectedFilter == category ? .blue : .secondary)
    }
}
