import Foundation
import SwiftUI
import Combine
import ZIPFoundation

@MainActor
final class SideBridgeViewModel: ObservableObject {
    @Published var selectedTab: SideBridgeTab = .devices

    // Devices & Pairing
    @Published var thisDevice: DiscoveredDevice
    @Published var wifiDevices: [DiscoveredDevice] = []
    @Published var usbDevices: [DiscoveredDevice] = []
    @Published var pairingRecords: [PairingRecord] = []
    @Published var selectedTargetDeviceId: String = "this-device-loopback"
    @Published var connectionTestMessage: String?

    // Library & Custom Signing
    @Published var importedIPAs: [LocalIPA] = []
    @Published var useCustomP12Signing: Bool = false
    @Published var customP12Loaded: Bool = false
    @Published var customProvisionLoaded: Bool = false
    @Published var customP12Passphrase: String = ""

    // Apps / Repositories
    @Published var repoApps: [RepoAppItem] = []
    @Published var directDownloadURLText: String = ""
    @Published var isLoadingRepo: Bool = false
    @Published var activeDownloadProgress: Double?

    // Queue & Logs
    @Published var isInstalling: Bool = false
    @Published var currentInstallStage: InstallStage = .provisioning
    @Published var currentStageProgress: Double = 0
    @Published var currentStageStatus: String = "Idle"
    @Published var activeInstallError: String?
    @Published var protocolLogs: [ProtocolLogEntry] = []

    // Account & Provisioning
    @Published var appleSession: AppleAccountSession?
    @Published var activeCertRecord: SigningIdentityRecord?
    @Published var registeredAppIds: [AppIdRecord] = []
    @Published var pendingTwoFactor: GrandSlamSRP.TwoFactorChallenge?
    @Published var authErrorMessage: String?
    @Published var isAuthenticating: Bool = false

    // Setup Wizard Checklist
    @Published var developerModeConfirmed: Bool = false
    @Published var profileTrustedConfirmed: Bool = false

    let tunnelManager = LocalTunnelManager.shared
    private let wifiDiscovery = WifiDeviceDiscovery()
    private let usbDiscovery = UsbNetworkDiscovery()
    private let srpClient = GrandSlamSRP()
    private let keychain = KeychainStorage.shared
    private let pairingStorage = PairingStorage.shared

    init() {
        let localPairing = PairingStorage.shared.thisDeviceRecord()
        self.thisDevice = DiscoveredDevice(
            id: "this-device-loopback",
            udid: localPairing?.udid,
            name: localPairing?.deviceName ?? UIDevice.current.name,
            host: LocalTunnelManager.loopbackLockdownHost,
            port: LocalTunnelManager.loopbackLockdownPort,
            interfaceName: "utun-loopback",
            connectionKind: .loopbackVPN,
            productVersion: UIDevice.current.systemVersion,
            hasPairingRecord: localPairing != nil
        )
        loadPersistedState()
    }

    var allDevices: [DiscoveredDevice] {
        [thisDevice] + usbDevices + wifiDevices
    }

    var selectedTargetDevice: DiscoveredDevice {
        allDevices.first(where: { $0.id == selectedTargetDeviceId }) ?? thisDevice
    }

    func loadPersistedState() {
        pairingRecords = pairingStorage.allRecords()
        if let local = pairingStorage.thisDeviceRecord() {
            thisDevice.udid = local.udid
            thisDevice.name = local.deviceName
            thisDevice.hasPairingRecord = true
        }
        appleSession = try? keychain.loadCodable(AppleAccountSession.self, for: .appleSession)
        activeCertRecord = try? keychain.loadCodable(SigningIdentityRecord.self, for: .activeCertRecord)
        customP12Loaded = (try? keychain.loadData(for: KeychainStorage.Key.customP12Data.rawValue)) != nil
        customProvisionLoaded = (try? keychain.loadData(for: KeychainStorage.Key.customMobileProvision.rawValue)) != nil
        reloadLocalIPAs()
    }

    func startDiscovery() {
        wifiDiscovery.start { [weak self] devices in
            Task { @MainActor in
                self?.wifiDevices = devices
            }
        }
        usbDiscovery.start { [weak self] devices in
            Task { @MainActor in
                self?.usbDevices = devices
            }
        }
    }

    func refreshUsbDiscovery() {
        usbDiscovery.triggerProbe()
    }

    func appendLog(_ category: LogCategory, _ message: String, isError: Bool = false) {
        protocolLogs.append(ProtocolLogEntry(category: category, message: message, isError: isError))
        if protocolLogs.count > 1000 {
            protocolLogs.removeFirst(protocolLogs.count - 1000)
        }
    }

    func clearLogs() {
        protocolLogs.removeAll()
    }

    func exportRedactedLogsText() -> String {
        let formatter = ISO8601DateFormatter()
        return protocolLogs.map { entry in
            "[\(formatter.string(from: entry.timestamp))] [\(entry.category.rawValue)] \(entry.message)"
        }.joined(separator: "\n")
    }

    // MARK: - Pairing & Connection Testing

    func importPairingFile(url: URL, forThisDevice: Bool) {
        do {
            let record = try pairingStorage.importPairingFile(from: url, markAsThisDevice: forThisDevice)
            loadPersistedState()
            appendLog(.transport, "Imported pairing record for \(record.deviceName) (UDID=\(record.udid.prefix(8))..., thisDevice=\(forThisDevice))")
        } catch {
            appendLog(.transport, "Pairing import failed: \(error.localizedDescription)", isError: true)
            connectionTestMessage = error.localizedDescription
        }
    }

    func testConnection(to device: DiscoveredDevice) async {
        connectionTestMessage = "Testing connection to \(device.name)..."
        do {
            if device.connectionKind == .loopbackVPN {
                try await tunnelManager.ensureConnected(timeout: 8.0)
            }
            let tcp = TcpDeviceTransport(host: device.host, port: device.port)
            try await tcp.connect(timeout: 6.0)
            let lockdown = LockdownClient(transport: tcp) { [weak self] cat, msg, err in
                Task { @MainActor in self?.appendLog(cat, msg, isError: err) }
            }
            defer { lockdown.close() }

            let type = try await lockdown.queryType()
            let info = try await lockdown.fetchDeviceInfo()
            if let pairing = resolvePairingRecord(for: device, discoveredUDID: info.udid) {
                _ = try await lockdown.startSession(with: pairing)
                await lockdown.stopSession()
                connectionTestMessage = "Verified TLS 1.2 session with \(info.deviceName) (iOS \(info.productVersion), \(type))"
            } else {
                connectionTestMessage = "Reached \(info.deviceName) (iOS \(info.productVersion)) — import .mobiledevicepairing for TLS."
            }
        } catch {
            connectionTestMessage = error.localizedDescription
            appendLog(.transport, "Connection test failed: \(error.localizedDescription)", isError: true)
        }
    }

    // MARK: - IPA & Credential Import

    func handleIncomingFileURL(_ url: URL) {
        let ext = url.pathExtension.lowercased()
        switch ext {
        case "ipa":
            importIPA(from: url)
            selectedTab = .library
        case "mobiledevicepairing", "plist":
            importPairingFile(url: url, forThisDevice: true)
            selectedTab = .devices
        case "p12":
            importCustomP12(from: url)
            selectedTab = .library
        case "mobileprovision":
            importCustomMobileProvision(from: url)
            selectedTab = .library
        default:
            break
        }
    }

    func importIPA(from sourceURL: URL) {
        let accessed = sourceURL.startAccessingSecurityScopedResource()
        defer { if accessed { sourceURL.stopAccessingSecurityScopedResource() } }

        do {
            let destDir = ipaLibraryDirectory()
            try FileManager.default.createDirectory(at: destDir, withIntermediateDirectories: true)
            let destURL = destDir.appendingPathComponent(sourceURL.lastPathComponent)
            if FileManager.default.fileExists(atPath: destURL.path) {
                try FileManager.default.removeItem(at: destURL)
            }
            try FileManager.default.copyItem(at: sourceURL, to: destURL)
            reloadLocalIPAs()
            appendLog(.sign, "Imported IPA into Library: \(destURL.lastPathComponent)")
        } catch {
            appendLog(.sign, "IPA import failed: \(error.localizedDescription)", isError: true)
        }
    }

    func importCustomP12(from url: URL) {
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }
        do {
            let data = try Data(contentsOf: url)
            try keychain.save(data, for: KeychainStorage.Key.customP12Data.rawValue)
            customP12Loaded = true
            appendLog(.provision, "Stored custom .p12 signing identity in Keychain (\(data.count) bytes)")
        } catch {
            appendLog(.provision, "Failed to import .p12: \(error.localizedDescription)", isError: true)
        }
    }

    func importCustomMobileProvision(from url: URL) {
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }
        do {
            let data = try Data(contentsOf: url)
            try keychain.save(data, for: KeychainStorage.Key.customMobileProvision.rawValue)
            customProvisionLoaded = true
            appendLog(.provision, "Stored custom .mobileprovision profile (\(data.count) bytes)")
        } catch {
            appendLog(.provision, "Failed to import .mobileprovision: \(error.localizedDescription)", isError: true)
        }
    }

    func installIPA(_ ipa: LocalIPA) async {
        guard !isInstalling else { return }
        let target = selectedTargetDevice
        guard let pairing = resolvePairingRecord(for: target, discoveredUDID: target.udid) else {
            activeInstallError = "No .mobiledevicepairing record found for \(target.name). Import one in Devices or Setup Wizard."
            selectedTab = .queue
            return
        }

        let signingMode: SigningMode
        if useCustomP12Signing {
            guard
                let p12 = try? keychain.loadData(for: KeychainStorage.Key.customP12Data.rawValue),
                let prov = try? keychain.loadData(for: KeychainStorage.Key.customMobileProvision.rawValue)
            else {
                activeInstallError = "Custom .p12 and .mobileprovision must both be imported in Library."
                selectedTab = .queue
                return
            }
            signingMode = .customP12(p12Data: p12, passphrase: customP12Passphrase, mobileProvision: prov)
        } else {
            guard let session = appleSession else {
                activeInstallError = "Sign in with your Apple ID in the Account tab first, or switch to Custom .p12 signing."
                selectedTab = .account
                return
            }
            signingMode = .freeAppleID(session)
        }

        isInstalling = true
        activeInstallError = nil
        currentInstallStage = .provisioning
        currentStageProgress = 0
        currentStageStatus = "Starting pipeline..."
        selectedTab = .queue

        let ipaURL = ipaLibraryDirectory().appendingPathComponent(ipa.fileName)
        let fallbackWifi = wifiDevices.first(where: { $0.udid != nil && $0.udid == target.udid })

        let installer = DeviceInstaller { [weak self] cat, msg, isErr in
            Task { @MainActor in self?.appendLog(cat, msg, isError: isErr) }
        }

        do {
            try await installer.installIPA(
                sourceIPAURL: ipaURL,
                originalBundleId: ipa.bundleIdentifier,
                primaryDevice: target,
                fallbackWifiDevice: fallbackWifi,
                pairingRecord: pairing,
                signingMode: signingMode
            ) { [weak self] update in
                Task { @MainActor in
                    self?.currentInstallStage = update.stage
                    self?.currentStageProgress = update.stageProgress
                    self?.currentStageStatus = update.statusMessage
                }
            }
        } catch {
            activeInstallError = error.localizedDescription
            appendLog(.instproxy, "Pipeline failed: \(error.localizedDescription)", isError: true)
        }
        isInstalling = false
    }

    // MARK: - Apple ID Account Flow

    func signInAppleID(email: String, password: String) async {
        isAuthenticating = true
        authErrorMessage = nil
        defer { isAuthenticating = false }

        do {
            appendLog(.provision, "Initiating GrandSlam SRP-6a (s2k/s2k_fo) login for \(email)")
            let result = try await srpClient.authenticate(appleId: email, password: password)
            switch result {
            case .authenticated(let dsid, let adsid, let token):
                try await finalizeAppleSession(appleId: email, dsid: dsid, adsid: adsid, token: token)
            case .twoFactorRequired(let challenge):
                pendingTwoFactor = challenge
                appendLog(.provision, "Apple requested 6-digit trusted-device / SMS 2FA code")
            }
        } catch {
            authErrorMessage = error.localizedDescription
            appendLog(.provision, "Apple ID login failed: \(error.localizedDescription)", isError: true)
        }
    }

    func submitTwoFactor(code: String) async {
        guard let challenge = pendingTwoFactor else { return }
        isAuthenticating = true
        authErrorMessage = nil
        defer { isAuthenticating = false }

        do {
            let (dsid, adsid, token) = try await srpClient.submitTwoFactorCode(code, challenge: challenge)
            pendingTwoFactor = nil
            try await finalizeAppleSession(appleId: challenge.appleId, dsid: dsid, adsid: adsid, token: token)
        } catch {
            authErrorMessage = error.localizedDescription
        }
    }

    private func finalizeAppleSession(appleId: String, dsid: String, adsid: String, token: String) async throws {
        let provisioner = AppleDeveloperProvisioner { [weak self] cat, msg, err in
            Task { @MainActor in self?.appendLog(cat, msg, isError: err) }
        }
        let teams = try await provisioner.listTeams(adsid: adsid, token: token)
        guard let firstTeam = teams.first, let teamId = firstTeam["teamId"] as? String else {
            throw ProvisionerError.portalError("No developer team returned for Apple ID.")
        }
        let teamName = (firstTeam["name"] as? String) ?? "Personal Team"
        let isFree = ((firstTeam["type"] as? String) ?? "Individual") != "Company/Organization"

        let session = AppleAccountSession(
            appleId: appleId,
            dsid: dsid,
            adsid: adsid,
            xcodeAuthToken: token,
            teamId: teamId,
            teamName: teamName,
            isFreePersonalTeam: isFree,
            authenticatedAt: Date()
        )
        try keychain.saveCodable(session, for: .appleSession)
        self.appleSession = session
        await refreshAccountQuota()
    }

    func refreshAccountQuota() async {
        guard let session = appleSession else { return }
        let provisioner = AppleDeveloperProvisioner { [weak self] cat, msg, err in
            Task { @MainActor in self?.appendLog(cat, msg, isError: err) }
        }
        do {
            registeredAppIds = try await provisioner.listAppIds(session: session)
            let certs = try await provisioner.listAllDevelopmentCerts(session: session)
            if let first = certs.first {
                activeCertRecord = SigningIdentityRecord(
                    id: first.certificateId,
                    displayName: first.name,
                    serialNumber: first.serialNumber,
                    sha1Thumbprint: first.sha1Thumbprint,
                    sha256Thumbprint: first.sha256Thumbprint,
                    expiresAt: Date().addingTimeInterval(7 * 24 * 3600),
                    isCustomP12: false
                )
            }
        } catch {
            authErrorMessage = error.localizedDescription
        }
    }

    func signOutAppleID() {
        keychain.delete(for: KeychainStorage.Key.appleSession.rawValue)
        appleSession = nil
        registeredAppIds = []
        activeCertRecord = nil
    }

    // MARK: - Repositories & Direct IPA Downloads

    func loadArchiveOrgFeed() async {
        isLoadingRepo = true
        defer { isLoadingRepo = false }
        guard let url = URL(string: "https://archive.org/advancedsearch.php?q=mediatype:software+AND+format:ipa&fl[]=identifier,title,creator,item_size&rows=25&output=json") else {
            return
        }
        do {
            let (data, _) = try await URLSession.shared.data(from: url)
            if let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
               let resp = json["response"] as? [String: Any],
               let docs = resp["docs"] as? [[String: Any]] {
                repoApps = docs.compactMap { doc in
                    guard let id = doc["identifier"] as? String,
                          let title = doc["title"] as? String,
                          let dlURL = URL(string: "https://archive.org/download/\(id)/\(id).ipa") else { return nil }
                    return RepoAppItem(
                        id: id,
                        name: title,
                        bundleId: "org.archive.\(id)",
                        version: "1.0",
                        developer: (doc["creator"] as? String) ?? "Archive.org",
                        sizeBytes: (doc["item_size"] as? NSNumber)?.int64Value ?? 0,
                        downloadURL: dlURL,
                        sourceName: "Archive.org Collection",
                        summary: "Decrypted iOS IPA package from Archive.org"
                    )
                }
            }
        } catch {
            appendLog(.transport, "Failed to fetch Archive.org repository: \(error.localizedDescription)", isError: true)
        }
    }

    func downloadIPA(from url: URL, suggestedName: String? = nil) async {
        activeDownloadProgress = 0.05
        defer { activeDownloadProgress = nil }
        do {
            let (tempURL, _) = try await URLSession.shared.download(from: url)
            activeDownloadProgress = 0.85
            let fileName = suggestedName ?? (url.lastPathComponent.hasSuffix(".ipa") ? url.lastPathComponent : "Downloaded.ipa")
            let destDir = ipaLibraryDirectory()
            try FileManager.default.createDirectory(at: destDir, withIntermediateDirectories: true)
            let destURL = destDir.appendingPathComponent(fileName)
            if FileManager.default.fileExists(atPath: destURL.path) {
                try FileManager.default.removeItem(at: destURL)
            }
            try FileManager.default.moveItem(at: tempURL, to: destURL)
            reloadLocalIPAs()
            activeDownloadProgress = 1.0
            appendLog(.transport, "Downloaded \(fileName) into Library")
        } catch {
            appendLog(.transport, "Direct IPA download failed: \(error.localizedDescription)", isError: true)
        }
    }

    // MARK: - Helpers

    private func resolvePairingRecord(for device: DiscoveredDevice, discoveredUDID: String?) -> PairingRecord? {
        if device.connectionKind == .loopbackVPN {
            return pairingStorage.thisDeviceRecord()
        }
        if let udid = discoveredUDID ?? device.udid {
            return pairingStorage.record(forUDID: udid)
        }
        return pairingRecords.first
    }

    private func ipaLibraryDirectory() -> URL {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        return docs.appendingPathComponent("IPAs", isDirectory: true)
    }

    private func reloadLocalIPAs() {
        let dir = ipaLibraryDirectory()
        guard let files = try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.fileSizeKey, .creationDateKey]) else {
            importedIPAs = []
            return
        }
        importedIPAs = files.filter { $0.pathExtension.lowercased() == "ipa" }.map { url in
            let vals = try? url.resourceValues(forKeys: [.fileSizeKey, .creationDateKey])
            let baseName = url.deletingPathExtension().lastPathComponent
            return LocalIPA(
                displayName: baseName,
                bundleIdentifier: "com.sidebridge.\(baseName.lowercased().replacingOccurrences(of: " ", with: ""))",
                version: "1.0",
                fileName: url.lastPathComponent,
                fileSizeBytes: Int64(vals?.fileSize ?? 0),
                importedAt: vals?.creationDate ?? Date()
            )
        }
    }
}
