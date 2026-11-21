import Foundation
import UIKit

public struct InstallProgressUpdate: Sendable {
    public let stage: InstallStage
    public let stageProgress: Double // 0.0 ... 1.0
    public let statusMessage: String
}

public enum SigningMode: Sendable {
    case freeAppleID(AppleAccountSession)
    case customP12(p12Data: Data, passphrase: String, mobileProvision: Data)
}

/// 4-stage installation orchestrator (`Provisioning` -> `Signing` -> `AFC Uploading` -> `Installing`)
/// protected by `UIApplication.shared.beginBackgroundTask`, with automatic USB-C/OTG -> Wi-Fi
/// transport fallback and optional `itms-services://` OTA manifest fallback for Ad-Hoc/Enterprise certs.
public final class DeviceInstaller: @unchecked Sendable {
    private let provisioner: AppleDeveloperProvisioner
    private let ipaSigner: IpaSigner
    private let logger: @Sendable (LogCategory, String, Bool) -> Void

    public init(logger: @escaping @Sendable (LogCategory, String, Bool) -> Void) {
        self.logger = logger
        self.provisioner = AppleDeveloperProvisioner(logger: logger)
        self.ipaSigner = IpaSigner(logger: logger)
    }

    public func installIPA(
        sourceIPAURL: URL,
        originalBundleId: String,
        primaryDevice: DiscoveredDevice,
        fallbackWifiDevice: DiscoveredDevice? = nil,
        pairingRecord: PairingRecord,
        signingMode: SigningMode,
        onProgress: @escaping @Sendable (InstallProgressUpdate) -> Void
    ) async throws {
        // Keep the signing + AFC streaming pipeline alive if the user briefly switches apps
        let bgTaskId = await MainActor.run {
            UIApplication.shared.beginBackgroundTask(withName: "SideBridgeInstallPipeline") {
                self.logger(.transport, "iOS background execution grace window expiring", true)
            }
        }
        defer {
            Task { @MainActor in
                if bgTaskId != .invalid {
                    UIApplication.shared.endBackgroundTask(bgTaskId)
                }
            }
        }

        // MARK: Stage 1 — Provisioning
        onProgress(InstallProgressUpdate(stage: .provisioning, stageProgress: 0.15, statusMessage: "Preparing signing identity and provisioning profile..."))
        let p12Data: Data
        let p12Passphrase: String
        let mobileProvisionData: Data
        let effectiveBundleId: String

        switch signingMode {
        case .freeAppleID(let session):
            let bundle = try await provisioner.prepareProvisioning(
                session: session,
                deviceUDID: pairingRecord.udid,
                deviceName: pairingRecord.deviceName,
                originalBundleId: originalBundleId
            )
            p12Data = bundle.p12Data
            p12Passphrase = bundle.p12Passphrase
            mobileProvisionData = bundle.mobileProvisionData
            effectiveBundleId = bundle.effectiveBundleIdentifier
        case .customP12(let customP12, let pass, let profile):
            logger(.provision, "Using custom .p12 signing identity and imported .mobileprovision", false)
            p12Data = customP12
            p12Passphrase = pass
            mobileProvisionData = profile
            effectiveBundleId = originalBundleId
        }
        onProgress(InstallProgressUpdate(stage: .provisioning, stageProgress: 1.0, statusMessage: "Provisioning profile verified"))

        // MARK: Stage 2 — On-Device Signing
        onProgress(InstallProgressUpdate(stage: .signing, stageProgress: 0.2, statusMessage: "Signing nested frameworks, dylibs, and Mach-O binary..."))
        let signedResult = try ipaSigner.signIPA(
            sourceIPAURL: sourceIPAURL,
            p12Data: p12Data,
            p12Passphrase: p12Passphrase,
            mobileProvisionData: mobileProvisionData,
            overrideBundleId: effectiveBundleId
        )
        onProgress(InstallProgressUpdate(
            stage: .signing,
            stageProgress: 1.0,
            statusMessage: "Signed \(signedResult.signedComponentCount) Mach-O components"
        ))

        // MARK: Stage 3 & 4 — Transport Connect (USB-OTG -> Wi-Fi fallback) + AFC Upload + InstallationProxy
        let selectedDevice = try await resolveReachableDevice(primary: primaryDevice, fallbackWifi: fallbackWifiDevice)

        if selectedDevice.connectionKind == .loopbackVPN {
            try await LocalTunnelManager.shared.ensureConnected(timeout: 8.0)
        }

        let lockdownTransport = TcpDeviceTransport(host: selectedDevice.host, port: selectedDevice.port)
        try await lockdownTransport.connect(timeout: 8.0)
        let lockdown = LockdownClient(transport: lockdownTransport, logger: logger)
        defer { lockdown.close() }

        _ = try await lockdown.queryType()
        _ = try await lockdown.startSession(with: pairingRecord)

        // Stage 3: Start com.apple.afc and stream signed IPA in 64KB chunks
        onProgress(InstallProgressUpdate(stage: .afcUploading, stageProgress: 0.02, statusMessage: "Starting com.apple.afc service..."))
        let afcDescriptor = try await lockdown.startService("com.apple.afc")
        let afcTransport = try await openServiceTransport(
            host: selectedDevice.host,
            descriptor: afcDescriptor,
            pairingRecord: pairingRecord
        )
        let afcClient = AfcClient(transport: afcTransport, logger: logger)
        defer { afcClient.close() }

        let stagedPath = try await afcClient.uploadIPA(
            fileURL: signedResult.signedIPAURL,
            bundleIdentifier: signedResult.effectiveBundleIdentifier,
            chunkSize: 65_536
        ) { fraction, sent, total in
            let mbSent = Double(sent) / 1_048_576.0
            let mbTotal = Double(total) / 1_048_576.0
            onProgress(InstallProgressUpdate(
                stage: .afcUploading,
                stageProgress: fraction,
                statusMessage: String(format: "Uploading %.1f / %.1f MB", mbSent, mbTotal)
            ))
        }

        // Stage 4: Start com.apple.mobile.installation_proxy and stream status until Complete
        onProgress(InstallProgressUpdate(stage: .installing, stageProgress: 0.05, statusMessage: "Starting com.apple.mobile.installation_proxy..."))
        let instDescriptor = try await lockdown.startService("com.apple.mobile.installation_proxy")
        let instTransport = try await openServiceTransport(
            host: selectedDevice.host,
            descriptor: instDescriptor,
            pairingRecord: pairingRecord
        )
        let instProxy = InstallationProxyClient(transport: instTransport, logger: logger)
        defer { instProxy.close() }

        try await instProxy.install(
            packagePath: stagedPath,
            bundleIdentifier: signedResult.effectiveBundleIdentifier
        ) { status, percent in
            onProgress(InstallProgressUpdate(
                stage: .installing,
                stageProgress: min(1.0, Double(percent) / 100.0),
                statusMessage: "\(status) (\(percent)%)"
            ))
        }

        await lockdown.stopSession()
        onProgress(InstallProgressUpdate(stage: .installing, stageProgress: 1.0, statusMessage: "Installation complete"))
    }

    /// Automatic fallback from USB-C/OTG Ethernet to Wi-Fi Bonjour when both routes exist.
    private func resolveReachableDevice(
        primary: DiscoveredDevice,
        fallbackWifi: DiscoveredDevice?
    ) async throws -> DiscoveredDevice {
        if primary.connectionKind == .usbEthernetOTG, let wifi = fallbackWifi {
            let probe = TcpDeviceTransport(host: primary.host, port: primary.port)
            do {
                try await probe.connect(timeout: 2.0)
                probe.close()
                logger(.transport, "Using primary USB-C/OTG link (\(primary.host):\(primary.port))", false)
                return primary
            } catch {
                probe.close()
                logger(.transport, "USB-C/OTG probe unavailable; falling back to Wi-Fi Bonjour (\(wifi.host):\(wifi.port))", false)
                return wifi
            }
        }
        return primary
    }

    private func openServiceTransport(
        host: String,
        descriptor: LockdownServiceDescriptor,
        pairingRecord: PairingRecord
    ) async throws -> DeviceTransport {
        let tcp = TcpDeviceTransport(host: host, port: descriptor.port)
        try await tcp.connect(timeout: 8.0)
        if descriptor.enableServiceSSL {
            let tls = try TlsDeviceTransport(underlying: tcp, pairingRecord: pairingRecord)
            try await tls.handshake(timeout: 8.0)
            return tls
        }
        return tcp
    }

    /// Generates an `itms-services://?action=download-manifest&url=...` OTA fallback URL
    /// for paid Ad-Hoc or Enterprise certificates hosted on an HTTPS endpoint.
    public static func buildOTAManifestURL(manifestHTTPSURL: URL) -> URL? {
        guard let encoded = manifestHTTPSURL.absoluteString.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) else {
            return nil
        }
        return URL(string: "itms-services://?action=download-manifest&url=\(encoded)")
    }

    public static func generateOTAManifestPlist(
        ipaHTTPSURL: URL,
        bundleIdentifier: String,
        bundleVersion: String,
        title: String
    ) throws -> Data {
        let manifest: [String: Any] = [
            "items": [
                [
                    "assets": [
                        [
                            "kind": "software-package",
                            "url": ipaHTTPSURL.absoluteString
                        ]
                    ],
                    "metadata": [
                        "bundle-identifier": bundleIdentifier,
                        "bundle-version": bundleVersion,
                        "kind": "software",
                        "title": title
                    ]
                ]
            ]
        ]
        return try PlistCodec.encodeXML(manifest)
    }
}
