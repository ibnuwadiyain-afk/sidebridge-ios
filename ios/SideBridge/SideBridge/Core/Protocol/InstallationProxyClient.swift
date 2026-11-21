import Foundation

/// Client for `com.apple.mobile.installation_proxy`.
/// Sends `Command = "Install"` for `PublicStaging/<bundleId>.ipa` and streams
/// `Status` and `PercentComplete` frames until `Complete`, translating iOS error codes
/// into actionable guidance for Developer Mode, Untrusted Developer Profile, and Locked Device.
public final class InstallationProxyClient: @unchecked Sendable {
    private let transport: DeviceTransport
    private let logger: (@Sendable (LogCategory, String, Bool) -> Void)?

    public init(
        transport: DeviceTransport,
        logger: (@Sendable (LogCategory, String, Bool) -> Void)? = nil
    ) {
        self.transport = transport
        self.logger = logger
    }

    public func install(
        packagePath: String,
        bundleIdentifier: String,
        applicationSinf: Data? = nil,
        iTunesMetadata: Data? = nil,
        onStatus: @Sendable (String, Int) -> Void
    ) async throws {
        var clientOptions: [String: Any] = [
            "CFBundleIdentifier": bundleIdentifier
        ]
        if let sinf = applicationSinf {
            clientOptions["ApplicationSINF"] = sinf
        }
        if let meta = iTunesMetadata {
            clientOptions["iTunesMetadata"] = meta
        }

        let request: [String: Any] = [
            "Command": "Install",
            "PackagePath": packagePath,
            "ClientOptions": clientOptions
        ]

        logger?(.instproxy, "TX Install PackagePath=\(packagePath) CFBundleIdentifier=\(bundleIdentifier)", false)
        let framed = try PlistCodec.encodeFramedXML(request)
        try await transport.send(framed)

        while true {
            try Task.checkCancellation()
            let response = try await PlistCodec.readFramedDictionary(from: transport, timeout: 120.0)

            if let errorName = response["Error"] as? String {
                let errorDesc = (response["ErrorDescription"] as? String) ?? ""
                let friendly = Self.mapActionableError(code: errorName, description: errorDesc)
                logger?(.instproxy, "RX Error=\(errorName) (\(errorDesc))", true)
                throw InstallationProxyError.installFailed(code: errorName, message: friendly)
            }

            let status = (response["Status"] as? String) ?? "Working"
            let percent = (response["PercentComplete"] as? NSNumber)?.intValue ?? 0
            logger?(.instproxy, "RX Status=\(status) PercentComplete=\(percent)%", false)
            onStatus(status, percent)

            if status == "Complete" {
                return
            }
        }
    }

    public func close() {
        transport.close()
    }

    /// Maps Apple MobileInstallation error strings into clear, actionable instructions.
    public static func mapActionableError(code: String, description: String) -> String {
        let combined = "\(code) \(description)".lowercased()

        if combined.contains("developer mode") || combined.contains("developermode") {
            return "iOS 16+ Developer Mode is disabled. Open Settings -> Privacy & Security -> Developer Mode, enable it, restart the device, and retry."
        }
        if combined.contains("untrusted") || combined.contains("profile") && combined.contains("verify") {
            return "Developer certificate is not yet trusted. Open Settings -> General -> VPN & Device Management and tap Trust on your Apple ID profile."
        }
        if combined.contains("device is locked") || combined.contains("passcode") || combined.contains("passwordprotected") {
            return "Target iOS device is locked. Unlock the device and keep the screen awake during installation."
        }
        if combined.contains("applicationverificationfailed") || combined.contains("0xe8008015") {
            return "Code signature verification failed (\(code)). Confirm your provisioning profile matches the active certificate thumbprint and WWDR chain."
        }
        if combined.contains("0xe8008018") || combined.contains("maximum number of installed") {
            return "Free Apple ID 3-app active limit reached. Remove one sideloaded app on the target device and retry."
        }
        if description.isEmpty {
            return "InstallationProxy failed with \(code)."
        }
        return "\(code): \(description)"
    }
}

public enum InstallationProxyError: LocalizedError {
    case installFailed(code: String, message: String)

    public var errorDescription: String? {
        switch self {
        case .installFailed(_, let message): return message
        }
    }
}
