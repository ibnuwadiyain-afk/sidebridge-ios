import Foundation

public struct LockdownServiceDescriptor: Sendable {
    public let serviceName: String
    public let port: UInt16
    public let enableServiceSSL: Bool
}

public struct LockdownDeviceInfo: Sendable {
    public let udid: String
    public let deviceName: String
    public let productVersion: String
    public let systemBuid: String?
}

/// Wire-compatible Apple `lockdownd` client using 4-byte Big-Endian length-prefixed XML plists.
/// Supports `QueryType`, `GetValue`, `StartSession` (upgrading to `TlsDeviceTransport`),
/// and `StartService` for `com.apple.afc` and `com.apple.mobile.installation_proxy`.
public final class LockdownClient: @unchecked Sendable {
    public static let label = "SideBridge"
    public static let protocolVersion = "2"

    private var transport: DeviceTransport
    private var sessionId: String?
    private let logger: (@Sendable (LogCategory, String, Bool) -> Void)?

    public init(
        transport: DeviceTransport,
        logger: (@Sendable (LogCategory, String, Bool) -> Void)? = nil
    ) {
        self.transport = transport
        self.logger = logger
    }

    public func queryType() async throws -> String {
        let response = try await exchange([
            "Request": "QueryType",
            "Label": Self.label
        ])
        guard let type = response["Type"] as? String else {
            throw LockdownError.unexpectedResponse("Missing Type in QueryType response")
        }
        return type
    }

    public func getValue(domain: String? = nil, key: String? = nil) async throws -> Any? {
        var req: [String: Any] = [
            "Request": "GetValue",
            "Label": Self.label
        ]
        if let domain { req["Domain"] = domain }
        if let key { req["Key"] = key }

        let response = try await exchange(req)
        return response["Value"]
    }

    public func fetchDeviceInfo() async throws -> LockdownDeviceInfo {
        let udid = (try await getValue(key: "UniqueDeviceID") as? String) ?? "unknown"
        let name = (try await getValue(key: "DeviceName") as? String) ?? "iOS Device"
        let version = (try await getValue(key: "ProductVersion") as? String) ?? "16.0"
        let buid = try? await getValue(key: "SystemBUID") as? String
        return LockdownDeviceInfo(udid: udid, deviceName: name, productVersion: version, systemBuid: buid)
    }

    /// Starts an authenticated lockdown session and upgrades the underlying transport
    /// to an in-memory OpenSSL TLS 1.2 session when `EnableSessionSSL` is true.
    public func startSession(with pairingRecord: PairingRecord) async throws -> String {
        let response = try await exchange([
            "Request": "StartSession",
            "Label": Self.label,
            "ProtocolVersion": Self.protocolVersion,
            "HostID": pairingRecord.hostId,
            "SystemBUID": pairingRecord.systemBuid
        ])

        guard let sid = response["SessionID"] as? String else {
            throw LockdownError.unexpectedResponse("StartSession did not return SessionID")
        }
        self.sessionId = sid

        let enableSSL = (response["EnableSessionSSL"] as? Bool) ?? false
        if enableSSL {
            logger?(.lockdownTx, "Upgrading lockdownd transport to OpenSSL BIO TLS 1.2 (HostID=\(pairingRecord.hostId.prefix(8))...)", false)
            let tlsTransport = try TlsDeviceTransport(underlying: transport, pairingRecord: pairingRecord)
            try await tlsTransport.handshake(timeout: 10.0)
            self.transport = tlsTransport
            logger?(.lockdownRx, "TLS 1.2 mutual auth established with lockdownd", false)
        }
        return sid
    }

    public func stopSession() async {
        guard let sid = sessionId else { return }
        _ = try? await exchange([
            "Request": "StopSession",
            "Label": Self.label,
            "SessionID": sid
        ])
        sessionId = nil
    }

    /// Requests lockdownd to spawn a device service (e.g. `com.apple.afc` or `com.apple.mobile.installation_proxy`).
    public func startService(_ serviceName: String) async throws -> LockdownServiceDescriptor {
        let response = try await exchange([
            "Request": "StartService",
            "Label": Self.label,
            "Service": serviceName
        ])

        guard let portNum = response["Port"] as? NSNumber else {
            throw LockdownError.serviceUnavailable(serviceName, detail: "Missing Port in StartService response")
        }
        let ssl = (response["EnableServiceSSL"] as? Bool) ?? false
        return LockdownServiceDescriptor(
            serviceName: serviceName,
            port: portNum.uint16Value,
            enableServiceSSL: ssl
        )
    }

    public func close() {
        transport.close()
    }

    // MARK: - Wire Exchange

    @discardableResult
    private func exchange(_ request: [String: Any]) async throws -> [String: Any] {
        logger?(.lockdownTx, PlistCodec.redactedSummary(request), false)
        let framed = try PlistCodec.encodeFramedXML(request)
        try await transport.send(framed)

        let response = try await PlistCodec.readFramedDictionary(from: transport, timeout: 15.0)
        logger?(.lockdownRx, PlistCodec.redactedSummary(response), response["Error"] != nil)

        if let errorCode = response["Error"] as? String {
            throw LockdownError.deviceError(errorCode)
        }
        return response
    }
}

public enum LockdownError: LocalizedError {
    case deviceError(String)
    case unexpectedResponse(String)
    case serviceUnavailable(String, detail: String)

    public var errorDescription: String? {
        switch self {
        case .deviceError(let code):
            switch code {
            case "PasswordProtected":
                return "Target iOS device is locked. Unlock the screen and tap Trust if prompted."
            case "InvalidHostID", "PairDialogResponsePending":
                return "Pairing record rejected (\(code)). Re-import a fresh .mobiledevicepairing file."
            case "InvalidService":
                return "Requested lockdown service is unavailable. Ensure iOS 16+ Developer Mode is enabled."
            default:
                return "Lockdown error: \(code)"
            }
        case .unexpectedResponse(let msg):
            return msg
        case .serviceUnavailable(let svc, let detail):
            return "Unable to start \(svc): \(detail)"
        }
    }
}
