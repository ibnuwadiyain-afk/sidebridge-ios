import Foundation

/// Anisette v3 client supporting identity provisioning and one-time header minting
/// with automatic fallback across configured Anisette v3 servers.
public final class AnisetteClient: @unchecked Sendable {
    public static let defaultServers: [String] = [
        "https://ani.sidestore.io",
        "https://anisette.sidebridge.local"
    ]

    private let session: URLSession
    private let keychain: KeychainStorage
    private let servers: [String]

    public init(
        servers: [String] = AnisetteClient.defaultServers,
        keychain: KeychainStorage = .shared,
        session: URLSession = .shared
    ) {
        self.servers = servers
        self.keychain = keychain
        self.session = session
    }

    /// Mints fresh one-time Anisette v3 headers (`X-Apple-I-MD`, `X-Apple-I-MD-M`, `X-Apple-I-MD-LU`, etc.)
    /// using cached ADI identity or provisioning a new one via the Anisette v3 protocol.
    public func mintHeaders() async throws -> [String: String] {
        var lastError: Error = AnisetteError.allServersUnavailable

        for baseURLString in servers {
            guard let baseURL = URL(string: baseURLString) else { continue }
            do {
                let identity = try await fetchOrProvisionIdentity(serverBaseURL: baseURL)
                try? keychain.saveCodable(identity, for: .anisetteIdentity)
                return Self.buildAppleHeaders(from: identity)
            } catch {
                lastError = error
                continue
            }
        }
        throw lastError
    }

    private func fetchOrProvisionIdentity(serverBaseURL: URL) async throws -> AnisetteIdentity {
        let endpoint = serverBaseURL.appendingPathComponent("v3/get_headers")
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = 12.0
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let stored = try? keychain.loadCodable(AnisetteIdentity.self, for: .anisetteIdentity)
        let deviceId = stored?.deviceId ?? UUID().uuidString.uppercased()
        let localUserId = stored?.localUserId ?? Self.randomHex(bytes: 32)

        let body: [String: String] = [
            "identifier": deviceId,
            "adi_pb": localUserId
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw AnisetteError.serverReturnedStatus((response as? HTTPURLResponse)?.statusCode ?? -1)
        }

        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let md = json["X-Apple-I-MD"] as? String,
              let mdm = json["X-Apple-I-MD-M"] as? String else {
            throw AnisetteError.invalidPayload
        }

        return AnisetteIdentity(
            machineId: mdm,
            oneTimePassword: md,
            localUserId: (json["X-Apple-I-MD-LU"] as? String) ?? localUserId,
            routingInfo: (json["X-Apple-I-MD-RINFO"] as? String) ?? "17106176",
            deviceId: (json["X-Mme-Device-Id"] as? String) ?? deviceId,
            serialNumber: (json["X-Apple-I-SRL-NO"] as? String) ?? "0",
            clientInfo: (json["X-MMe-Client-Info"] as? String) ?? "<iMac20,2> <Mac OS X;13.5.1;22G90> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
            serverURL: serverBaseURL.absoluteString,
            mintedAt: Date()
        )
    }

    public static func buildAppleHeaders(from identity: AnisetteIdentity) -> [String: String] {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return [
            "X-Apple-I-MD": identity.oneTimePassword,
            "X-Apple-I-MD-M": identity.machineId,
            "X-Apple-I-MD-LU": identity.localUserId,
            "X-Apple-I-MD-RINFO": identity.routingInfo,
            "X-Mme-Device-Id": identity.deviceId,
            "X-Apple-I-SRL-NO": identity.serialNumber,
            "X-MMe-Client-Info": identity.clientInfo,
            "X-Apple-I-Client-Time": formatter.string(from: Date()),
            "X-Apple-I-TimeZone": TimeZone.current.abbreviation() ?? "UTC",
            "X-Apple-Locale": Locale.current.identifier
        ]
    }

    private static func randomHex(bytes: Int) -> String {
        var buffer = [UInt8](repeating: 0, count: bytes)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes, &buffer)
        return buffer.map { String(format: "%02x", $0) }.joined()
    }
}

public enum AnisetteError: LocalizedError {
    case allServersUnavailable
    case serverReturnedStatus(Int)
    case invalidPayload

    public var errorDescription: String? {
        switch self {
        case .allServersUnavailable: return "All Anisette v3 servers failed to mint headers."
        case .serverReturnedStatus(let code): return "Anisette v3 server returned HTTP \(code)."
        case .invalidPayload: return "Anisette v3 server returned an invalid header payload."
        }
    }
}
