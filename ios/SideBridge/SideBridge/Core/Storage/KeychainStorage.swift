import Foundation
import Security

/// Thread-safe shared Keychain storage backed by SideBridge's Keychain Access Group.
/// Persists Apple ID session tokens, Anisette v3 identity, `.p12` signing identities,
/// and private keys for pairing records.
public final class KeychainStorage: @unchecked Sendable {
    public static let shared = KeychainStorage()

    private let service = "com.sidebridge.ios.keychain"
    private let accessGroup: String?
    private let lock = NSLock()

    public enum Key: String {
        case appleSession = "sidebridge.apple.session"
        case anisetteIdentity = "sidebridge.anisette.v3.identity"
        case activeP12Data = "sidebridge.signing.active.p12.data"
        case activeP12Passphrase = "sidebridge.signing.active.p12.passphrase"
        case activeCertRecord = "sidebridge.signing.active.cert.record"
        case customP12Data = "sidebridge.signing.custom.p12.data"
        case customP12Passphrase = "sidebridge.signing.custom.p12.passphrase"
        case customMobileProvision = "sidebridge.signing.custom.mobileprovision"
    }

    public init(accessGroup: String? = nil) {
        self.accessGroup = accessGroup
    }

    public func save(_ data: Data, for key: String) throws {
        lock.lock()
        defer { lock.unlock() }

        var query = baseQuery(for: key)
        SecItemDelete(query as CFDictionary)

        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.osStatus(status)
        }
    }

    public func loadData(for key: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }

        var query = baseQuery(for: key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw KeychainError.osStatus(status)
        }
        return result as? Data
    }

    public func delete(for key: String) {
        lock.lock()
        defer { lock.unlock() }
        let query = baseQuery(for: key)
        SecItemDelete(query as CFDictionary)
    }

    public func saveCodable<T: Encodable>(_ value: T, for key: Key) throws {
        let data = try JSONEncoder().encode(value)
        try save(data, for: key.rawValue)
    }

    public func loadCodable<T: Decodable>(_ type: T.Type, for key: Key) throws -> T? {
        guard let data = try loadData(for: key.rawValue) else { return nil }
        return try JSONDecoder().decode(type, from: data)
    }

    public func saveString(_ value: String, for key: Key) throws {
        try save(Data(value.utf8), for: key.rawValue)
    }

    public func loadString(for key: Key) throws -> String? {
        guard let data = try loadData(for: key.rawValue) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func baseQuery(for key: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }
}

public enum KeychainError: LocalizedError {
    case osStatus(OSStatus)

    public var errorDescription: String? {
        switch self {
        case .osStatus(let code):
            return "Keychain operation failed with OSStatus \(code)."
        }
    }
}
