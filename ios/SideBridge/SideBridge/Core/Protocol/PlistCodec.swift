import Foundation

/// Wrapper around `PropertyListSerialization` supporting both XML and `bplist00` binary plists,
/// plus 4-byte Big-Endian framing used by `lockdownd` and `installation_proxy`.
public enum PlistCodec {
    public static func encodeXML(_ object: Any) throws -> Data {
        try PropertyListSerialization.data(fromPropertyList: object, format: .xml, options: 0)
    }

    public static func encodeBinary(_ object: Any) throws -> Data {
        try PropertyListSerialization.data(fromPropertyList: object, format: .binary, options: 0)
    }

    public static func decodeDictionary(_ data: Data) throws -> [String: Any] {
        var format: PropertyListSerialization.PropertyListFormat = .xml
        let obj = try PropertyListSerialization.propertyList(from: data, options: [], format: &format)
        guard let dict = obj as? [String: Any] else {
            throw PlistCodecError.expectedDictionary
        }
        return dict
    }

    public static func isBinaryPlist(_ data: Data) -> Bool {
        data.count >= 8 && data.prefix(8) == Data("bplist00".utf8)
    }

    /// Encodes a dictionary as XML plist prefixed with a 4-byte Big-Endian length header.
    public static func encodeFramedXML(_ dict: [String: Any]) throws -> Data {
        let payload = try encodeXML(dict)
        var lengthBE = UInt32(payload.count).bigEndian
        var framed = Data(bytes: &lengthBE, count: 4)
        framed.append(payload)
        return framed
    }

    /// Reads a 4-byte Big-Endian length-prefixed plist frame from a `DeviceTransport`.
    public static func readFramedDictionary(
        from transport: DeviceTransport,
        timeout: TimeInterval = 15.0
    ) async throws -> [String: Any] {
        let header = try await transport.receiveExact(4, timeout: timeout)
        let length = header.withUnsafeBytes { raw -> UInt32 in
            raw.loadUnaligned(as: UInt32.self).bigEndian
        }
        guard length > 0, length <= 32 * 1024 * 1024 else {
            throw PlistCodecError.invalidFrameLength(length)
        }
        let body = try await transport.receiveExact(Int(length), timeout: timeout)
        return try decodeDictionary(body)
    }

    /// Redacts sensitive keys (keys, certs, tokens, auth cookies) before emitting protocol logs.
    public static func redactedSummary(_ dict: [String: Any]) -> String {
        let sensitiveKeys: Set<String> = [
            "HostCertificate", "HostPrivateKey", "RootCertificate", "DeviceCertificate",
            "DevicePublicKey", "EscrowBag", "SessionID", "ApplicationSINF", "Password"
        ]
        let pairs = dict.keys.sorted().map { key -> String in
            if sensitiveKeys.contains(key) {
                return "\(key)=<REDACTED>"
            }
            let val = dict[key]
            if let str = val as? String {
                return "\(key)=\"\(str)\""
            } else if let num = val as? NSNumber {
                return "\(key)=\(num)"
            } else if let data = val as? Data {
                return "\(key)=<\(data.count)B>"
            } else if let nested = val as? [String: Any] {
                return "\(key)={\(nested.keys.sorted().joined(separator: ","))}"
            }
            return "\(key)=\(String(describing: val ?? "nil"))"
        }
        return "{ " + pairs.joined(separator: ", ") + " }"
    }
}

public enum PlistCodecError: LocalizedError {
    case expectedDictionary
    case invalidFrameLength(UInt32)

    public var errorDescription: String? {
        switch self {
        case .expectedDictionary: return "Decoded property list root was not a dictionary."
        case .invalidFrameLength(let len): return "Invalid framed plist length: \(len) bytes."
        }
    }
}
