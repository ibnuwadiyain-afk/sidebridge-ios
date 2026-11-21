import Foundation

/// Persists `PairingRecord` credentials in the shared App Group / Keychain
/// and parses `.mobiledevicepairing` / `.plist` files exported by JitterbugPair,
/// `idevicepair`, or Android SideBridge.
public final class PairingStorage: @unchecked Sendable {
    public static let shared = PairingStorage()
    public static let appGroupIdentifier = "group.com.sidebridge.shared"

    private let keychain: KeychainStorage
    private let indexKey = "sidebridge.pairing.udid.index"
    private let lock = NSLock()

    public init(keychain: KeychainStorage = .shared) {
        self.keychain = keychain
    }

    public func allRecords() -> [PairingRecord] {
        lock.lock()
        defer { lock.unlock() }
        guard let udids = loadUdidIndex() else { return [] }
        return udids.compactMap { loadRecordUnlocked(udid: $0) }
    }

    public func record(forUDID udid: String) -> PairingRecord? {
        lock.lock()
        defer { lock.unlock() }
        return loadRecordUnlocked(udid: udid)
    }

    public func thisDeviceRecord() -> PairingRecord? {
        allRecords().first(where: { $0.isThisDevice })
    }

    public func save(_ record: PairingRecord) throws {
        lock.lock()
        defer { lock.unlock() }

        var recordToSave = record
        // Ensure only one record is marked as "This Device"
        if recordToSave.isThisDevice {
            let existing = loadUdidIndex() ?? []
            for udid in existing where udid != recordToSave.udid {
                if var other = loadRecordUnlocked(udid: udid), other.isThisDevice {
                    other.isThisDevice = false
                    try persistRecordUnlocked(other)
                }
            }
        }

        try persistRecordUnlocked(recordToSave)
        var udids = Set(loadUdidIndex() ?? [])
        udids.insert(recordToSave.udid)
        try saveUdidIndex(Array(udids).sorted())
    }

    public func delete(udid: String) throws {
        lock.lock()
        defer { lock.unlock() }
        keychain.delete(for: recordKey(for: udid))
        var udids = Set(loadUdidIndex() ?? [])
        udids.remove(udid)
        try saveUdidIndex(Array(udids).sorted())
    }

    /// Parses a `.mobiledevicepairing` or `.plist` file (XML or binary plist) from
    /// JitterbugPair, libimobiledevice (`idevicepair`), or Android SideBridge export.
    public func importPairingFile(
        from url: URL,
        markAsThisDevice: Bool,
        fallbackDeviceName: String? = nil
    ) throws -> PairingRecord {
        let accessed = url.startAccessingSecurityScopedResource()
        defer {
            if accessed { url.stopAccessingSecurityScopedResource() }
        }
        let data = try Data(contentsOf: url)
        let record = try parsePairingPlist(
            data: data,
            fileName: url.deletingPathExtension().lastPathComponent,
            markAsThisDevice: markAsThisDevice,
            fallbackDeviceName: fallbackDeviceName
        )
        try save(record)
        return record
    }

    public func parsePairingPlist(
        data: Data,
        fileName: String,
        markAsThisDevice: Bool,
        fallbackDeviceName: String? = nil
    ) throws -> PairingRecord {
        let plist = try PlistCodec.decodeDictionary(data)

        guard
            let hostId = plist["HostID"] as? String,
            let systemBuid = plist["SystemBUID"] as? String
        else {
            throw PairingError.missingRequiredField("HostID or SystemBUID")
        }

        guard let hostCertPem = extractPemString(plist["HostCertificate"], label: "CERTIFICATE") else {
            throw PairingError.missingRequiredField("HostCertificate")
        }
        guard let hostKeyPem = extractPemString(plist["HostPrivateKey"], label: "PRIVATE KEY") else {
            throw PairingError.missingRequiredField("HostPrivateKey")
        }
        guard let rootCertPem = extractPemString(plist["RootCertificate"], label: "CERTIFICATE") else {
            throw PairingError.missingRequiredField("RootCertificate")
        }
        let deviceCertPem = extractPemString(plist["DeviceCertificate"], label: "CERTIFICATE") ?? ""

        let udid = (plist["UDID"] as? String)
            ?? (plist["UniqueDeviceID"] as? String)
            ?? (fileName.count >= 24 ? fileName : UUID().uuidString)

        let deviceName = (plist["DeviceName"] as? String)
            ?? fallbackDeviceName
            ?? (markAsThisDevice ? "This iOS Device" : "Paired Device (\(udid.prefix(8)))")

        let wifiAddress = plist["WiFiMACAddress"] as? String ?? plist["WiFiAddress"] as? String

        return PairingRecord(
            udid: udid,
            deviceName: deviceName,
            hostId: hostId,
            systemBuid: systemBuid,
            hostCertificatePem: hostCertPem,
            hostPrivateKeyPem: hostKeyPem,
            rootCertificatePem: rootCertPem,
            deviceCertificatePem: deviceCertPem,
            wifiAddress: wifiAddress,
            isThisDevice: markAsThisDevice
        )
    }

    /// Exports a PairingRecord back into Apple `.mobiledevicepairing` XML plist format.
    public func exportPairingPlist(_ record: PairingRecord) throws -> Data {
        var dict: [String: Any] = [
            "UDID": record.udid,
            "DeviceName": record.deviceName,
            "HostID": record.hostId,
            "SystemBUID": record.systemBuid,
            "HostCertificate": Data(record.hostCertificatePem.utf8),
            "HostPrivateKey": Data(record.hostPrivateKeyPem.utf8),
            "RootCertificate": Data(record.rootCertificatePem.utf8),
            "DeviceCertificate": Data(record.deviceCertificatePem.utf8)
        ]
        if let wifi = record.wifiAddress {
            dict["WiFiAddress"] = wifi
        }
        return try PlistCodec.encodeXML(dict)
    }

    private func extractPemString(_ value: Any?, label: String) -> String? {
        if let str = value as? String, !str.isEmpty {
            return str
        }
        if let data = value as? Data, !data.isEmpty {
            if let utf8 = String(data: data, encoding: .utf8), utf8.contains("-----BEGIN") {
                return utf8
            }
            // Convert raw DER bytes to PEM
            let base64 = data.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
            return "-----BEGIN \(label)-----\n\(base64)\n-----END \(label)-----\n"
        }
        return nil
    }

    private func recordKey(for udid: String) -> String {
        "sidebridge.pairing.record.\(udid)"
    }

    private func persistRecordUnlocked(_ record: PairingRecord) throws {
        let data = try JSONEncoder().encode(record)
        try keychain.save(data, for: recordKey(for: record.udid))
    }

    private func loadRecordUnlocked(udid: String) -> PairingRecord? {
        guard let data = try? keychain.loadData(for: recordKey(for: udid)) else { return nil }
        return try? JSONDecoder().decode(PairingRecord.self, from: data)
    }

    private func loadUdidIndex() -> [String]? {
        guard let data = try? keychain.loadData(for: indexKey) else { return nil }
        return try? JSONDecoder().decode([String].self, from: data)
    }

    private func saveUdidIndex(_ udids: [String]) throws {
        let data = try JSONEncoder().encode(udids)
        try keychain.save(data, for: indexKey)
    }
}

public enum PairingError: LocalizedError {
    case missingRequiredField(String)
    case invalidPlistFormat

    public var errorDescription: String? {
        switch self {
        case .missingRequiredField(let field):
            return "Pairing file is missing required field: \(field)."
        case .invalidPlistFormat:
            return "Unable to decode .mobiledevicepairing / .plist file."
        }
    }
}
