import Foundation

// MARK: - Pairing & Device Models

public struct PairingRecord: Codable, Identifiable, Hashable, Sendable {
    public var id: String { udid }
    public let udid: String
    public var deviceName: String
    public let hostId: String
    public let systemBuid: String
    public let hostCertificatePem: String
    public let hostPrivateKeyPem: String
    public let rootCertificatePem: String
    public let deviceCertificatePem: String
    public var wifiAddress: String?
    public var isThisDevice: Bool
    public let importedAt: Date

    public init(
        udid: String,
        deviceName: String,
        hostId: String,
        systemBuid: String,
        hostCertificatePem: String,
        hostPrivateKeyPem: String,
        rootCertificatePem: String,
        deviceCertificatePem: String,
        wifiAddress: String? = nil,
        isThisDevice: Bool = false,
        importedAt: Date = Date()
    ) {
        self.udid = udid
        self.deviceName = deviceName
        self.hostId = hostId
        self.systemBuid = systemBuid
        self.hostCertificatePem = hostCertificatePem
        self.hostPrivateKeyPem = hostPrivateKeyPem
        self.rootCertificatePem = rootCertificatePem
        self.deviceCertificatePem = deviceCertificatePem
        self.wifiAddress = wifiAddress
        self.isThisDevice = isThisDevice
        self.importedAt = importedAt
    }
}

public enum DeviceConnectionKind: String, Codable, Hashable, Sendable {
    case loopbackVPN = "Loopback VPN"
    case wifiBonjour = "Wi-Fi Bonjour"
    case usbEthernetOTG = "USB-C / OTG"
    case rawUsbmux = "Raw USB (usbmux)"
}

public struct DiscoveredDevice: Identifiable, Hashable, Sendable {
    public let id: String
    public var udid: String?
    public var name: String
    public var host: String
    public var port: UInt16
    public var interfaceName: String?
    public var connectionKind: DeviceConnectionKind
    public var productVersion: String?
    public var hasPairingRecord: Bool
    public var lastSeen: Date

    public init(
        id: String,
        udid: String? = nil,
        name: String,
        host: String,
        port: UInt16 = 62078,
        interfaceName: String? = nil,
        connectionKind: DeviceConnectionKind,
        productVersion: String? = nil,
        hasPairingRecord: Bool = false,
        lastSeen: Date = Date()
    ) {
        self.id = id
        self.udid = udid
        self.name = name
        self.host = host
        self.port = port
        self.interfaceName = interfaceName
        self.connectionKind = connectionKind
        self.productVersion = productVersion
        self.hasPairingRecord = hasPairingRecord
        self.lastSeen = lastSeen
    }
}

// MARK: - Apple Account & Provisioning Models

public struct AnisetteIdentity: Codable, Sendable {
    public let machineId: String
    public let oneTimePassword: String
    public let localUserId: String
    public let routingInfo: String
    public let deviceId: String
    public let serialNumber: String
    public let clientInfo: String
    public let serverURL: String
    public let mintedAt: Date
}

public struct AppleAccountSession: Codable, Sendable {
    public let appleId: String
    public let dsid: String
    public let adsid: String
    public let xcodeAuthToken: String
    public let teamId: String
    public let teamName: String
    public let isFreePersonalTeam: Bool
    public let authenticatedAt: Date
}

public struct SigningIdentityRecord: Codable, Identifiable, Sendable {
    public let id: String
    public let displayName: String
    public let serialNumber: String
    public let sha1Thumbprint: String
    public let sha256Thumbprint: String
    public let expiresAt: Date
    public let isCustomP12: Bool
}

public struct AppIdRecord: Codable, Identifiable, Sendable {
    public let id: String
    public let appIdId: String
    public let name: String
    public let identifier: String
    public let expirationDate: Date?
}

// MARK: - IPA & Installation Queue Models

public struct LocalIPA: Identifiable, Codable, Hashable, Sendable {
    public let id: UUID
    public var displayName: String
    public var bundleIdentifier: String
    public var version: String
    public var fileName: String
    public var fileSizeBytes: Int64
    public var importedAt: Date
    public var isEncryptedFairPlay: Bool

    public init(
        id: UUID = UUID(),
        displayName: String,
        bundleIdentifier: String,
        version: String,
        fileName: String,
        fileSizeBytes: Int64,
        importedAt: Date = Date(),
        isEncryptedFairPlay: Bool = false
    ) {
        self.id = id
        self.displayName = displayName
        self.bundleIdentifier = bundleIdentifier
        self.version = version
        self.fileName = fileName
        self.fileSizeBytes = fileSizeBytes
        self.importedAt = importedAt
        self.isEncryptedFairPlay = isEncryptedFairPlay
    }
}

public enum InstallStage: Int, CaseIterable, Sendable {
    case provisioning = 0
    case signing = 1
    case afcUploading = 2
    case installing = 3

    public var title: String {
        switch self {
        case .provisioning: return "Provisioning"
        case .signing: return "Signing"
        case .afcUploading: return "AFC Uploading"
        case .installing: return "Installing"
        }
    }
}

public enum LogCategory: String, CaseIterable, Codable, Sendable {
    case lockdownTx = "LOCKDOWN_TX"
    case lockdownRx = "LOCKDOWN_RX"
    case afc = "AFC"
    case instproxy = "INSTPROXY"
    case sign = "SIGN"
    case provision = "PROVISION"
    case transport = "TRANSPORT"
}

public struct ProtocolLogEntry: Identifiable, Sendable {
    public let id: UUID
    public let timestamp: Date
    public let category: LogCategory
    public let message: String
    public let isError: Bool

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        category: LogCategory,
        message: String,
        isError: Bool = false
    ) {
        self.id = id
        self.timestamp = timestamp
        self.category = category
        self.message = message
        self.isError = isError
    }
}

public struct RepoAppItem: Identifiable, Codable, Hashable, Sendable {
    public let id: String
    public let name: String
    public let bundleId: String
    public let version: String
    public let developer: String
    public let sizeBytes: Int64
    public let downloadURL: URL
    public let sourceName: String
    public let summary: String
}
