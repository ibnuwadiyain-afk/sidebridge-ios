import Foundation
import CryptoKit

public struct DeveloperCertificateInfo: Sendable {
    public let certificateId: String
    public let serialNumber: String
    public let name: String
    public let certContentDER: Data
    public let sha1Thumbprint: String
    public let sha256Thumbprint: String
}

public struct ProvisioningBundle: Sendable {
    public let p12Data: Data
    public let p12Passphrase: String
    public let mobileProvisionData: Data
    public let effectiveBundleIdentifier: String
    public let certificateThumbprintSHA1: String
    public let certificateThumbprintSHA256: String
}

/// Apple Developer Portal (`developerservices2.apple.com/services/QH65B2/...`) Personal Team provisioner.
/// CRITICAL INVARIANTS:
/// 1. Always calls `listAllDevelopmentCerts` before signing and auto-revokes / re-creates via CSR if
///    the local certificate was revoked externally (e.g., by Sideloadly or AltStore).
/// 2. Always verifies that the downloaded `.mobileprovision` `DeveloperCertificates` array contains
///    the exact active `.p12` leaf certificate SHA-1 and SHA-256 thumbprint before returning.
public final class AppleDeveloperProvisioner: @unchecked Sendable {
    public static let portalBase = "https://developerservices2.apple.com/services/QH65B2"
    private static let clientId = "XABBG36SBA"

    private let anisette: AnisetteClient
    private let keychain: KeychainStorage
    private let session: URLSession
    private let logger: (@Sendable (LogCategory, String, Bool) -> Void)?

    public init(
        anisette: AnisetteClient = AnisetteClient(),
        keychain: KeychainStorage = .shared,
        session: URLSession = .shared,
        logger: (@Sendable (LogCategory, String, Bool) -> Void)? = nil
    ) {
        self.anisette = anisette
        self.keychain = keychain
        self.session = session
        self.logger = logger
    }

    // MARK: - High-Level Provisioning Pipeline

    public func prepareProvisioning(
        session: AppleAccountSession,
        deviceUDID: String,
        deviceName: String,
        originalBundleId: String
    ) async throws -> ProvisioningBundle {
        logger?(.provision, "Ensuring device \(deviceUDID.prefix(8))... is registered on team \(session.teamId)", false)
        try await ensureDeviceRegistered(session: session, udid: deviceUDID, name: deviceName)

        // CRITICAL: Always verify active certificates on Apple Portal before signing
        logger?(.provision, "Verifying active development certificates via listAllDevelopmentCerts", false)
        let activeCert = try await ensureActiveSigningIdentity(session: session)

        // Ensure App ID exists (suffixed with teamId for Free Personal Teams to avoid global bundle ID collisions)
        let targetBundleId = session.isFreePersonalTeam
            ? "\(originalBundleId).\(session.teamId)"
            : originalBundleId
        let appId = try await ensureAppId(session: session, bundleId: targetBundleId, displayName: "SideBridge \(originalBundleId)")

        // Download team provisioning profile
        logger?(.provision, "Downloading team provisioning profile for \(targetBundleId)", false)
        let profileData = try await downloadTeamProvisioningProfile(session: session, appIdId: appId.appIdId)

        // CRITICAL: Verify downloaded .mobileprovision DeveloperCertificates contains active .p12 leaf thumbprint
        try verifyProfileContainsCertificate(
            profileData: profileData,
            expectedSHA1: activeCert.sha1Thumbprint,
            expectedSHA256: activeCert.sha256Thumbprint
        )
        logger?(.provision, "Verified .mobileprovision DeveloperCertificates matches leaf SHA-1 \(activeCert.sha1Thumbprint.prefix(12))...", false)

        return ProvisioningBundle(
            p12Data: activeCert.p12Data,
            p12Passphrase: activeCert.passphrase,
            mobileProvisionData: profileData,
            effectiveBundleIdentifier: targetBundleId,
            certificateThumbprintSHA1: activeCert.sha1Thumbprint,
            certificateThumbprintSHA256: activeCert.sha256Thumbprint
        )
    }

    // MARK: - QH65B2 Endpoints

    public func listTeams(adsid: String, token: String) async throws -> [[String: Any]] {
        let resp = try await sendPortalRequest(path: "listTeams.action", adsid: adsid, token: token, params: [:])
        return (resp["teams"] as? [[String: Any]]) ?? []
    }

    public func listDevices(session: AppleAccountSession) async throws -> [[String: Any]] {
        let resp = try await sendPortalRequest(
            path: "ios/listDevices.action",
            adsid: session.adsid,
            token: session.xcodeAuthToken,
            params: ["teamId": session.teamId]
        )
        return (resp["devices"] as? [[String: Any]]) ?? []
    }

    public func addDevice(session: AppleAccountSession, udid: String, name: String) async throws {
        _ = try await sendPortalRequest(
            path: "ios/addDevice.action",
            adsid: session.adsid,
            token: session.xcodeAuthToken,
            params: [
                "teamId": session.teamId,
                "deviceNumber": udid,
                "name": name
            ]
        )
    }

    public func listAllDevelopmentCerts(session: AppleAccountSession) async throws -> [DeveloperCertificateInfo] {
        let resp = try await sendPortalRequest(
            path: "ios/listAllDevelopmentCerts.action",
            adsid: session.adsid,
            token: session.xcodeAuthToken,
            params: ["teamId": session.teamId]
        )
        let rawCerts = (resp["certificates"] as? [[String: Any]]) ?? []
        return rawCerts.compactMap { entry in
            guard
                let certId = entry["certificateId"] as? String,
                let serial = entry["serialNumber"] as? String,
                let der = entry["certContent"] as? Data
            else { return nil }
            let name = (entry["name"] as? String) ?? "iOS Development"
            return DeveloperCertificateInfo(
                certificateId: certId,
                serialNumber: serial,
                name: name,
                certContentDER: der,
                sha1Thumbprint: Self.sha1Hex(der),
                sha256Thumbprint: Self.sha256Hex(der)
            )
        }
    }

    public func submitDevelopmentCSR(session: AppleAccountSession, csrPem: String) async throws -> DeveloperCertificateInfo {
        let resp = try await sendPortalRequest(
            path: "ios/submitDevelopmentCSR.action",
            adsid: session.adsid,
            token: session.xcodeAuthToken,
            params: [
                "teamId": session.teamId,
                "csrContent": csrPem
            ]
        )
        guard
            let reqDict = resp["certRequest"] as? [String: Any],
            let certId = reqDict["certRequestId"] as? String,
            let der = reqDict["certContent"] as? Data
        else {
            // Some Apple responses require re-fetching listAllDevelopmentCerts after submitDevelopmentCSR
            let updated = try await listAllDevelopmentCerts(session: session)
            guard let newest = updated.last else {
                throw ProvisionerError.csrSubmissionFailed("Apple did not return issued certificate")
            }
            return newest
        }
        return DeveloperCertificateInfo(
            certificateId: certId,
            serialNumber: (reqDict["serialNumber"] as? String) ?? "",
            name: (reqDict["machineName"] as? String) ?? "SideBridge",
            certContentDER: der,
            sha1Thumbprint: Self.sha1Hex(der),
            sha256Thumbprint: Self.sha256Hex(der)
        )
    }

    public func revokeDevelopmentCert(session: AppleAccountSession, serialNumber: String) async throws {
        logger?(.provision, "Revoking stale/conflicting development certificate serial=\(serialNumber)", false)
        _ = try await sendPortalRequest(
            path: "ios/revokeDevelopmentCert.action",
            adsid: session.adsid,
            token: session.xcodeAuthToken,
            params: [
                "teamId": session.teamId,
                "serialNumber": serialNumber
            ]
        )
    }

    public func listAppIds(session: AppleAccountSession) async throws -> [AppIdRecord] {
        let resp = try await sendPortalRequest(
            path: "ios/listAppIds.action",
            adsid: session.adsid,
            token: session.xcodeAuthToken,
            params: ["teamId": session.teamId]
        )
        let items = (resp["appIds"] as? [[String: Any]]) ?? []
        return items.compactMap { item in
            guard
                let appIdId = item["appIdId"] as? String,
                let identifier = item["identifier"] as? String
            else { return nil }
            return AppIdRecord(
                id: appIdId,
                appIdId: appIdId,
                name: (item["name"] as? String) ?? identifier,
                identifier: identifier,
                expirationDate: item["expirationDate"] as? Date
            )
        }
    }

    public func addAppId(session: AppleAccountSession, name: String, identifier: String) async throws -> AppIdRecord {
        let resp = try await sendPortalRequest(
            path: "ios/addAppId.action",
            adsid: session.adsid,
            token: session.xcodeAuthToken,
            params: [
                "teamId": session.teamId,
                "name": name,
                "identifier": identifier
            ]
        )
        guard
            let appIdDict = resp["appId"] as? [String: Any],
            let appIdId = appIdDict["appIdId"] as? String
        else {
            throw ProvisionerError.portalError("addAppId did not return appIdId")
        }
        return AppIdRecord(
            id: appIdId,
            appIdId: appIdId,
            name: name,
            identifier: identifier,
            expirationDate: appIdDict["expirationDate"] as? Date
        )
    }

    public func downloadTeamProvisioningProfile(session: AppleAccountSession, appIdId: String) async throws -> Data {
        let resp = try await sendPortalRequest(
            path: "ios/downloadTeamProvisioningProfile.action",
            adsid: session.adsid,
            token: session.xcodeAuthToken,
            params: [
                "teamId": session.teamId,
                "appIdId": appIdId
            ]
        )
        guard
            let profileDict = resp["provisioningProfile"] as? [String: Any],
            let encodedProfile = profileDict["encodedProfile"] as? Data
        else {
            throw ProvisionerError.portalError("Missing encodedProfile in downloadTeamProvisioningProfile response")
        }
        return encodedProfile
    }

    // MARK: - Certificate Synchronization & Thumbprint Verification

    private struct ActiveSigningIdentity {
        let p12Data: Data
        let passphrase: String
        let sha1Thumbprint: String
        let sha256Thumbprint: String
    }

    private func ensureActiveSigningIdentity(session: AppleAccountSession) async throws -> ActiveSigningIdentity {
        let remoteCerts = try await listAllDevelopmentCerts(session: session)
        let localRecord = try? keychain.loadCodable(SigningIdentityRecord.self, for: .activeCertRecord)
        let localP12 = try? keychain.loadData(for: KeychainStorage.Key.activeP12Data.rawValue)
        let localPass = (try? keychain.loadString(for: .activeP12Passphrase)) ?? ""

        // Verify our cached local certificate is STILL active on Apple's servers (not revoked by Sideloadly/AltStore)
        if let localRecord, let localP12,
           remoteCerts.contains(where: { $0.sha256Thumbprint == localRecord.sha256Thumbprint }) {
            logger?(.provision, "Active local cert matches portal (\(localRecord.serialNumber))", false)
            return ActiveSigningIdentity(
                p12Data: localP12,
                passphrase: localPass,
                sha1Thumbprint: localRecord.sha1Thumbprint,
                sha256Thumbprint: localRecord.sha256Thumbprint
            )
        }

        // Local cert missing or revoked externally -> revoke any conflicting personal team certs, generate RSA-2048 CSR, and submit
        if session.isFreePersonalTeam {
            for stale in remoteCerts {
                try await revokeDevelopmentCert(session: session, serialNumber: stale.serialNumber)
            }
        }

        logger?(.provision, "Generating RSA-2048 keypair and CSR for SideBridge signing identity", false)
        let (privateKeyPem, csrPem) = try Self.generateRSA2048KeyAndCSR(commonName: "SideBridge iOS")
        let issued = try await submitDevelopmentCSR(session: session, csrPem: csrPem)
        let passphrase = UUID().uuidString
        let p12 = try Self.packagePKCS12(certDER: issued.certContentDER, privateKeyPem: privateKeyPem, passphrase: passphrase)

        let record = SigningIdentityRecord(
            id: issued.certificateId,
            displayName: issued.name,
            serialNumber: issued.serialNumber,
            sha1Thumbprint: issued.sha1Thumbprint,
            sha256Thumbprint: issued.sha256Thumbprint,
            expiresAt: Date().addingTimeInterval(7 * 24 * 3600),
            isCustomP12: false
        )
        try keychain.save(p12, for: KeychainStorage.Key.activeP12Data.rawValue)
        try keychain.saveString(passphrase, for: .activeP12Passphrase)
        try keychain.saveCodable(record, for: .activeCertRecord)

        return ActiveSigningIdentity(
            p12Data: p12,
            passphrase: passphrase,
            sha1Thumbprint: issued.sha1Thumbprint,
            sha256Thumbprint: issued.sha256Thumbprint
        )
    }

    private func ensureDeviceRegistered(session: AppleAccountSession, udid: String, name: String) async throws {
        let existing = try await listDevices(session: session)
        let alreadyRegistered = existing.contains { ($0["deviceNumber"] as? String)?.lowercased() == udid.lowercased() }
        if !alreadyRegistered {
            logger?(.provision, "Registering device \(name) (\(udid.prefix(8))...) on Developer Portal", false)
            try await addDevice(session: session, udid: udid, name: name)
        }
    }

    private func ensureAppId(session: AppleAccountSession, bundleId: String, displayName: String) async throws -> AppIdRecord {
        let existing = try await listAppIds(session: session)
        if let match = existing.first(where: { $0.identifier == bundleId }) {
            return match
        }
        return try await addAppId(session: session, name: displayName, identifier: bundleId)
    }

    /// Parses the embedded XML plist from a CMS-signed `.mobileprovision` file and confirms
    /// `DeveloperCertificates` contains a certificate matching both SHA-1 and SHA-256 thumbprints.
    public func verifyProfileContainsCertificate(
        profileData: Data,
        expectedSHA1: String,
        expectedSHA256: String
    ) throws {
        let plist = try Self.extractMobileProvisionPlist(profileData)
        guard let devCerts = plist["DeveloperCertificates"] as? [Data], !devCerts.isEmpty else {
            throw ProvisionerError.certificateThumbprintMismatch("Provisioning profile has no DeveloperCertificates entries.")
        }

        let matched = devCerts.contains { certDER in
            Self.sha1Hex(certDER) == expectedSHA1.lowercased() &&
            Self.sha256Hex(certDER) == expectedSHA256.lowercased()
        }
        guard matched else {
            throw ProvisionerError.certificateThumbprintMismatch(
                "Downloaded .mobileprovision does not contain active leaf certificate thumbprint \(expectedSHA1.prefix(12))..."
            )
        }
    }

    public static func extractMobileProvisionPlist(_ profileData: Data) throws -> [String: Any] {
        guard
            let startRange = profileData.range(of: Data("<?xml".utf8)),
            let endRange = profileData.range(of: Data("</plist>".utf8))
        else {
            throw ProvisionerError.invalidProvisioningProfile
        }
        let xmlSlice = profileData.subdata(in: startRange.lowerBound..<endRange.upperBound)
        return try PlistCodec.decodeDictionary(xmlSlice)
    }

    // MARK: - HTTP & OpenSSL Helpers

    private func sendPortalRequest(
        path: String,
        adsid: String,
        token: String,
        params: [String: Any]
    ) async throws -> [String: Any] {
        let headers = try await anisette.mintHeaders()
        guard let url = URL(string: "\(Self.portalBase)/\(path)?clientId=\(Self.clientId)") else {
            throw ProvisionerError.portalError("Invalid portal endpoint URL: \(path)")
        }

        var body = params
        body["clientId"] = Self.clientId
        body["myacinfo"] = token
        body["protocolVersion"] = "QH65B2"
        body["requestId"] = UUID().uuidString.uppercased()
        body["userLocale"] = ["en_US"]

        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("text/x-xml-plist", forHTTPHeaderField: "Content-Type")
        req.setValue("text/x-xml-plist", forHTTPHeaderField: "Accept")
        req.setValue("Xcode", forHTTPHeaderField: "User-Agent")
        req.setValue("1", forHTTPHeaderField: "X-Xcode-Version")
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        req.httpBody = try PlistCodec.encodeXML(body)

        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw ProvisionerError.portalError("Developer Portal HTTP error \((response as? HTTPURLResponse)?.statusCode ?? -1)")
        }

        let plist = try PlistCodec.decodeDictionary(data)
        if let resultCode = (plist["resultCode"] as? NSNumber)?.intValue, resultCode != 0 {
            let resultString = (plist["resultString"] as? String) ?? "Apple Developer Portal error \(resultCode)"
            throw ProvisionerError.portalError("\(resultString) (code \(resultCode))")
        }
        return plist
    }

    private static func generateRSA2048KeyAndCSR(commonName: String) throws -> (privateKeyPem: String, csrPem: String) {
        guard let pkey = EVP_RSA_gen(2048) else {
            throw ProvisionerError.csrSubmissionFailed("OpenSSL EVP_RSA_gen(2048) failed")
        }
        defer { EVP_PKEY_free(pkey) }

        guard let req = X509_REQ_new() else {
            throw ProvisionerError.csrSubmissionFailed("X509_REQ_new failed")
        }
        defer { X509_REQ_free(req) }

        X509_REQ_set_version(req, 0)
        if let name = X509_REQ_get_subject_name(req) {
            X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, commonName, -1, -1, 0)
        }
        X509_REQ_set_pubkey(req, pkey)
        X509_REQ_sign(req, pkey, EVP_sha256())

        let keyBio = BIO_new(BIO_s_mem())
        let csrBio = BIO_new(BIO_s_mem())
        defer { BIO_free(keyBio); BIO_free(csrBio) }

        PEM_write_bio_PrivateKey(keyBio, pkey, nil, nil, 0, nil, nil)
        PEM_write_bio_X509_REQ(csrBio, req)

        return (readBioString(keyBio), readBioString(csrBio))
    }

    private static func packagePKCS12(certDER: Data, privateKeyPem: String, passphrase: String) throws -> Data {
        guard let keyBio = BIO_new_mem_buf(privateKeyPem, Int32(privateKeyPem.utf8.count)) else {
            throw ProvisionerError.csrSubmissionFailed("Failed to create key BIO")
        }
        defer { BIO_free(keyBio) }
        guard let pkey = PEM_read_bio_PrivateKey(keyBio, nil, nil, nil) else {
            throw ProvisionerError.csrSubmissionFailed("Failed to read private key PEM")
        }
        defer { EVP_PKEY_free(pkey) }

        let certPtr: OpaquePointer? = certDER.withUnsafeBytes { raw in
            var p = raw.baseAddress?.assumingMemoryBound(to: UInt8.self)
            return d2i_X509(nil, &p, certDER.count)
        }
        guard let cert = certPtr else {
            throw ProvisionerError.csrSubmissionFailed("Failed to parse issued DER certificate")
        }
        defer { X509_free(cert) }

        guard let p12 = PKCS12_create(passphrase, "SideBridge", pkey, cert, nil, 0, 0, 0, 0, 0) else {
            throw ProvisionerError.csrSubmissionFailed("PKCS12_create failed")
        }
        defer { PKCS12_free(p12) }

        guard let outBio = BIO_new(BIO_s_mem()) else {
            throw ProvisionerError.csrSubmissionFailed("Failed to allocate PKCS12 output BIO")
        }
        defer { BIO_free(outBio) }
        i2d_PKCS12_bio(outBio, p12)

        return readBioData(outBio)
    }

    private static func readBioData(_ bio: OpaquePointer?) -> Data {
        guard let bio else { return Data() }
        let len = Int(BIO_ctrl_pending(bio))
        guard len > 0 else { return Data() }
        var buf = [UInt8](repeating: 0, count: len)
        let readCount = BIO_read(bio, &buf, Int32(len))
        return Data(buf.prefix(max(0, Int(readCount))))
    }

    private static func readBioString(_ bio: OpaquePointer?) -> String {
        String(data: readBioData(bio), encoding: .utf8) ?? ""
    }

    public static func sha1Hex(_ data: Data) -> String {
        Insecure.SHA1.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    public static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

public enum ProvisionerError: LocalizedError {
    case portalError(String)
    case csrSubmissionFailed(String)
    case invalidProvisioningProfile
    case certificateThumbprintMismatch(String)

    public var errorDescription: String? {
        switch self {
        case .portalError(let msg): return msg
        case .csrSubmissionFailed(let msg): return msg
        case .invalidProvisioningProfile: return "Provisioning profile does not contain a valid embedded plist."
        case .certificateThumbprintMismatch(let msg): return msg
        }
    }
}
