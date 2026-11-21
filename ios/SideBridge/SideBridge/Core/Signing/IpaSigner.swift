import Foundation
import CryptoKit
import ZIPFoundation

public struct SignedIPAResult: Sendable {
    public let signedIPAURL: URL
    public let effectiveBundleIdentifier: String
    public let signedComponentCount: Int
    public let detectedFairPlaySinf: Bool
}

/// Complete on-device `.ipa` unpacker, surgical Info.plist updater, bottom-up nested framework/dylib signer,
/// `_CodeSignature/CodeResources` (SHA-1 & SHA-256) generator, and CoreTrust-safe IPA repacker.
///
/// CRITICAL INVARIANTS:
/// 1. Leaves nested `.framework/Info.plist` (`bplist00`) files byte-for-byte untouched unless
///    `CFBundleResourceSpecification` is present.
/// 2. Recursively signs nested `.framework` bundles, `.appex` plugins, and standalone `.dylib` Mach-O
///    binaries bottom-up BEFORE generating the parent bundle's `_CodeSignature/CodeResources`.
/// 3. Repacks the signed IPA with `STORED` directory entries (`size = 0, crc = 0`) and Unix `0755`
///    (`0x81ED`) external file attributes on executables.
public final class IpaSigner: @unchecked Sendable {
    private let machOSigner: MachOSigner
    private let logger: (@Sendable (LogCategory, String, Bool) -> Void)?

    public init(
        machOSigner: MachOSigner = MachOSigner(),
        logger: (@Sendable (LogCategory, String, Bool) -> Void)? = nil
    ) {
        self.machOSigner = machOSigner
        self.logger = logger
    }

    public func signIPA(
        sourceIPAURL: URL,
        p12Data: Data,
        p12Passphrase: String,
        mobileProvisionData: Data,
        overrideBundleId: String? = nil
    ) throws -> SignedIPAResult {
        let fm = FileManager.default
        let workDir = fm.temporaryDirectory.appendingPathComponent("SideBridgeSign-\(UUID().uuidString)", isDirectory: true)
        let extractDir = workDir.appendingPathComponent("extracted", isDirectory: true)
        try fm.createDirectory(at: extractDir, withIntermediateDirectories: true)

        logger?(.sign, "Unpacking \(sourceIPAURL.lastPathComponent) via ZIPFoundation", false)
        try fm.unzipItem(at: sourceIPAURL, to: extractDir)

        let payloadDir = extractDir.appendingPathComponent("Payload", isDirectory: true)
        let payloadContents = try fm.contentsOfDirectory(at: payloadDir, includingPropertiesForKeys: nil)
        guard let appBundleURL = payloadContents.first(where: { $0.pathExtension == "app" }) else {
            throw SigningError.missingAppBundle
        }

        // Parse embedded mobileprovision plist for TeamIdentifier & Entitlements
        let provisionPlist = try AppleDeveloperProvisioner.extractMobileProvisionPlist(mobileProvisionData)
        let teamId = ((provisionPlist["TeamIdentifier"] as? [String])?.first)
            ?? ((provisionPlist["ApplicationIdentifierPrefix"] as? [String])?.first)
            ?? "SIDEBRIDGE"
        let entitlementsDict = (provisionPlist["Entitlements"] as? [String: Any]) ?? [:]
        let entitlementsXML = try PlistCodec.encodeXML(entitlementsDict)

        let credentials = try MachOSigner.loadCredentials(
            p12Data: p12Data,
            passphrase: p12Passphrase,
            teamIdentifier: teamId
        )

        // Detect FairPlay .sinf encrypted binaries
        let hasSinf = detectFairPlaySinf(in: appBundleURL)
        let infoPlistURL = appBundleURL.appendingPathComponent("Info.plist")
        guard fm.fileExists(atPath: infoPlistURL.path) else {
            throw SigningError.missingInfoPlist
        }
        var mainInfo = try PlistCodec.decodeDictionary(Data(contentsOf: infoPlistURL))
        let mainExecName = (mainInfo["CFBundleExecutable"] as? String) ?? appBundleURL.deletingPathExtension().lastPathComponent
        let mainExecURL = appBundleURL.appendingPathComponent(mainExecName)

        if hasSinf || MachOSigner.isFairPlayEncrypted(fileURL: mainExecURL) {
            logger?(.sign, "Detected FairPlay-encrypted binary (.sinf or cryptid != 0)", true)
            throw SigningError.fairPlayEncryptedBinary(mainExecName)
        }

        // Embed mobileprovision inside the main .app bundle
        let embeddedProvisionURL = appBundleURL.appendingPathComponent("embedded.mobileprovision")
        try mobileProvisionData.write(to: embeddedProvisionURL, options: .atomic)

        // Surgically update CFBundleIdentifier in the main app Info.plist
        let effectiveBundleId = overrideBundleId ?? (mainInfo["CFBundleIdentifier"] as? String) ?? "com.sidebridge.app"
        if mainInfo["CFBundleIdentifier"] as? String != effectiveBundleId {
            mainInfo["CFBundleIdentifier"] = effectiveBundleId
            mainInfo.removeValue(forKey: "CFBundleResourceSpecification")
            let updatedMainInfoData = try PlistCodec.encodeBinary(mainInfo)
            try updatedMainInfoData.write(to: infoPlistURL, options: .atomic)
            logger?(.sign, "Updated main Info.plist CFBundleIdentifier -> \(effectiveBundleId)", false)
        }

        // Recursively sign all nested .framework bundles, .appex extensions, and standalone .dylibs bottom-up
        var signedCount = 0
        signedCount += try signNestedComponentsBottomUp(
            in: appBundleURL,
            credentials: credentials,
            entitlementsXML: entitlementsXML
        )

        // Generate _CodeSignature/CodeResources (SHA-1 & SHA-256) for main .app bundle
        let codeResourcesData = try generateCodeResources(for: appBundleURL, mainExecutableName: mainExecName)
        let mainInfoBytes = try Data(contentsOf: infoPlistURL)

        // Sign main app Mach-O executable
        logger?(.sign, "Signing main Mach-O executable \(mainExecName) (WWDR chain count=\(credentials.certificateChainDER.count))", false)
        try machOSigner.signMachOFile(
            at: mainExecURL,
            identifier: effectiveBundleId,
            infoPlistData: mainInfoBytes,
            codeResourcesData: codeResourcesData,
            entitlementsXML: entitlementsXML,
            credentials: credentials
        )
        signedCount += 1

        // Repack signed IPA with STORED directory entries (size=0, crc=0) and Unix 0755 (0x81ED) on executables
        let outputURL = workDir.appendingPathComponent("\(effectiveBundleId)-signed.ipa")
        try repackSignedIPA(from: extractDir, to: outputURL, executablePaths: collectExecutableRelativePaths(in: extractDir))
        logger?(.sign, "Repacked signed IPA (\(signedCount) signed binaries) with STORED dirs & 0755 executable bits", false)

        return SignedIPAResult(
            signedIPAURL: outputURL,
            effectiveBundleIdentifier: effectiveBundleId,
            signedComponentCount: signedCount,
            detectedFairPlaySinf: hasSinf
        )
    }

    // MARK: - Bottom-Up Nested Signing

    private func signNestedComponentsBottomUp(
        in bundleURL: URL,
        credentials: ParsedSigningCredentials,
        entitlementsXML: Data
    ) throws -> Int {
        let fm = FileManager.default
        var count = 0

        let frameworksDir = bundleURL.appendingPathComponent("Frameworks", isDirectory: true)
        if fm.fileExists(atPath: frameworksDir.path) {
            let items = try fm.contentsOfDirectory(at: frameworksDir, includingPropertiesForKeys: [.isDirectoryKey])
            for item in items {
                if item.pathExtension == "framework" {
                    // Recurse deeper first (bottom-up)
                    count += try signNestedComponentsBottomUp(in: item, credentials: credentials, entitlementsXML: entitlementsXML)
                    try signFrameworkBundle(item, credentials: credentials)
                    count += 1
                } else if item.pathExtension == "dylib" {
                    logger?(.sign, "Signing standalone Mach-O dylib \(item.lastPathComponent)", false)
                    try machOSigner.signMachOFile(
                        at: item,
                        identifier: item.deletingPathExtension().lastPathComponent,
                        infoPlistData: nil, // MachOSigner automatically hashes embedded __TEXT,__info_plist if present
                        codeResourcesData: nil,
                        entitlementsXML: nil,
                        credentials: credentials
                    )
                    count += 1
                }
            }
        }

        let plugInsDir = bundleURL.appendingPathComponent("PlugIns", isDirectory: true)
        if fm.fileExists(atPath: plugInsDir.path) {
            let plugins = try fm.contentsOfDirectory(at: plugInsDir, includingPropertiesForKeys: nil)
            for plugin in plugins where plugin.pathExtension == "appex" {
                count += try signNestedComponentsBottomUp(in: plugin, credentials: credentials, entitlementsXML: entitlementsXML)
                try signFrameworkBundle(plugin, credentials: credentials, entitlementsXML: entitlementsXML)
                count += 1
            }
        }

        return count
    }

    private func signFrameworkBundle(
        _ bundleURL: URL,
        credentials: ParsedSigningCredentials,
        entitlementsXML: Data? = nil
    ) throws {
        let infoURL = bundleURL.appendingPathComponent("Info.plist")
        var infoBytes = try Data(contentsOf: infoURL)
        var infoDict = try PlistCodec.decodeDictionary(infoBytes)

        // CRITICAL: Leave nested .framework/Info.plist (bplist00) byte-for-byte untouched
        // UNLESS deprecated `CFBundleResourceSpecification` is present.
        if infoDict["CFBundleResourceSpecification"] != nil {
            infoDict.removeValue(forKey: "CFBundleResourceSpecification")
            infoBytes = PlistCodec.isBinaryPlist(infoBytes)
                ? try PlistCodec.encodeBinary(infoDict)
                : try PlistCodec.encodeXML(infoDict)
            try infoBytes.write(to: infoURL, options: .atomic)
        }

        let execName = (infoDict["CFBundleExecutable"] as? String) ?? bundleURL.deletingPathExtension().lastPathComponent
        let bundleId = (infoDict["CFBundleIdentifier"] as? String) ?? execName
        let execURL = bundleURL.appendingPathComponent(execName)

        let codeResources = try generateCodeResources(for: bundleURL, mainExecutableName: execName)
        logger?(.sign, "Signing nested bundle \(bundleURL.lastPathComponent) (\(execName))", false)
        try machOSigner.signMachOFile(
            at: execURL,
            identifier: bundleId,
            infoPlistData: infoBytes,
            codeResourcesData: codeResources,
            entitlementsXML: entitlementsXML,
            credentials: credentials
        )
    }

    // MARK: - _CodeSignature/CodeResources (SHA-1 & SHA-256)

    private func generateCodeResources(for bundleURL: URL, mainExecutableName: String) throws -> Data {
        let fm = FileManager.default
        let codeSigDir = bundleURL.appendingPathComponent("_CodeSignature", isDirectory: true)
        try fm.createDirectory(at: codeSigDir, withIntermediateDirectories: true)

        var filesV1: [String: Any] = [:]
        var filesV2: [String: Any] = [:]

        let enumerator = fm.enumerator(
            at: bundleURL,
            includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey],
            options: []
        )

        let basePath = bundleURL.standardizedFileURL.path + "/"
        while let fileURL = enumerator?.nextObject() as? URL {
            let fullPath = fileURL.standardizedFileURL.path
            guard fullPath.hasPrefix(basePath) else { continue }
            let relPath = String(fullPath.dropFirst(basePath.count))

            // Exclude _CodeSignature and the main executable itself
            if relPath == "_CodeSignature" || relPath.hasPrefix("_CodeSignature/") || relPath == mainExecutableName {
                continue
            }

            let values = try fileURL.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            if values.isSymbolicLink == true {
                let target = try fm.destinationOfSymbolicLink(atPath: fileURL.path)
                filesV2[relPath] = ["symlink": target]
                continue
            }
            guard values.isRegularFile == true else { continue }

            let data = try Data(contentsOf: fileURL)
            let sha1 = Data(Insecure.SHA1.hash(data: data))
            let sha256 = Data(SHA256.hash(data: data))

            if relPath != "Info.plist" {
                filesV1[relPath] = sha1
            }
            filesV2[relPath] = [
                "hash": sha1,
                "hash2": sha256
            ]
        }

        let codeResourcesDict: [String: Any] = [
            "files": filesV1,
            "files2": filesV2,
            "rules": [
                "^.*": true,
                "^.*\\.lproj/": ["optional": true, "weight": 1000.0],
                "^Info\\.plist$": ["omit": true, "weight": 20.0],
                "^PkgInfo$": ["omit": true, "weight": 20.0]
            ],
            "rules2": [
                "^.*": true,
                "^.*\\.lproj/": ["optional": true, "weight": 1000.0],
                "^(_CodeSignature|CodeResources)": ["omit": true, "weight": 2000.0],
                "^Info\\.plist$": ["omit": true, "weight": 20.0],
                "^PkgInfo$": ["omit": true, "weight": 20.0],
                "^embedded\\.provisionprofile$": ["weight": 20.0]
            ]
        ]

        let xmlData = try PlistCodec.encodeXML(codeResourcesDict)
        try xmlData.write(to: codeSigDir.appendingPathComponent("CodeResources"), options: .atomic)
        return xmlData
    }

    // MARK: - CoreTrust-Safe IPA Repacking (STORED Dirs & Unix 0755)

    private func repackSignedIPA(
        from rootDir: URL,
        to destinationURL: URL,
        executablePaths: Set<String>
    ) throws {
        let fm = FileManager.default
        if fm.fileExists(atPath: destinationURL.path) {
            try fm.removeItem(at: destinationURL)
        }
        guard let archive = Archive(url: destinationURL, accessMode: .create) else {
            throw SigningError.cryptoFailure("Unable to create output IPA ZIP archive")
        }

        let basePath = rootDir.standardizedFileURL.path + "/"
        let enumerator = fm.enumerator(
            at: rootDir,
            includingPropertiesForKeys: [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey],
            options: []
        )

        var paths: [(url: URL, rel: String, isDir: Bool)] = []
        while let item = enumerator?.nextObject() as? URL {
            let full = item.standardizedFileURL.path
            guard full.hasPrefix(basePath) else { continue }
            let rel = String(full.dropFirst(basePath.count))
            let values = try item.resourceValues(forKeys: [.isDirectoryKey])
            paths.append((item, rel, values.isDirectory == true))
        }

        // Deterministic sort ensures Payload/ directory precedes files
        paths.sort { $0.rel < $1.rel }

        for entry in paths {
            if entry.isDir {
                // CRITICAL: Emit explicit STORED directory entries (`size = 0, crc = 0`)
                let dirPath = entry.rel.hasSuffix("/") ? entry.rel : entry.rel + "/"
                try archive.addEntry(
                    with: dirPath,
                    type: .directory,
                    uncompressedSize: 0,
                    compressionMethod: .none,
                    provider: { _, _ in Data() }
                )
            } else {
                // Ensure Unix 0755 (`0x81ED`) permissions on Mach-O executables & dylibs
                if executablePaths.contains(entry.rel) {
                    try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: entry.url.path)
                }
                try archive.addEntry(
                    with: entry.rel,
                    relativeTo: rootDir,
                    compressionMethod: .deflate
                )
            }
        }
    }

    private func collectExecutableRelativePaths(in rootDir: URL) -> Set<String> {
        var execs = Set<String>()
        let fm = FileManager.default
        let basePath = rootDir.standardizedFileURL.path + "/"
        let enumerator = fm.enumerator(at: rootDir, includingPropertiesForKeys: [.isRegularFileKey])
        while let file = enumerator?.nextObject() as? URL {
            guard (try? file.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true else { continue }
            if let handle = try? FileHandle(forReadingFrom: file),
               let header = try? handle.read(upToCount: 4),
               header.count == 4 {
                try? handle.close()
                let magic = header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
                if magic == MH_MAGIC_64 || magic == FAT_MAGIC || magic == FAT_CIGAM {
                    let full = file.standardizedFileURL.path
                    if full.hasPrefix(basePath) {
                        execs.insert(String(full.dropFirst(basePath.count)))
                    }
                }
            }
        }
        return execs
    }

    private func detectFairPlaySinf(in appBundleURL: URL) -> Bool {
        let scInfo = appBundleURL.appendingPathComponent("SC_Info", isDirectory: true)
        guard let items = try? FileManager.default.contentsOfDirectory(at: scInfo, includingPropertiesForKeys: nil) else {
            return false
        }
        return items.contains { $0.pathExtension.lowercased() == "sinf" }
    }
}
