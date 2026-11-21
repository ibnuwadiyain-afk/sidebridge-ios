import Foundation
import CryptoKit
import MachO

public struct ParsedSigningCredentials: @unchecked Sendable {
    public let leafCertDER: Data
    public let certificateChainDER: [Data]
    public let issuerDER: Data
    public let serialNumberDER: Data
    public let teamIdentifier: String
    public let signRSASHA256: @Sendable (Data) throws -> Data
}

/// On-device Mach-O (arm64 / FAT universal) code signer producing XNU CoreTrust-compliant
/// `CS_SuperBlob` (`0xfade0cc0`) signatures with dual SHA-1 + SHA-256 CodeDirectories,
/// embedded `__TEXT,__info_plist` Special Slot `-1` hashing, entitlements slots `-5`/`-7`,
/// and strict definite-length DER CMS (`0xfade0b01`) blobs.
public final class MachOSigner: @unchecked Sendable {
    public static let magicEmbeddedSignature: UInt32 = 0xfade0cc0
    public static let magicCodeDirectory: UInt32 = 0xfade0c02
    public static let magicRequirements: UInt32 = 0xfade0c01
    public static let magicEmbeddedEntitlements: UInt32 = 0xfade7171
    public static let magicEmbeddedDEREntitlements: UInt32 = 0xfade7172
    public static let magicBlobWrapperCMS: UInt32 = 0xfade0b01

    public static let slotCodeDirectory: UInt32 = 0x00000000
    public static let slotRequirements: UInt32 = 0x00000002
    public static let slotEntitlements: UInt32 = 0x00000005
    public static let slotDEREntitlements: UInt32 = 0x00000007
    public static let slotAlternateCodeDirectory: UInt32 = 0x00001000
    public static let slotSignatureCMS: UInt32 = 0x00010000

    public static let pageSize = 4096

    public init() {}

    /// Parses a `.p12` container via OpenSSL PKCS12 and resolves its WWDR G1-G6 intermediate CA chain.
    public static func loadCredentials(p12Data: Data, passphrase: String, teamIdentifier: String) throws -> ParsedSigningCredentials {
        let p12Ptr: OpaquePointer? = p12Data.withUnsafeBytes { raw in
            var ptr = raw.baseAddress?.assumingMemoryBound(to: UInt8.self)
            return d2i_PKCS12(nil, &ptr, p12Data.count)
        }
        guard let p12 = p12Ptr else {
            throw SigningError.invalidPKCS12("Unable to parse PKCS#12 archive")
        }
        defer { PKCS12_free(p12) }

        var pkey: OpaquePointer?
        var cert: OpaquePointer?
        var caStack: OpaquePointer?
        guard PKCS12_parse(p12, passphrase, &pkey, &cert, &caStack) == 1,
              let privateKey = pkey,
              let leafCert = cert else {
            throw SigningError.invalidPKCS12("Incorrect .p12 passphrase or missing leaf keypair")
        }
        defer { X509_free(leafCert) }

        let leafDER = exportX509DER(leafCert)
        let issuerDER = exportIssuerDER(leafCert)
        let serialDER = exportSerialNumberDER(leafCert)
        let chainDER = AppleWWDRCertificates.resolveChainDER(forLeafDER: leafDER)

        // Retain private key PEM for thread-safe EVP_DigestSign operations
        let keyBio = BIO_new(BIO_s_mem())
        defer { BIO_free(keyBio) }
        PEM_write_bio_PrivateKey(keyBio, privateKey, nil, nil, 0, nil, nil)
        EVP_PKEY_free(privateKey)
        let keyLen = Int(BIO_ctrl_pending(keyBio))
        var keyBuf = [UInt8](repeating: 0, count: max(0, keyLen))
        _ = BIO_read(keyBio, &keyBuf, Int32(keyLen))
        let privateKeyPem = String(bytes: keyBuf, encoding: .utf8) ?? ""

        let signerClosure: @Sendable (Data) throws -> Data = { payload in
            try Self.rsaSHA256Sign(payload: payload, privateKeyPem: privateKeyPem)
        }

        return ParsedSigningCredentials(
            leafCertDER: leafDER,
            certificateChainDER: chainDER,
            issuerDER: issuerDER,
            serialNumberDER: serialDER,
            teamIdentifier: teamIdentifier,
            signRSASHA256: signerClosure
        )
    }

    /// Signs a single Mach-O executable or `.dylib` in place (handles both 64-bit thin and FAT universal binaries).
    public func signMachOFile(
        at url: URL,
        identifier: String,
        infoPlistData: Data?,
        codeResourcesData: Data?,
        entitlementsXML: Data?,
        credentials: ParsedSigningCredentials
    ) throws {
        var binary = try Data(contentsOf: url)
        guard binary.count >= 4 else { throw SigningError.notAMachO(url.lastPathComponent) }

        let magic = binary.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }

        if magic == FAT_MAGIC || magic == FAT_CIGAM {
            binary = try signFatBinary(
                binary,
                identifier: identifier,
                infoPlistData: infoPlistData,
                codeResourcesData: codeResourcesData,
                entitlementsXML: entitlementsXML,
                credentials: credentials
            )
        } else if magic == MH_MAGIC_64 {
            binary = try signThinMachO64(
                binary,
                identifier: identifier,
                infoPlistData: infoPlistData,
                codeResourcesData: codeResourcesData,
                entitlementsXML: entitlementsXML,
                credentials: credentials
            )
        } else {
            throw SigningError.notAMachO(url.lastPathComponent)
        }

        try binary.write(to: url, options: .atomic)
    }

    /// Detects whether a Mach-O binary has an active FairPlay `LC_ENCRYPTION_INFO_64` (`cryptid != 0`).
    public static func isFairPlayEncrypted(fileURL: URL) -> Bool {
        guard let data = try? Data(contentsOf: fileURL), data.count >= MemoryLayout<mach_header_64>.size else {
            return false
        }
        let magic = data.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
        guard magic == MH_MAGIC_64 else { return false }

        let ncmds = Int(data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 16, as: UInt32.self) })
        var offset = MemoryLayout<mach_header_64>.size
        for _ in 0..<ncmds {
            guard offset + 8 <= data.count else { break }
            let cmd = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self) }
            let cmdsize = Int(data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset + 4, as: UInt32.self) })
            if (cmd == LC_ENCRYPTION_INFO_64 || cmd == LC_ENCRYPTION_INFO), offset + 20 <= data.count {
                let cryptid = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset + 16, as: UInt32.self) }
                if cryptid != 0 { return true }
            }
            offset += max(cmdsize, 8)
        }
        return false
    }

    // MARK: - Thin & FAT Mach-O Signing

    private func signFatBinary(
        _ fatData: Data,
        identifier: String,
        infoPlistData: Data?,
        codeResourcesData: Data?,
        entitlementsXML: Data?,
        credentials: ParsedSigningCredentials
    ) throws -> Data {
        let nfatArch = Int(fatData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 4, as: UInt32.self).bigEndian })
        guard nfatArch > 0, fatData.count >= 8 + nfatArch * 20 else {
            throw SigningError.malformedMachO("Invalid FAT header")
        }

        var slices: [(cputype: UInt32, cpusubtype: UInt32, align: UInt32, data: Data)] = []
        for i in 0..<nfatArch {
            let base = 8 + i * 20
            let cputype = fatData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: base, as: UInt32.self).bigEndian }
            let cpusubtype = fatData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: base + 4, as: UInt32.self).bigEndian }
            let offset = Int(fatData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: base + 8, as: UInt32.self).bigEndian })
            let size = Int(fatData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: base + 12, as: UInt32.self).bigEndian })
            let align = fatData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: base + 16, as: UInt32.self).bigEndian }

            guard offset + size <= fatData.count else { continue }
            var slice = fatData.subdata(in: offset..<(offset + size))
            let sliceMagic = slice.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
            if sliceMagic == MH_MAGIC_64 {
                slice = try signThinMachO64(
                    slice,
                    identifier: identifier,
                    infoPlistData: infoPlistData,
                    codeResourcesData: codeResourcesData,
                    entitlementsXML: entitlementsXML,
                    credentials: credentials
                )
            }
            slices.append((cputype, cpusubtype, align, slice))
        }

        var out = Data()
        appendUInt32BE(FAT_MAGIC, to: &out)
        appendUInt32BE(UInt32(slices.count), to: &out)

        var currentOffset = 8 + slices.count * 20
        var offsets: [Int] = []
        for s in slices {
            let alignment = 1 << min(Int(s.align), 14)
            currentOffset = (currentOffset + alignment - 1) & ~(alignment - 1)
            offsets.append(currentOffset)
            currentOffset += s.data.count
        }

        for (i, s) in slices.enumerated() {
            appendUInt32BE(s.cputype, to: &out)
            appendUInt32BE(s.cpusubtype, to: &out)
            appendUInt32BE(UInt32(offsets[i]), to: &out)
            appendUInt32BE(UInt32(s.data.count), to: &out)
            appendUInt32BE(s.align, to: &out)
        }

        for (i, s) in slices.enumerated() {
            if out.count < offsets[i] {
                out.append(Data(count: offsets[i] - out.count))
            }
            out.append(s.data)
        }
        return out
    }

    private func signThinMachO64(
        _ original: Data,
        identifier: String,
        infoPlistData: Data?,
        codeResourcesData: Data?,
        entitlementsXML: Data?,
        credentials: ParsedSigningCredentials
    ) throws -> Data {
        var binary = original
        let headerSize = MemoryLayout<mach_header_64>.size
        guard binary.count >= headerSize else {
            throw SigningError.malformedMachO("Truncated mach_header_64")
        }

        let ncmds = Int(binary.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 16, as: UInt32.self) })
        var offset = headerSize

        var linkeditCmdOffset: Int?
        var codeSigCmdOffset: Int?
        var codeSigDataOffset: Int?
        var embeddedInfoPlist: Data?

        for _ in 0..<ncmds {
            guard offset + 8 <= binary.count else { break }
            let cmd = binary.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self) }
            let cmdsize = Int(binary.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset + 4, as: UInt32.self) })

            if cmd == LC_SEGMENT_64, offset + 72 <= binary.count {
                let segName = readFixedCString(binary, offset: offset + 8, maxLen: 16)
                if segName == "__LINKEDIT" {
                    linkeditCmdOffset = offset
                } else if segName == "__TEXT" {
                    // Extract embedded __TEXT,__info_plist section for standalone Mach-O Special Slot -1
                    embeddedInfoPlist = extractEmbeddedInfoPlist(from: binary, segmentOffset: offset)
                }
            } else if cmd == LC_CODE_SIGNATURE, offset + 16 <= binary.count {
                codeSigCmdOffset = offset
                codeSigDataOffset = Int(binary.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset + 8, as: UInt32.self) })
            }

            offset += max(cmdsize, 8)
        }

        // Trim existing signature blob if present, align codeLimit to 16 bytes
        let codeLimit: Int
        if let existingSigOffset = codeSigDataOffset, existingSigOffset <= binary.count {
            codeLimit = existingSigOffset
            binary = binary.prefix(codeLimit)
        } else {
            let aligned = (binary.count + 15) & ~15
            if aligned > binary.count {
                binary.append(Data(count: aligned - binary.count))
            }
            codeLimit = binary.count
        }

        // Effective Info.plist for Special Slot -1: explicit bundle Info.plist OR embedded __TEXT,__info_plist
        let effectiveInfoPlist = infoPlistData ?? embeddedInfoPlist

        // Build dual CodeDirectories (SHA-1 primary slot 0, SHA-256 alternate slot 0x1000) + CMS blob
        let superBlob = try buildSuperBlob(
            codeBytes: binary,
            codeLimit: UInt32(codeLimit),
            identifier: identifier,
            infoPlistData: effectiveInfoPlist,
            codeResourcesData: codeResourcesData,
            entitlementsXML: entitlementsXML,
            credentials: credentials
        )

        // Update or append LC_CODE_SIGNATURE and __LINKEDIT filesize/vmsize
        if let sigCmdOffset = codeSigCmdOffset {
            writeUInt32LE(UInt32(codeLimit), to: &binary, at: sigCmdOffset + 8)
            writeUInt32LE(UInt32(superBlob.count), to: &binary, at: sigCmdOffset + 12)
        } else {
            // Append new 16-byte LC_CODE_SIGNATURE command right after existing load commands
            let sizeofcmds = Int(binary.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 20, as: UInt32.self) })
            let insertAt = headerSize + sizeofcmds
            writeUInt32LE(UInt32(ncmds + 1), to: &binary, at: 16)
            writeUInt32LE(UInt32(sizeofcmds + 16), to: &binary, at: 20)
            writeUInt32LE(UInt32(LC_CODE_SIGNATURE), to: &binary, at: insertAt)
            writeUInt32LE(16, to: &binary, at: insertAt + 4)
            writeUInt32LE(UInt32(codeLimit), to: &binary, at: insertAt + 8)
            writeUInt32LE(UInt32(superBlob.count), to: &binary, at: insertAt + 12)
        }

        let newFileSize = codeLimit + superBlob.count
        if let linkeditOffset = linkeditCmdOffset {
            let fileoff = Int(binary.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: linkeditOffset + 40, as: UInt64.self) })
            let newLinkeditFileSize = UInt64(max(0, newFileSize - fileoff))
            let alignedVMSize = ((newLinkeditFileSize + 0x3FFF) / 0x4000) * 0x4000
            writeUInt64LE(alignedVMSize, to: &binary, at: linkeditOffset + 32)
            writeUInt64LE(newLinkeditFileSize, to: &binary, at: linkeditOffset + 48)
        }

        binary.append(superBlob)
        return binary
    }

    /// Reads `__TEXT,__info_plist` section data from a 64-bit Mach-O segment if present.
    private func extractEmbeddedInfoPlist(from binary: Data, segmentOffset: Int) -> Data? {
        let nsects = Int(binary.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: segmentOffset + 64, as: UInt32.self) })
        var sectOffset = segmentOffset + 72 // sizeof(segment_command_64)
        for _ in 0..<nsects {
            guard sectOffset + 80 <= binary.count else { break }
            let sectName = readFixedCString(binary, offset: sectOffset, maxLen: 16)
            if sectName == "__info_plist" {
                let size = Int(binary.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: sectOffset + 40, as: UInt64.self) })
                let fileOffset = Int(binary.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: sectOffset + 48, as: UInt32.self) })
                if fileOffset > 0, fileOffset + size <= binary.count {
                    return binary.subdata(in: fileOffset..<(fileOffset + size))
                }
            }
            sectOffset += 80 // sizeof(section_64)
        }
        return nil
    }

    // MARK: - CodeDirectory & SuperBlob Construction

    private func buildSuperBlob(
        codeBytes: Data,
        codeLimit: UInt32,
        identifier: String,
        infoPlistData: Data?,
        codeResourcesData: Data?,
        entitlementsXML: Data?,
        credentials: ParsedSigningCredentials
    ) throws -> Data {
        // Empty Requirements blob (0xfade0c01, 12 bytes)
        var reqBlob = Data()
        appendUInt32BE(Self.magicRequirements, to: &reqBlob)
        appendUInt32BE(12, to: &reqBlob)
        appendUInt32BE(0, to: &reqBlob)

        var entitlementsBlob: Data?
        var derEntitlementsBlob: Data?
        if let entXML = entitlementsXML {
            var eb = Data()
            appendUInt32BE(Self.magicEmbeddedEntitlements, to: &eb)
            appendUInt32BE(UInt32(8 + entXML.count), to: &eb)
            eb.append(entXML)
            entitlementsBlob = eb

            // Minimal DER entitlements blob wrapping XML payload hash anchor for slot -7
            let derPayload = DEREncoder.octetString(entXML)
            var db = Data()
            appendUInt32BE(Self.magicEmbeddedDEREntitlements, to: &db)
            appendUInt32BE(UInt32(8 + derPayload.count), to: &db)
            db.append(derPayload)
            derEntitlementsBlob = db
        }

        let cdSHA1 = buildCodeDirectory(
            codeBytes: codeBytes,
            codeLimit: codeLimit,
            identifier: identifier,
            teamId: credentials.teamIdentifier,
            hashType: 1, // SHA-1
            infoPlistData: infoPlistData,
            requirementsBlob: reqBlob,
            codeResourcesData: codeResourcesData,
            entitlementsBlob: entitlementsBlob,
            derEntitlementsBlob: derEntitlementsBlob
        )

        let cdSHA256 = buildCodeDirectory(
            codeBytes: codeBytes,
            codeLimit: codeLimit,
            identifier: identifier,
            teamId: credentials.teamIdentifier,
            hashType: 2, // SHA-256
            infoPlistData: infoPlistData,
            requirementsBlob: reqBlob,
            codeResourcesData: codeResourcesData,
            entitlementsBlob: entitlementsBlob,
            derEntitlementsBlob: derEntitlementsBlob
        )

        let sha1CDHash = Data(Insecure.SHA1.hash(data: cdSHA1))
        let sha256CDHash = Data(SHA256.hash(data: cdSHA256))

        let cmsDER = try DEREncoder.buildCoreTrustCMS(
            primaryCodeDirectory: cdSHA1,
            sha1CDHash: sha1CDHash,
            sha256CDHash: sha256CDHash,
            certificateChainDER: credentials.certificateChainDER,
            issuerDER: credentials.issuerDER,
            serialNumberDER: credentials.serialNumberDER,
            signRSASHA256: credentials.signRSASHA256
        )

        var cmsBlob = Data()
        appendUInt32BE(Self.magicBlobWrapperCMS, to: &cmsBlob)
        appendUInt32BE(UInt32(8 + cmsDER.count), to: &cmsBlob)
        cmsBlob.append(cmsDER)

        var entries: [(slot: UInt32, blob: Data)] = [
            (Self.slotCodeDirectory, cdSHA1),
            (Self.slotRequirements, reqBlob)
        ]
        if let entitlementsBlob {
            entries.append((Self.slotEntitlements, entitlementsBlob))
        }
        if let derEntitlementsBlob {
            entries.append((Self.slotDEREntitlements, derEntitlementsBlob))
        }
        entries.append((Self.slotAlternateCodeDirectory, cdSHA256))
        entries.append((Self.slotSignatureCMS, cmsBlob))

        let headerLen = 12 + entries.count * 8
        let totalLen = headerLen + entries.reduce(0) { $0 + $1.blob.count }

        var superBlob = Data()
        superBlob.reserveCapacity(totalLen)
        appendUInt32BE(Self.magicEmbeddedSignature, to: &superBlob)
        appendUInt32BE(UInt32(totalLen), to: &superBlob)
        appendUInt32BE(UInt32(entries.count), to: &superBlob)

        var currentBlobOffset = headerLen
        for entry in entries {
            appendUInt32BE(entry.slot, to: &superBlob)
            appendUInt32BE(UInt32(currentBlobOffset), to: &superBlob)
            currentBlobOffset += entry.blob.count
        }
        for entry in entries {
            superBlob.append(entry.blob)
        }
        return superBlob
    }

    private func buildCodeDirectory(
        codeBytes: Data,
        codeLimit: UInt32,
        identifier: String,
        teamId: String,
        hashType: UInt8,
        infoPlistData: Data?,
        requirementsBlob: Data,
        codeResourcesData: Data?,
        entitlementsBlob: Data?,
        derEntitlementsBlob: Data?
    ) -> Data {
        let hashSize = hashType == 2 ? 32 : 20
        let zeroHash = Data(count: hashSize)

        func digest(_ data: Data) -> Data {
            hashType == 2 ? Data(SHA256.hash(data: data)) : Data(Insecure.SHA1.hash(data: data))
        }

        // Special slots: -7 (DER Entitlements) .. -1 (Info.plist / __TEXT,__info_plist)
        let nSpecialSlots: UInt32 = derEntitlementsBlob != nil ? 7 : (entitlementsBlob != nil ? 5 : (codeResourcesData != nil ? 3 : 2))
        var specialHashes: [Data] = []
        for slot in stride(from: Int(nSpecialSlots), through: 1, by: -1) {
            switch slot {
            case 7: specialHashes.append(derEntitlementsBlob.map(digest) ?? zeroHash)
            case 5: specialHashes.append(entitlementsBlob.map(digest) ?? zeroHash)
            case 3: specialHashes.append(codeResourcesData.map(digest) ?? zeroHash)
            case 2: specialHashes.append(digest(requirementsBlob))
            case 1: specialHashes.append(infoPlistData.map(digest) ?? zeroHash)
            default: specialHashes.append(zeroHash)
            }
        }

        let pageCount = (Int(codeLimit) + Self.pageSize - 1) / Self.pageSize
        var codeHashes: [Data] = []
        codeHashes.reserveCapacity(pageCount)
        for page in 0..<pageCount {
            let start = page * Self.pageSize
            let end = min(start + Self.pageSize, Int(codeLimit))
            codeHashes.append(digest(codeBytes.subdata(in: start..<end)))
        }

        let identBytes = Data(identifier.utf8) + Data([0])
        let teamBytes = Data(teamId.utf8) + Data([0])

        let fixedHeaderSize = 52 // version 0x20400 header with teamOffset
        let identOffset = fixedHeaderSize
        let teamOffset = identOffset + identBytes.count
        let specialStartOffset = teamOffset + teamBytes.count
        let hashOffset = specialStartOffset + Int(nSpecialSlots) * hashSize
        let totalLength = hashOffset + pageCount * hashSize

        var cd = Data()
        cd.reserveCapacity(totalLength)
        appendUInt32BE(Self.magicCodeDirectory, to: &cd)
        appendUInt32BE(UInt32(totalLength), to: &cd)
        appendUInt32BE(0x00020400, to: &cd) // version 2.4 (execSeg + teamId)
        appendUInt32BE(0x00000000, to: &cd) // flags
        appendUInt32BE(UInt32(hashOffset), to: &cd)
        appendUInt32BE(UInt32(identOffset), to: &cd)
        appendUInt32BE(nSpecialSlots, to: &cd)
        appendUInt32BE(UInt32(pageCount), to: &cd)
        appendUInt32BE(codeLimit, to: &cd)
        cd.append(UInt8(hashSize))
        cd.append(hashType)
        cd.append(0)  // platform
        cd.append(12) // log2(4096)
        appendUInt32BE(0, to: &cd) // spare2
        appendUInt32BE(0, to: &cd) // scatterOffset
        appendUInt32BE(UInt32(teamOffset), to: &cd)

        cd.append(identBytes)
        cd.append(teamBytes)
        for h in specialHashes { cd.append(h) }
        for h in codeHashes { cd.append(h) }
        return cd
    }

    // MARK: - OpenSSL Helpers & Binary Utilities

    private static func rsaSHA256Sign(payload: Data, privateKeyPem: String) throws -> Data {
        guard let bio = BIO_new_mem_buf(privateKeyPem, Int32(privateKeyPem.utf8.count)) else {
            throw SigningError.cryptoFailure("BIO_new_mem_buf failed")
        }
        defer { BIO_free(bio) }
        guard let pkey = PEM_read_bio_PrivateKey(bio, nil, nil, nil) else {
            throw SigningError.cryptoFailure("PEM_read_bio_PrivateKey failed")
        }
        defer { EVP_PKEY_free(pkey) }

        guard let mdCtx = EVP_MD_CTX_new() else {
            throw SigningError.cryptoFailure("EVP_MD_CTX_new failed")
        }
        defer { EVP_MD_CTX_free(mdCtx) }

        guard EVP_DigestSignInit(mdCtx, nil, EVP_sha256(), nil, pkey) == 1 else {
            throw SigningError.cryptoFailure("EVP_DigestSignInit failed")
        }

        var sigLen: Int = 0
        let updateOk = payload.withUnsafeBytes { raw in
            EVP_DigestSignUpdate(mdCtx, raw.baseAddress, payload.count) == 1
        }
        guard updateOk, EVP_DigestSignFinal(mdCtx, nil, &sigLen) == 1 else {
            throw SigningError.cryptoFailure("EVP_DigestSignFinal sizing failed")
        }

        var signature = [UInt8](repeating: 0, count: sigLen)
        guard EVP_DigestSignFinal(mdCtx, &signature, &sigLen) == 1 else {
            throw SigningError.cryptoFailure("EVP_DigestSignFinal signing failed")
        }
        return Data(signature.prefix(sigLen))
    }

    private static func exportX509DER(_ cert: OpaquePointer) -> Data {
        let len = i2d_X509(cert, nil)
        guard len > 0 else { return Data() }
        var buf = [UInt8](repeating: 0, count: Int(len))
        buf.withUnsafeMutableBufferPointer { ptr in
            var out = ptr.baseAddress
            _ = i2d_X509(cert, &out)
        }
        return Data(buf)
    }

    private static func exportIssuerDER(_ cert: OpaquePointer) -> Data {
        guard let issuer = X509_get_issuer_name(cert) else { return Data() }
        let len = i2d_X509_NAME(issuer, nil)
        guard len > 0 else { return Data() }
        var buf = [UInt8](repeating: 0, count: Int(len))
        buf.withUnsafeMutableBufferPointer { ptr in
            var out = ptr.baseAddress
            _ = i2d_X509_NAME(issuer, &out)
        }
        return Data(buf)
    }

    private static func exportSerialNumberDER(_ cert: OpaquePointer) -> Data {
        guard let serial = X509_get0_serialNumber(cert) else { return Data() }
        let len = i2d_ASN1_INTEGER(serial, nil)
        guard len > 0 else { return Data() }
        var buf = [UInt8](repeating: 0, count: Int(len))
        buf.withUnsafeMutableBufferPointer { ptr in
            var out = ptr.baseAddress
            _ = i2d_ASN1_INTEGER(serial, &out)
        }
        return Data(buf)
    }

    private func readFixedCString(_ data: Data, offset: Int, maxLen: Int) -> String {
        let slice = data.subdata(in: offset..<min(offset + maxLen, data.count))
        let trimmed = slice.prefix(while: { $0 != 0 })
        return String(data: trimmed, encoding: .utf8) ?? ""
    }

    private func appendUInt32BE(_ value: UInt32, to data: inout Data) {
        var be = value.bigEndian
        data.append(Data(bytes: &be, count: 4))
    }

    private func writeUInt32LE(_ value: UInt32, to data: inout Data, at offset: Int) {
        var le = value.littleEndian
        withUnsafeBytes(of: &le) { bytes in
            data.replaceSubrange(offset..<(offset + 4), with: bytes)
        }
    }

    private func writeUInt64LE(_ value: UInt64, to data: inout Data, at offset: Int) {
        var le = value.littleEndian
        withUnsafeBytes(of: &le) { bytes in
            data.replaceSubrange(offset..<(offset + 8), with: bytes)
        }
    }
}

public enum SigningError: LocalizedError {
    case invalidPKCS12(String)
    case notAMachO(String)
    case malformedMachO(String)
    case fairPlayEncryptedBinary(String)
    case missingAppBundle
    case missingInfoPlist
    case cryptoFailure(String)

    public var errorDescription: String? {
        switch self {
        case .invalidPKCS12(let msg): return msg
        case .notAMachO(let file): return "\(file) is not a valid 64-bit or FAT Mach-O binary."
        case .malformedMachO(let msg): return "Malformed Mach-O binary: \(msg)"
        case .fairPlayEncryptedBinary(let name):
            return "\(name) is FairPlay-encrypted (.sinf / cryptid != 0). Only decrypted IPAs can be re-signed."
        case .missingAppBundle: return "IPA archive does not contain a Payload/*.app bundle."
        case .missingInfoPlist: return "App bundle is missing Info.plist."
        case .cryptoFailure(let msg): return "Signing cryptographic failure: \(msg)"
        }
    }
}
