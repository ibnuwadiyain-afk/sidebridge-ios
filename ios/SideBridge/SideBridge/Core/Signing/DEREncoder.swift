import Foundation
import CryptoKit

/// Strict definite-length ASN.1 DER encoder and XNU CoreTrust CMS (`0xfade0b01`) builder.
///
/// CRITICAL XNU CORETRUST COMPLIANCE:
/// 1. Every ASN.1 TLV is emitted in strict definite-length DER (NEVER indefinite-length BER `0x80`).
/// 2. RFC 6211 `cmsAlgorithmProtect` (`1.2.840.113549.1.9.52`) is strictly OMITTED.
/// 3. `SignerInfo.signedAttrs` contains ONLY Apple's exact 5 attributes in canonical DER SET order:
///    - `1.2.840.113549.1.9.3` (contentType = id-data)
///    - `1.2.840.113549.1.9.5` (signingTime = UTCTime)
///    - `1.2.840.113549.1.9.4` (messageDigest = SHA-256 of primary CodeDirectory)
///    - `1.2.840.113635.100.9.1` (Apple CDHashes XML plist containing SHA-1 CDHash)
///    - `1.2.840.113635.100.9.2` (Apple CDHashes2 DER sequence containing SHA-256 CDHash)
public enum DEREncoder {
    // MARK: - Core Definite-Length ASN.1 Primitives

    public static func encodeLength(_ length: Int) -> Data {
        if length < 0x80 {
            return Data([UInt8(length)])
        }
        var len = length
        var bytes: [UInt8] = []
        while len > 0 {
            bytes.insert(UInt8(len & 0xFF), at: 0)
            len >>= 8
        }
        return Data([UInt8(0x80 | bytes.count)] + bytes)
    }

    public static func tlv(tag: UInt8, content: Data) -> Data {
        var out = Data([tag])
        out.append(encodeLength(content.count))
        out.append(content)
        return out
    }

    public static func sequence(_ items: [Data]) -> Data {
        tlv(tag: 0x30, content: items.reduce(Data(), +))
    }

    /// Encodes a DER SET (`0x31`) with elements lexicographically sorted by encoded bytes (X.690 §11.6).
    public static func set(_ items: [Data]) -> Data {
        let sorted = items.sorted { $0.lexicographicallyPrecedes($1) }
        return tlv(tag: 0x31, content: sorted.reduce(Data(), +))
    }

    public static func contextSpecific(tagNumber: UInt8, constructed: Bool = true, content: Data) -> Data {
        let tag = (constructed ? 0xA0 : 0x80) | (tagNumber & 0x1F)
        return tlv(tag: tag, content: content)
    }

    public static func integer(_ value: UInt64) -> Data {
        if value == 0 { return tlv(tag: 0x02, content: Data([0x00])) }
        var v = value
        var bytes: [UInt8] = []
        while v > 0 {
            bytes.insert(UInt8(v & 0xFF), at: 0)
            v >>= 8
        }
        if let first = bytes.first, first & 0x80 != 0 {
            bytes.insert(0x00, at: 0)
        }
        return tlv(tag: 0x02, content: Data(bytes))
    }

    public static func octetString(_ data: Data) -> Data {
        tlv(tag: 0x04, content: data)
    }

    public static func null() -> Data {
        Data([0x05, 0x00])
    }

    public static func oid(_ dotted: String) -> Data {
        let parts = dotted.split(separator: ".").compactMap { UInt64($0) }
        precondition(parts.count >= 2, "Invalid OID: \(dotted)")
        var body = Data([UInt8(parts[0] * 40 + parts[1])])
        for component in parts.dropFirst(2) {
            body.append(encodeBase128(component))
        }
        return tlv(tag: 0x06, content: body)
    }

    public static func utcTime(_ date: Date) -> Data {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyMMddHHmmss'Z'"
        return tlv(tag: 0x17, content: Data(formatter.string(from: date).utf8))
    }

    private static func encodeBase128(_ value: UInt64) -> Data {
        if value == 0 { return Data([0x00]) }
        var v = value
        var bytes: [UInt8] = []
        while v > 0 {
            bytes.insert(UInt8(v & 0x7F), at: 0)
            v >>= 7
        }
        for i in 0..<(bytes.count - 1) {
            bytes[i] |= 0x80
        }
        return Data(bytes)
    }

    // MARK: - XNU CoreTrust CMS SignedData Builder (0xfade0b01)

    /// Builds a strict definite-length DER CMS `ContentInfo(SignedData)` structure
    /// with Apple's exact 5 `signedAttrs` and ZERO RFC 6211 `cmsAlgorithmProtect` attribute.
    public static func buildCoreTrustCMS(
        primaryCodeDirectory: Data,
        sha1CDHash: Data,
        sha256CDHash: Data,
        certificateChainDER: [Data],
        issuerDER: Data,
        serialNumberDER: Data,
        signRSASHA256: (Data) throws -> Data,
        signingDate: Date = Date()
    ) throws -> Data {
        let oidSignedData = oid("1.2.840.113549.1.7.2")
        let oidData = oid("1.2.840.113549.1.7.1")
        let oidSHA256 = oid("2.16.840.1.101.3.4.2.1")
        let oidRSAEncryption = oid("1.2.840.113549.1.1.1")

        let sha256AlgId = sequence([oidSHA256, null()])
        let rsaAlgId = sequence([oidRSAEncryption, null()])

        // 1. contentType (1.2.840.113549.1.9.3)
        let attrContentType = sequence([
            oid("1.2.840.113549.1.9.3"),
            set([oidData])
        ])

        // 2. signingTime (1.2.840.113549.1.9.5)
        let attrSigningTime = sequence([
            oid("1.2.840.113549.1.9.5"),
            set([utcTime(signingDate)])
        ])

        // 3. messageDigest (1.2.840.113549.1.9.4) = SHA-256 of primary CodeDirectory
        let cdMessageDigest = Data(SHA256.hash(data: primaryCodeDirectory))
        let attrMessageDigest = sequence([
            oid("1.2.840.113549.1.9.4"),
            set([octetString(cdMessageDigest)])
        ])

        // 4. Apple CDHashes XML plist (1.2.840.113635.100.9.1) — 20-byte truncated SHA-1 & SHA-256 CDHashes
        let cdHashesPlist = try PlistCodec.encodeXML([
            "cdhashes": [sha1CDHash.prefix(20), sha256CDHash.prefix(20)]
        ])
        let attrAppleCDHashes = sequence([
            oid("1.2.840.113635.100.9.1"),
            set([octetString(cdHashesPlist)])
        ])

        // 5. Apple CDHashes2 DER sequence (1.2.840.113635.100.9.2)
        let cdHash2Entry = sequence([
            oidSHA256,
            octetString(sha256CDHash)
        ])
        let attrAppleCDHashes2 = sequence([
            oid("1.2.840.113635.100.9.2"),
            set([cdHash2Entry])
        ])

        // Exact 5 attributes — cmsAlgorithmProtect (1.2.840.113549.1.9.52) deliberately OMITTED
        let exactFiveAttrs = [
            attrContentType,
            attrSigningTime,
            attrMessageDigest,
            attrAppleCDHashes,
            attrAppleCDHashes2
        ]

        // Sign the DER SET (`0x31`) encoding of signedAttrs per RFC 5652 §5.4
        let signedAttrsForSigning = set(exactFiveAttrs)
        let rawSignature = try signRSASHA256(signedAttrsForSigning)

        // Encode IMPLICIT [0] SET (`0xA0`) inside SignerInfo using the same sorted attribute bytes
        let sortedAttrsBody = exactFiveAttrs.sorted { $0.lexicographicallyPrecedes($1) }.reduce(Data(), +)
        let signedAttrsImplicit0 = contextSpecific(tagNumber: 0, constructed: true, content: sortedAttrsBody)

        let issuerAndSerial = sequence([issuerDER, serialNumberDER])
        let signerInfo = sequence([
            integer(1),                 // version = 1
            issuerAndSerial,            // sid = IssuerAndSerialNumber
            sha256AlgId,                // digestAlgorithm
            signedAttrsImplicit0,       // [0] IMPLICIT signedAttrs (exact 5 attributes)
            rsaAlgId,                   // signatureAlgorithm
            octetString(rawSignature)   // signature
        ])

        let encapContentInfo = sequence([oidData]) // detached signature (no eContent)
        let certsBlock = contextSpecific(tagNumber: 0, constructed: true, content: certificateChainDER.reduce(Data(), +))

        let signedData = sequence([
            integer(1),                 // SignedData version = 1
            set([sha256AlgId]),         // digestAlgorithms
            encapContentInfo,           // encapContentInfo (detached)
            certsBlock,                 // [0] IMPLICIT certificates (Leaf + WWDR G1-G6 intermediate)
            set([signerInfo])           // signerInfos
        ])

        // Top-level ContentInfo wrapping SignedData in EXPLICIT [0]
        return sequence([
            oidSignedData,
            contextSpecific(tagNumber: 0, constructed: true, content: signedData)
        ])
    }
}
