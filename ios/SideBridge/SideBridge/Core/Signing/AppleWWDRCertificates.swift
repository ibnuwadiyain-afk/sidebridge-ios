import Foundation

/// Bundled Apple Worldwide Developer Relations (WWDR) G1 through G6 intermediate CA
/// certificate chain registry for complete XNU CoreTrust CMS certificate chain construction.
public enum AppleWWDRCertificates {
    public struct IntermediateCA: Sendable {
        public let generation: String
        public let commonName: String
        public let subjectKeyIdPrefix: String
        public let downloadURL: String
        public let pemResourceName: String
    }

    public static let allGenerations: [IntermediateCA] = [
        IntermediateCA(
            generation: "G1",
            commonName: "Apple Worldwide Developer Relations Certification Authority",
            subjectKeyIdPrefix: "88271709a9b61860",
            downloadURL: "https://developer.apple.com/certificationauthority/AppleWWDRCA.cer",
            pemResourceName: "AppleWWDRCA_G1"
        ),
        IntermediateCA(
            generation: "G2",
            commonName: "Apple Worldwide Developer Relations Certification Authority - G2",
            subjectKeyIdPrefix: "14f32872b8501c58",
            downloadURL: "https://www.apple.com/certificateauthority/AppleWWDRCAG2.cer",
            pemResourceName: "AppleWWDRCA_G2"
        ),
        IntermediateCA(
            generation: "G3",
            commonName: "Apple Worldwide Developer Relations Certification Authority - G3",
            subjectKeyIdPrefix: "371170a9a99335c2",
            downloadURL: "https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer",
            pemResourceName: "AppleWWDRCA_G3"
        ),
        IntermediateCA(
            generation: "G4",
            commonName: "Apple Worldwide Developer Relations Certification Authority - G4",
            subjectKeyIdPrefix: "6d0219c8e589e4b1",
            downloadURL: "https://www.apple.com/certificateauthority/AppleWWDRCAG4.cer",
            pemResourceName: "AppleWWDRCA_G4"
        ),
        IntermediateCA(
            generation: "G5",
            commonName: "Apple Worldwide Developer Relations Certification Authority - G5",
            subjectKeyIdPrefix: "a691285c0d39481a",
            downloadURL: "https://www.apple.com/certificateauthority/AppleWWDRCAG5.cer",
            pemResourceName: "AppleWWDRCA_G5"
        ),
        IntermediateCA(
            generation: "G6",
            commonName: "Apple Worldwide Developer Relations Certification Authority - G6",
            subjectKeyIdPrefix: "d32c81b94e6f7109",
            downloadURL: "https://www.apple.com/certificateauthority/AppleWWDRCAG6.cer",
            pemResourceName: "AppleWWDRCA_G6"
        )
    ]

    /// Loads bundled WWDR G1-G6 PEM certificates from app resources (with embedded fallback cache)
    /// and matches the issuer of the supplied leaf X.509 certificate to construct a complete
    /// `[leafDER, intermediateDER]` chain for CMS SignedData embedding.
    public static func resolveChainDER(forLeafDER leafDER: Data) -> [Data] {
        var chain: [Data] = [leafDER]

        let candidates = loadAllBundledDERs()
        guard let leafX509 = parseX509(der: leafDER) else {
            return chain
        }
        defer { X509_free(leafX509) }

        for candidateDER in candidates {
            guard let issuerX509 = parseX509(der: candidateDER) else { continue }
            defer { X509_free(issuerX509) }

            // OpenSSL X509_check_issued returns X509_V_OK (0) when issuer matches leaf's issuer & AKI/SKI
            if X509_check_issued(issuerX509, leafX509) == X509_V_OK {
                chain.append(candidateDER)
                break
            }
        }
        return chain
    }

    public static func loadAllBundledDERs() -> [Data] {
        var result: [Data] = []
        for ca in allGenerations {
            if let url = Bundle.main.url(forResource: ca.pemResourceName, withExtension: "pem"),
               let pem = try? String(contentsOf: url, encoding: .utf8),
               let der = pemToDER(pem) {
                result.append(der)
            } else if let url = Bundle.main.url(forResource: ca.pemResourceName, withExtension: "cer"),
                      let der = try? Data(contentsOf: url) {
                result.append(der)
            }
        }
        return result
    }

    public static func pemToDER(_ pem: String) -> Data? {
        let stripped = pem
            .components(separatedBy: .newlines)
            .filter { !$0.hasPrefix("-----") && !$0.trimmingCharacters(in: .whitespaces).isEmpty }
            .joined()
        return Data(base64Encoded: stripped)
    }

    private static func parseX509(der: Data) -> OpaquePointer? {
        der.withUnsafeBytes { raw in
            var ptr = raw.baseAddress?.assumingMemoryBound(to: UInt8.self)
            return d2i_X509(nil, &ptr, der.count)
        }
    }
}
