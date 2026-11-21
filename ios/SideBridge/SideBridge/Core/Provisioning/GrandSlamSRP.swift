import Foundation
import CryptoKit
import CommonCrypto

/// Apple GrandSlam (`gsa.apple.com/grandslam/GsService2/lookup`) SRP-6a authenticator.
/// Implements `s2k` / `s2k_fo` PBKDF2-HMAC-SHA256 password derivation, 2048-bit RFC 5054
/// modular exponentiation via OpenSSL `BIGNUM`, 2FA trusted-device / SMS code submission,
/// and AES-256-GCM decryption of the `com.apple.gs.xcode.auth` service token.
public final class GrandSlamSRP: @unchecked Sendable {
    public static let gsaEndpoint = URL(string: "https://gsa.apple.com/grandslam/GsService2")!
    public static let xcodeServiceKey = "com.apple.gs.xcode.auth"

    // RFC 5054 2048-bit SRP-6a prime N and generator g=2
    private static let srpPrimeNHex =
        "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
        "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
        "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
        "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" +
        "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748" +
        "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6" +
        "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
        "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"

    public enum AuthResult: Sendable {
        case authenticated(dsid: String, adsid: String, xcodeAuthToken: String)
        case twoFactorRequired(TwoFactorChallenge)
    }

    public struct TwoFactorChallenge: Sendable {
        public let appleId: String
        public let dsid: String
        public let idmsToken: String
        public let sessionKey: Data
        public let headers: [String: String]
    }

    private let anisette: AnisetteClient
    private let session: URLSession

    public init(anisette: AnisetteClient = AnisetteClient(), session: URLSession = .shared) {
        self.anisette = anisette
        self.session = session
    }

    public func authenticate(appleId: String, password: String) async throws -> AuthResult {
        let headers = try await anisette.mintHeaders()

        // Step 1: Generate ephemeral client secret `a` and public `A = g^a mod N`
        let (aHex, ABytes) = try generateClientKeypair()

        // Step 2: Init request (`s2k` + `s2k_fo`)
        let initRequest: [String: Any] = [
            "Header": ["Version": "1.0.1"],
            "Request": [
                "A2k": ABytes,
                "ps": ["s2k", "s2k_fo"],
                "u": appleId,
                "o": "init",
                "cpd": headers
            ]
        ]

        let initResp = try await postGSA(body: initRequest, headers: headers)
        guard let responseDict = initResp["Response"] as? [String: Any] else {
            throw GrandSlamError.malformedResponse("Missing Response dictionary in SRP init")
        }
        try checkStatus(responseDict)

        guard
            let salt = responseDict["s"] as? Data,
            let BBytes = responseDict["B"] as? Data,
            let cToken = responseDict["c"] as? String,
            let iterations = (responseDict["i"] as? NSNumber)?.intValue,
            let sp = responseDict["sp"] as? String
        else {
            throw GrandSlamError.malformedResponse("Missing SRP challenge parameters (s, B, c, i, sp)")
        }

        // Step 3: Derive password key (`s2k` or `s2k_fo`) via PBKDF2-HMAC-SHA256
        let passwordKey = try derivePasswordKey(password: password, salt: salt, iterations: iterations, protocolMode: sp)

        // Step 4: Compute shared secret K and client proof M1
        let (sessionKeyK, clientProofM1) = try computeSRPProof(
            appleId: appleId,
            passwordKey: passwordKey,
            salt: salt,
            aHex: aHex,
            ABytes: ABytes,
            BBytes: BBytes
        )

        // Step 5: Complete SRP exchange
        let completeRequest: [String: Any] = [
            "Header": ["Version": "1.0.1"],
            "Request": [
                "M1": clientProofM1,
                "c": cToken,
                "u": appleId,
                "o": "complete",
                "cpd": headers
            ]
        ]

        let completeResp = try await postGSA(body: completeRequest, headers: headers)
        guard let compDict = completeResp["Response"] as? [String: Any] else {
            throw GrandSlamError.malformedResponse("Missing Response in SRP complete")
        }

        let statusDict = compDict["Status"] as? [String: Any]
        let authType = statusDict?["au"] as? String
        let statusCode = (statusDict?["ec"] as? NSNumber)?.intValue ?? 0

        guard let spdEncrypted = compDict["spd"] as? Data else {
            if statusCode != 0 {
                let msg = (statusDict?["em"] as? String) ?? "Apple ID authentication failed (\(statusCode))."
                throw GrandSlamError.appleError(code: statusCode, message: msg)
            }
            throw GrandSlamError.malformedResponse("Missing encrypted spd blob")
        }

        let spdPlist = try decryptSPD(encryptedSPD: spdEncrypted, sessionKey: sessionKeyK)
        let dsid = (spdPlist["dsid"] as? String) ?? ""
        let adsid = (spdPlist["adsid"] as? String) ?? ""
        let idmsToken = (spdPlist["GsIdmsToken"] as? String) ?? ""

        if authType == "trustedDeviceSecondaryAuth" || authType == "secondaryAuth" {
            let challenge = TwoFactorChallenge(
                appleId: appleId,
                dsid: dsid,
                idmsToken: idmsToken,
                sessionKey: sessionKeyK,
                headers: headers
            )
            return .twoFactorRequired(challenge)
        }

        let xcodeToken = try await fetchXcodeAppToken(
            appleId: appleId,
            adsid: adsid,
            idmsToken: idmsToken,
            sessionKey: sessionKeyK,
            headers: headers
        )
        return .authenticated(dsid: dsid, adsid: adsid, xcodeAuthToken: xcodeToken)
    }

    /// Submits a 6-digit trusted-device or SMS 2FA verification code and fetches `com.apple.gs.xcode.auth`.
    public func submitTwoFactorCode(
        _ code: String,
        challenge: TwoFactorChallenge
    ) async throws -> (dsid: String, adsid: String, xcodeAuthToken: String) {
        let verifyURL = URL(string: "https://gsa.apple.com/auth/verify/trusteddevice")!
        var req = URLRequest(url: verifyURL)
        req.httpMethod = "GET"
        for (k, v) in challenge.headers {
            req.setValue(v, forHTTPHeaderField: k)
        }
        let identityToken = Data("\(challenge.dsid):\(challenge.idmsToken)".utf8).base64EncodedString()
        req.setValue(identityToken, forHTTPHeaderField: "X-Apple-Identity-Token")
        req.setValue(code.trimmingCharacters(in: .whitespacesAndNewlines), forHTTPHeaderField: "security-code")
        req.setValue("application/x-plist", forHTTPHeaderField: "Accept")

        let (_, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw GrandSlamError.twoFactorRejected
        }

        let token = try await fetchXcodeAppToken(
            appleId: challenge.appleId,
            adsid: challenge.dsid,
            idmsToken: challenge.idmsToken,
            sessionKey: challenge.sessionKey,
            headers: challenge.headers
        )
        return (challenge.dsid, challenge.dsid, token)
    }

    // MARK: - App Token & AES-256-GCM Decryption

    private func fetchXcodeAppToken(
        appleId: String,
        adsid: String,
        idmsToken: String,
        sessionKey: Data,
        headers: [String: String]
    ) async throws -> String {
        let checksumKey = hmacSHA256(key: sessionKey, data: Data("apptokens".utf8))
        var checksumInput = Data("apptokens".utf8)
        checksumInput.append(Data(adsid.utf8))
        checksumInput.append(Data(Self.xcodeServiceKey.utf8))
        let checksum = hmacSHA256(key: checksumKey, data: checksumInput)

        let body: [String: Any] = [
            "Header": ["Version": "1.0.1"],
            "Request": [
                "u": adsid,
                "o": "apptokens",
                "app": [Self.xcodeServiceKey],
                "t": idmsToken,
                "c": checksum,
                "cpd": headers
            ]
        ]

        let resp = try await postGSA(body: body, headers: headers)
        guard let respDict = resp["Response"] as? [String: Any] else {
            throw GrandSlamError.malformedResponse("Missing Response in apptokens")
        }
        try checkStatus(respDict)

        guard let encryptedTokens = respDict["et"] as? Data else {
            throw GrandSlamError.malformedResponse("Missing encrypted app tokens (et)")
        }

        let decrypted = try decryptAppTokensAESGCM(encryptedTokens: encryptedTokens, sessionKey: sessionKey)
        guard
            let tokensMap = decrypted["t"] as? [String: Any],
            let xcodeEntry = tokensMap[Self.xcodeServiceKey] as? [String: Any],
            let tokenString = xcodeEntry["token"] as? String
        else {
            throw GrandSlamError.malformedResponse("Missing com.apple.gs.xcode.auth token in decrypted payload")
        }
        return tokenString
    }

    /// Decrypts GrandSlam `et` app-token envelope using AES-256-GCM (3-byte version header, 16-byte IV, ciphertext, 16-byte tag).
    public func decryptAppTokensAESGCM(encryptedTokens: Data, sessionKey: Data) throws -> [String: Any] {
        guard encryptedTokens.count > 3 + 16 + 16 else {
            throw GrandSlamError.decryptionFailed("Encrypted app token blob too short")
        }
        let header = encryptedTokens.prefix(3)
        let iv = encryptedTokens.subdata(in: 3..<19)
        let tagStart = encryptedTokens.count - 16
        let ciphertext = encryptedTokens.subdata(in: 19..<tagStart)
        let tag = encryptedTokens.subdata(in: tagStart..<encryptedTokens.count)

        let derivedKey = hmacSHA256(key: sessionKey, data: Data("apptokens".utf8))
        let symmetricKey = SymmetricKey(data: derivedKey)
        let nonce = try AES.GCM.Nonce(data: iv)
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        let plaintext = try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: header)
        return try PlistCodec.decodeDictionary(plaintext)
    }

    private func decryptSPD(encryptedSPD: Data, sessionKey: Data) throws -> [String: Any] {
        let key = hmacSHA256(key: sessionKey, data: Data("extra data key:".utf8))
        let iv = hmacSHA256(key: sessionKey, data: Data("extra data iv:".utf8)).prefix(16)
        let decrypted = try aes256CBCDecrypt(ciphertext: encryptedSPD, key: key, iv: Data(iv))
        return try PlistCodec.decodeDictionary(decrypted)
    }

    // MARK: - Crypto Primitives (s2k / s2k_fo + SRP-6a BigNum)

    public func derivePasswordKey(password: String, salt: Data, iterations: Int, protocolMode: String) throws -> Data {
        let sha256 = Data(SHA256.hash(data: Data(password.utf8)))
        let input: Data
        if protocolMode == "s2k_fo" {
            // s2k_fo encodes raw SHA-256 digest as lowercase hex ASCII bytes before PBKDF2
            let hexString = sha256.map { String(format: "%02x", $0) }.joined()
            input = Data(hexString.utf8)
        } else {
            input = sha256
        }

        var derived = [UInt8](repeating: 0, count: 32)
        let status = input.withUnsafeBytes { passPtr in
            salt.withUnsafeBytes { saltPtr in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passPtr.baseAddress?.assumingMemoryBound(to: Int8.self),
                    input.count,
                    saltPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    UInt32(iterations),
                    &derived,
                    derived.count
                )
            }
        }
        guard status == kCCSuccess else {
            throw GrandSlamError.cryptoFailure("PBKDF2-HMAC-SHA256 failed (\(status))")
        }
        return Data(derived)
    }

    private func generateClientKeypair() throws -> (aHex: String, ABytes: Data) {
        var randomBytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes) == errSecSuccess else {
            throw GrandSlamError.cryptoFailure("SecRandomCopyBytes failed")
        }
        let aHex = randomBytes.map { String(format: "%02x", $0) }.joined()

        guard
            let ctx = BN_CTX_new(),
            let N = bnFromHex(Self.srpPrimeNHex),
            let g = BN_new(),
            let a = bnFromHex(aHex),
            let A = BN_new()
        else {
            throw GrandSlamError.cryptoFailure("OpenSSL BN allocation failed")
        }
        defer { BN_CTX_free(ctx); BN_free(N); BN_free(g); BN_free(a); BN_free(A) }

        BN_set_word(g, 2)
        BN_mod_exp(A, g, a, N, ctx)
        return (aHex, bnToPaddedData(A, length: 256))
    }

    private func computeSRPProof(
        appleId: String,
        passwordKey: Data,
        salt: Data,
        aHex: String,
        ABytes: Data,
        BBytes: Data
    ) throws -> (sessionKey: Data, clientProof: Data) {
        guard
            let ctx = BN_CTX_new(),
            let N = bnFromHex(Self.srpPrimeNHex),
            let g = BN_new(),
            let a = bnFromHex(aHex),
            let B = bnFromData(BBytes)
        else {
            throw GrandSlamError.cryptoFailure("SRP BN setup failed")
        }
        defer { BN_CTX_free(ctx); BN_free(N); BN_free(g); BN_free(a); BN_free(B) }
        BN_set_word(g, 2)

        let NBytes = bnToPaddedData(N, length: 256)
        let gPadded = bnToPaddedData(g, length: 256)
        let kHash = Data(SHA256.hash(data: NBytes + gPadded))
        let uHash = Data(SHA256.hash(data: ABytes + BBytes))

        let innerHash = Data(SHA256.hash(data: Data(":".utf8) + passwordKey))
        let xHash = Data(SHA256.hash(data: salt + innerHash))

        guard
            let k = bnFromData(kHash),
            let u = bnFromData(uHash),
            let x = bnFromData(xHash),
            let gx = BN_new(),
            let kgx = BN_new(),
            let base = BN_new(),
            let ux = BN_new(),
            let exp = BN_new(),
            let S = BN_new()
        else {
            throw GrandSlamError.cryptoFailure("SRP intermediate BN alloc failed")
        }
        defer {
            BN_free(k); BN_free(u); BN_free(x); BN_free(gx); BN_free(kgx)
            BN_free(base); BN_free(ux); BN_free(exp); BN_free(S)
        }

        // S = (B - k * g^x)^(a + u * x) mod N
        BN_mod_exp(gx, g, x, N, ctx)
        BN_mod_mul(kgx, k, gx, N, ctx)
        BN_mod_sub(base, B, kgx, N, ctx)
        BN_mul(ux, u, x, ctx)
        BN_add(exp, a, ux)
        BN_mod_exp(S, base, exp, N, ctx)

        let SBytes = bnToPaddedData(S, length: 256)
        let sessionKeyK = Data(SHA256.hash(data: SBytes))

        // M1 = H(H(N) XOR H(g) | H(I) | s | A | B | K)
        let hN = Array(SHA256.hash(data: NBytes))
        let hG = Array(SHA256.hash(data: Data([2])))
        var xorNG = Data(count: 32)
        for i in 0..<32 { xorNG[i] = hN[i] ^ hG[i] }
        let hI = Data(SHA256.hash(data: Data(appleId.utf8)))
        let M1 = Data(SHA256.hash(data: xorNG + hI + salt + ABytes + BBytes + sessionKeyK))

        return (sessionKeyK, M1)
    }

    private func postGSA(body: [String: Any], headers: [String: String]) async throws -> [String: Any] {
        var req = URLRequest(url: Self.gsaEndpoint)
        req.httpMethod = "POST"
        req.setValue("text/x-xml-plist", forHTTPHeaderField: "Content-Type")
        req.setValue("*/*", forHTTPHeaderField: "Accept")
        req.setValue("akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0", forHTTPHeaderField: "User-Agent")
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        req.httpBody = try PlistCodec.encodeXML(body)

        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw GrandSlamError.httpError((response as? HTTPURLResponse)?.statusCode ?? -1)
        }
        return try PlistCodec.decodeDictionary(data)
    }

    private func checkStatus(_ dict: [String: Any]) throws {
        guard let status = dict["Status"] as? [String: Any] else { return }
        let code = (status["ec"] as? NSNumber)?.intValue ?? 0
        if code != 0 {
            let msg = (status["em"] as? String) ?? "Apple GSA error \(code)"
            throw GrandSlamError.appleError(code: code, message: msg)
        }
    }

    private func hmacSHA256(key: Data, data: Data) -> Data {
        let mac = HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key))
        return Data(mac)
    }

    private func aes256CBCDecrypt(ciphertext: Data, key: Data, iv: Data) throws -> Data {
        var outLength: size_t = 0
        var outBuffer = [UInt8](repeating: 0, count: ciphertext.count + kCCBlockSizeAES128)
        let status = ciphertext.withUnsafeBytes { ctPtr in
            key.withUnsafeBytes { keyPtr in
                iv.withUnsafeBytes { ivPtr in
                    CCCrypt(
                        CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyPtr.baseAddress, key.count,
                        ivPtr.baseAddress,
                        ctPtr.baseAddress, ciphertext.count,
                        &outBuffer, outBuffer.count,
                        &outLength
                    )
                }
            }
        }
        guard status == kCCSuccess else {
            throw GrandSlamError.decryptionFailed("AES-256-CBC decrypt failed (\(status))")
        }
        return Data(outBuffer.prefix(outLength))
    }

    private func bnFromHex(_ hex: String) -> OpaquePointer? {
        var bn: OpaquePointer?
        BN_hex2bn(&bn, hex)
        return bn
    }

    private func bnFromData(_ data: Data) -> OpaquePointer? {
        data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return nil }
            return BN_bin2bn(base, Int32(data.count), nil)
        }
    }

    private func bnToPaddedData(_ bn: OpaquePointer, length: Int) -> Data {
        var out = [UInt8](repeating: 0, count: length)
        BN_bn2binpad(bn, &out, Int32(length))
        return Data(out)
    }
}

public enum GrandSlamError: LocalizedError {
    case httpError(Int)
    case malformedResponse(String)
    case appleError(code: Int, message: String)
    case twoFactorRejected
    case decryptionFailed(String)
    case cryptoFailure(String)

    public var errorDescription: String? {
        switch self {
        case .httpError(let code): return "GrandSlam HTTP request failed with status \(code)."
        case .malformedResponse(let msg): return msg
        case .appleError(_, let msg): return msg
        case .twoFactorRejected: return "Invalid or expired 2FA verification code."
        case .decryptionFailed(let msg): return "GrandSlam decryption failed: \(msg)"
        case .cryptoFailure(let msg): return msg
        }
    }
}
