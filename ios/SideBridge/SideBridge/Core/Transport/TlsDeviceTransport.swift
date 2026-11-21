import Foundation

/// In-memory OpenSSL/BoringSSL BIO TLS 1.2 transport (`SSL_new` + `BIO_s_mem()`).
/// Uses the `PairingRecord`'s `HostCertificate`, `HostPrivateKey`, and `RootCertificate`
/// directly, bypassing Apple's `SecTrust` rejections on self-signed `lockdownd` certificates.
public final class TlsDeviceTransport: DeviceTransport, @unchecked Sendable {
    private let underlying: DeviceTransport
    private var sslCtx: OpaquePointer?
    private var ssl: OpaquePointer?
    private var readBio: OpaquePointer?
    private var writeBio: OpaquePointer?
    private let sslLock = NSLock()

    public init(underlying: DeviceTransport, pairingRecord: PairingRecord) throws {
        self.underlying = underlying

        guard let ctx = SSL_CTX_new(TLS_client_method()) else {
            throw TransportError.tlsHandshakeFailed("SSL_CTX_new failed")
        }
        self.sslCtx = ctx

        // Strictly pin TLS 1.2 for Apple lockdownd compatibility across iOS 16-18+
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)
        SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION)
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nil)

        try loadCredentials(into: ctx, pairingRecord: pairingRecord)

        guard let sslPtr = SSL_new(ctx) else {
            SSL_CTX_free(ctx)
            self.sslCtx = nil
            throw TransportError.tlsHandshakeFailed("SSL_new failed")
        }

        let rbio = BIO_new(BIO_s_mem())
        let wbio = BIO_new(BIO_s_mem())
        guard let rbio, let wbio else {
            SSL_free(sslPtr)
            SSL_CTX_free(ctx)
            throw TransportError.tlsHandshakeFailed("BIO_s_mem allocation failed")
        }

        // SSL takes ownership of rbio and wbio
        SSL_set_bio(sslPtr, rbio, wbio)
        SSL_set_connect_state(sslPtr)

        self.ssl = sslPtr
        self.readBio = rbio
        self.writeBio = wbio
    }

    deinit {
        close()
    }

    /// Executes the non-blocking TLS 1.2 handshake over the underlying `DeviceTransport`.
    public func handshake(timeout: TimeInterval = 10.0) async throws {
        let deadline = Date().addingTimeInterval(timeout)

        while true {
            if deadline.timeIntervalSinceNow <= 0 {
                throw TransportError.timeout
            }

            let stepResult: (done: Bool, needsRead: Bool, pendingWrite: Data) = try {
                sslLock.lock()
                defer { sslLock.unlock() }
                guard let ssl else { throw TransportError.connectionClosed }

                let ret = SSL_do_handshake(ssl)
                let outgoing = drainWriteBioLocked()

                if ret == 1 {
                    return (true, false, outgoing)
                }

                let err = SSL_get_error(ssl, ret)
                if err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE {
                    return (false, err == SSL_ERROR_WANT_READ, outgoing)
                }

                throw TransportError.tlsHandshakeFailed(Self.lastOpenSSLError())
            }()

            if !stepResult.pendingWrite.isEmpty {
                try await underlying.send(stepResult.pendingWrite)
            }
            if stepResult.done {
                return
            }
            if stepResult.needsRead {
                let remaining = max(0.5, deadline.timeIntervalSinceNow)
                let incoming = try await underlying.receive(maxLength: 16_384, timeout: remaining)
                if incoming.isEmpty {
                    throw TransportError.connectionClosed
                }
                feedReadBio(incoming)
            }
        }
    }

    public func send(_ data: Data) async throws {
        guard !data.isEmpty else { return }
        var offset = 0

        while offset < data.count {
            let chunkResult: (written: Int, encryptedOut: Data) = try {
                sslLock.lock()
                defer { sslLock.unlock() }
                guard let ssl else { throw TransportError.connectionClosed }

                let written = data.withUnsafeBytes { rawBuf -> Int32 in
                    guard let base = rawBuf.baseAddress else { return 0 }
                    return SSL_write(ssl, base.advanced(by: offset), Int32(data.count - offset))
                }
                let out = drainWriteBioLocked()
                if written <= 0 {
                    let err = SSL_get_error(ssl, written)
                    if err != SSL_ERROR_WANT_WRITE && err != SSL_ERROR_WANT_READ {
                        throw TransportError.sendFailed("SSL_write error \(err): \(Self.lastOpenSSLError())")
                    }
                    return (0, out)
                }
                return (Int(written), out)
            }()

            if !chunkResult.encryptedOut.isEmpty {
                try await underlying.send(chunkResult.encryptedOut)
            }
            offset += chunkResult.written
        }
    }

    public func receive(maxLength: Int, timeout: TimeInterval) async throws -> Data {
        let deadline = Date().addingTimeInterval(timeout)

        while true {
            if deadline.timeIntervalSinceNow <= 0 {
                throw TransportError.timeout
            }

            let readAttempt: (plaintext: Data?, pendingWrite: Data) = try {
                sslLock.lock()
                defer { sslLock.unlock() }
                guard let ssl else { throw TransportError.connectionClosed }

                var buf = [UInt8](repeating: 0, count: max(1, maxLength))
                let n = SSL_read(ssl, &buf, Int32(buf.count))
                let out = drainWriteBioLocked()

                if n > 0 {
                    return (Data(buf[0..<Int(n)]), out)
                }
                let err = SSL_get_error(ssl, n)
                if err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE {
                    return (nil, out)
                }
                if err == SSL_ERROR_ZERO_RETURN {
                    throw TransportError.connectionClosed
                }
                throw TransportError.receiveFailed("SSL_read error \(err): \(Self.lastOpenSSLError())")
            }()

            if !readAttempt.pendingWrite.isEmpty {
                try await underlying.send(readAttempt.pendingWrite)
            }
            if let plaintext = readAttempt.plaintext {
                return plaintext
            }

            let remaining = max(0.25, deadline.timeIntervalSinceNow)
            let ciphertext = try await underlying.receive(maxLength: 32_768, timeout: remaining)
            if ciphertext.isEmpty {
                throw TransportError.connectionClosed
            }
            feedReadBio(ciphertext)
        }
    }

    public func close() {
        sslLock.lock()
        if let ssl {
            SSL_shutdown(ssl)
            SSL_free(ssl)
            self.ssl = nil
            self.readBio = nil
            self.writeBio = nil
        }
        if let sslCtx {
            SSL_CTX_free(sslCtx)
            self.sslCtx = nil
        }
        sslLock.unlock()
        underlying.close()
    }

    // MARK: - OpenSSL Credential & BIO Helpers

    private func loadCredentials(into ctx: OpaquePointer, pairingRecord: PairingRecord) throws {
        // Load HostCertificate
        guard let hostCert = parseX509(pem: pairingRecord.hostCertificatePem) else {
            throw TransportError.invalidCredential("Failed to parse HostCertificate PEM")
        }
        defer { X509_free(hostCert) }
        guard SSL_CTX_use_certificate(ctx, hostCert) == 1 else {
            throw TransportError.invalidCredential("SSL_CTX_use_certificate failed: \(Self.lastOpenSSLError())")
        }

        // Load HostPrivateKey
        guard let hostKey = parsePrivateKey(pem: pairingRecord.hostPrivateKeyPem) else {
            throw TransportError.invalidCredential("Failed to parse HostPrivateKey PEM")
        }
        defer { EVP_PKEY_free(hostKey) }
        guard SSL_CTX_use_PrivateKey(ctx, hostKey) == 1 else {
            throw TransportError.invalidCredential("SSL_CTX_use_PrivateKey failed: \(Self.lastOpenSSLError())")
        }

        // Attach RootCertificate as extra chain cert & trust store anchor
        if let rootCert = parseX509(pem: pairingRecord.rootCertificatePem) {
            if let store = SSL_CTX_get_cert_store(ctx) {
                X509_STORE_add_cert(store, rootCert)
            }
            SSL_CTX_add_extra_chain_cert(ctx, rootCert)
        }
    }

    private func parseX509(pem: String) -> OpaquePointer? {
        guard let bio = BIO_new_mem_buf(pem, Int32(pem.utf8.count)) else { return nil }
        defer { BIO_free(bio) }
        return PEM_read_bio_X509(bio, nil, nil, nil)
    }

    private func parsePrivateKey(pem: String) -> OpaquePointer? {
        guard let bio = BIO_new_mem_buf(pem, Int32(pem.utf8.count)) else { return nil }
        defer { BIO_free(bio) }
        return PEM_read_bio_PrivateKey(bio, nil, nil, nil)
    }

    private func feedReadBio(_ data: Data) {
        sslLock.lock()
        defer { sslLock.unlock() }
        guard let readBio else { return }
        data.withUnsafeBytes { rawBuf in
            guard let base = rawBuf.baseAddress else { return }
            _ = BIO_write(readBio, base, Int32(data.count))
        }
    }

    private func drainWriteBioLocked() -> Data {
        guard let writeBio else { return Data() }
        var output = Data()
        var chunk = [UInt8](repeating: 0, count: 16_384)
        while true {
            let pending = BIO_ctrl_pending(writeBio)
            if pending <= 0 { break }
            let n = BIO_read(writeBio, &chunk, Int32(min(Int(pending), chunk.count)))
            if n <= 0 { break }
            output.append(contentsOf: chunk[0..<Int(n)])
        }
        return output
    }

    private static func lastOpenSSLError() -> String {
        let code = ERR_get_error()
        guard code != 0 else { return "Unknown OpenSSL error" }
        var buf = [CChar](repeating: 0, count: 256)
        ERR_error_string_n(code, &buf, buf.count)
        return String(cString: buf)
    }
}
