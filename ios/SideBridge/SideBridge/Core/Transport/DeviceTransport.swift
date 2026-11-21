import Foundation

/// Abstract transport interface shared across TCP (Wi-Fi / Loopback VPN / USB Ethernet),
/// OpenSSL TLS 1.2 BIO tunnels, and pluggable raw USB `usbmux` builds.
public protocol DeviceTransport: AnyObject, Sendable {
    func send(_ data: Data) async throws
    func receive(maxLength: Int, timeout: TimeInterval) async throws -> Data
    func receiveExact(_ length: Int, timeout: TimeInterval) async throws -> Data
    func close()
}

public extension DeviceTransport {
    func receiveExact(_ length: Int, timeout: TimeInterval) async throws -> Data {
        guard length > 0 else { return Data() }
        var buffer = Data()
        buffer.reserveCapacity(length)
        let deadline = Date().addingTimeInterval(timeout)

        while buffer.count < length {
            let remaining = deadline.timeIntervalSinceNow
            if remaining <= 0 {
                throw TransportError.timeout
            }
            let chunk = try await receive(maxLength: length - buffer.count, timeout: remaining)
            if chunk.isEmpty {
                throw TransportError.connectionClosed
            }
            buffer.append(chunk)
        }
        return buffer
    }
}

public enum TransportError: LocalizedError {
    case connectFailed(String)
    case timeout
    case connectionClosed
    case sendFailed(String)
    case receiveFailed(String)
    case tlsHandshakeFailed(String)
    case invalidCredential(String)
    case unsupportedInSandbox(String)

    public var errorDescription: String? {
        switch self {
        case .connectFailed(let detail): return "TCP connect failed: \(detail)"
        case .timeout: return "Transport I/O timed out."
        case .connectionClosed: return "Remote device closed the connection."
        case .sendFailed(let detail): return "Transport send failed: \(detail)"
        case .receiveFailed(let detail): return "Transport receive failed: \(detail)"
        case .tlsHandshakeFailed(let detail): return "OpenSSL TLS 1.2 handshake failed: \(detail)"
        case .invalidCredential(let detail): return "Invalid pairing credential: \(detail)"
        case .unsupportedInSandbox(let detail): return detail
        }
    }
}

/// Extension point for unsandboxed / jailbroken builds that connect directly to
/// `/var/run/usbmuxd` or raw USB bulk endpoints via IOKit.
public final class RawUsbmuxDeviceTransport: DeviceTransport, @unchecked Sendable {
    private let socketPath: String

    public init(socketPath: String = "/var/run/usbmuxd") {
        self.socketPath = socketPath
    }

    public func send(_ data: Data) async throws {
        throw TransportError.unsupportedInSandbox(
            "Raw usbmux (\(socketPath)) requires an unsandboxed/jailbroken entitlement. Use USB-C Ethernet/OTG TCP 62078 on stock iOS."
        )
    }

    public func receive(maxLength: Int, timeout: TimeInterval) async throws -> Data {
        throw TransportError.unsupportedInSandbox(
            "Raw usbmux (\(socketPath)) requires an unsandboxed/jailbroken entitlement."
        )
    }

    public func close() {}
}
