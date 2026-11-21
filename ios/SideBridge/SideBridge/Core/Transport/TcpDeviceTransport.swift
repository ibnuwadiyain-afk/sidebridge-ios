import Foundation
import Darwin

/// Non-blocking POSIX TCP transport with `TCP_NODELAY` and `SO_KEEPALIVE`.
/// Used for same-device Loopback VPN (`10.7.0.1:62078`), Wi-Fi Bonjour (`:62078`),
/// and USB-C / OTG Ethernet interfaces (`169.254.x.x:62078`, `172.20.10.x:62078`).
public final class TcpDeviceTransport: DeviceTransport, @unchecked Sendable {
    public let host: String
    public let port: UInt16

    private var fd: Int32 = -1
    private let ioQueue = DispatchQueue(label: "com.sidebridge.tcp.io", qos: .userInitiated)
    private let stateLock = NSLock()

    public init(host: String, port: UInt16 = 62078) {
        self.host = host
        self.port = port
    }

    deinit {
        close()
    }

    public func connect(timeout: TimeInterval = 8.0) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            ioQueue.async {
                do {
                    try self.connectBlocking(timeout: timeout)
                    continuation.resume()
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    public func send(_ data: Data) async throws {
        guard !data.isEmpty else { return }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            ioQueue.async {
                do {
                    try self.sendBlocking(data, timeout: 15.0)
                    continuation.resume()
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    public func receive(maxLength: Int, timeout: TimeInterval) async throws -> Data {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            ioQueue.async {
                do {
                    let result = try self.receiveBlocking(maxLength: maxLength, timeout: timeout)
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    public func close() {
        stateLock.lock()
        let currentFd = fd
        fd = -1
        stateLock.unlock()
        if currentFd >= 0 {
            Darwin.shutdown(currentFd, SHUT_RDWR)
            Darwin.close(currentFd)
        }
    }

    // MARK: - POSIX Implementation

    private func connectBlocking(timeout: TimeInterval) throws {
        var hints = addrinfo(
            ai_flags: 0,
            ai_family: AF_UNSPEC,
            ai_socktype: SOCK_STREAM,
            ai_protocol: IPPROTO_TCP,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )
        var res: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, String(port), &hints, &res)
        guard status == 0, let head = res else {
            let errMsg = String(cString: gai_strerror(status))
            throw TransportError.connectFailed("DNS/address resolution failed for \(host):\(port) — \(errMsg)")
        }
        defer { freeaddrinfo(head) }

        var lastError = "Unable to connect to \(host):\(port)"
        var ptr: UnsafeMutablePointer<addrinfo>? = head

        while let info = ptr {
            let sock = Darwin.socket(info.pointee.ai_family, info.pointee.ai_socktype, info.pointee.ai_protocol)
            if sock < 0 {
                ptr = info.pointee.ai_next
                continue
            }

            // Configure non-blocking + TCP_NODELAY + SO_KEEPALIVE + SO_NOSIGPIPE
            var one: Int32 = 1
            setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, socklen_t(MemoryLayout<Int32>.size))
            setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &one, socklen_t(MemoryLayout<Int32>.size))
            setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))

            let flags = fcntl(sock, F_GETFL, 0)
            _ = fcntl(sock, F_SETFL, flags | O_NONBLOCK)

            let connectResult = Darwin.connect(sock, info.pointee.ai_addr, info.pointee.ai_addrlen)
            if connectResult == 0 {
                setFileDescriptor(sock)
                return
            }

            if errno == EINPROGRESS {
                var pfd = pollfd(fd: sock, events: Int16(POLLOUT), revents: 0)
                let pollMs = Int32(max(100, timeout * 1000))
                let pollResult = Darwin.poll(&pfd, 1, pollMs)
                if pollResult > 0 {
                    var soError: Int32 = 0
                    var soLen = socklen_t(MemoryLayout<Int32>.size)
                    getsockopt(sock, SOL_SOCKET, SO_ERROR, &soError, &soLen)
                    if soError == 0 {
                        setFileDescriptor(sock)
                        return
                    }
                    lastError = String(cString: strerror(soError))
                } else if pollResult == 0 {
                    lastError = "Connection timed out after \(String(format: "%.1f", timeout))s"
                } else {
                    lastError = String(cString: strerror(errno))
                }
            } else {
                lastError = String(cString: strerror(errno))
            }

            Darwin.close(sock)
            ptr = info.pointee.ai_next
        }

        throw TransportError.connectFailed(lastError)
    }

    private func sendBlocking(_ data: Data, timeout: TimeInterval) throws {
        let sock = currentFileDescriptor()
        guard sock >= 0 else { throw TransportError.connectionClosed }

        let deadline = Date().addingTimeInterval(timeout)
        var totalSent = 0

        try data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return }
            while totalSent < data.count {
                let remainingMs = Int32(max(1, deadline.timeIntervalSinceNow * 1000))
                if remainingMs <= 0 { throw TransportError.timeout }

                var pfd = pollfd(fd: sock, events: Int16(POLLOUT), revents: 0)
                let ready = Darwin.poll(&pfd, 1, remainingMs)
                if ready == 0 { throw TransportError.timeout }
                if ready < 0 {
                    if errno == EINTR { continue }
                    throw TransportError.sendFailed(String(cString: strerror(errno)))
                }

                let sent = Darwin.send(sock, base.advanced(by: totalSent), data.count - totalSent, 0)
                if sent > 0 {
                    totalSent += sent
                } else if sent == 0 {
                    throw TransportError.connectionClosed
                } else if errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR {
                    continue
                } else {
                    throw TransportError.sendFailed(String(cString: strerror(errno)))
                }
            }
        }
    }

    private func receiveBlocking(maxLength: Int, timeout: TimeInterval) throws -> Data {
        let sock = currentFileDescriptor()
        guard sock >= 0 else { throw TransportError.connectionClosed }

        let deadline = Date().addingTimeInterval(timeout)
        var buffer = [UInt8](repeating: 0, count: max(1, maxLength))

        while true {
            let remainingMs = Int32(max(1, deadline.timeIntervalSinceNow * 1000))
            if deadline.timeIntervalSinceNow <= 0 {
                throw TransportError.timeout
            }

            var pfd = pollfd(fd: sock, events: Int16(POLLIN), revents: 0)
            let ready = Darwin.poll(&pfd, 1, remainingMs)
            if ready == 0 {
                throw TransportError.timeout
            }
            if ready < 0 {
                if errno == EINTR { continue }
                throw TransportError.receiveFailed(String(cString: strerror(errno)))
            }

            let count = Darwin.recv(sock, &buffer, buffer.count, 0)
            if count > 0 {
                return Data(buffer[0..<count])
            } else if count == 0 {
                throw TransportError.connectionClosed
            } else if errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR {
                continue
            } else {
                throw TransportError.receiveFailed(String(cString: strerror(errno)))
            }
        }
    }

    private func setFileDescriptor(_ newFd: Int32) {
        stateLock.lock()
        fd = newFd
        stateLock.unlock()
    }

    private func currentFileDescriptor() -> Int32 {
        stateLock.lock()
        defer { stateLock.unlock() }
        return fd
    }
}
