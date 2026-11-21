import Foundation

/// Apple File Conduit (`com.apple.afc`) binary packet client using `CFA6LPAA` 40-byte framing.
/// Streams signed `.ipa` archives in 32KB–64KB chunks to `PublicStaging/<bundleId>.ipa`.
public final class AfcClient: @unchecked Sendable {
    private static let magic: [UInt8] = Array("CFA6LPAA".utf8) // 8 bytes
    private static let headerSize = 40

    private enum Operation: UInt64 {
        case status = 0x00000001
        case data = 0x00000002
        case makeDir = 0x00000009
        case fileRefOpen = 0x0000000D
        case fileRefOpenResult = 0x0000000E
        case fileRefWrite = 0x00000010
        case fileRefClose = 0x00000014
    }

    private enum OpenMode: UInt64 {
        case wrOnly = 0x00000003 // create/truncate write-only
    }

    private let transport: DeviceTransport
    private var nextPacketNumber: UInt64 = 1
    private let logger: (@Sendable (LogCategory, String, Bool) -> Void)?

    public init(
        transport: DeviceTransport,
        logger: (@Sendable (LogCategory, String, Bool) -> Void)? = nil
    ) {
        self.transport = transport
        self.logger = logger
    }

    public func makeDirectory(_ path: String) async throws {
        var headerPayload = Data(path.utf8)
        headerPayload.append(0) // NUL-terminated C string
        let response = try await sendPacket(operation: .makeDir, headerPayload: headerPayload, bodyPayload: Data())
        // Status 0 (OK) or 7 (OBJECT_EXISTS) are both valid for PublicStaging
        if response.statusCode != 0 && response.statusCode != 7 {
            throw AfcError.statusFailed(operation: "MakeDir(\(path))", code: response.statusCode)
        }
        logger?(.afc, "Ensured staging directory \(path) (status=\(response.statusCode))", false)
    }

    public func openFileForWrite(_ path: String) async throws -> UInt64 {
        var modeLE = OpenMode.wrOnly.rawValue.littleEndian
        var headerPayload = Data(bytes: &modeLE, count: 8)
        headerPayload.append(Data(path.utf8))
        headerPayload.append(0)

        let response = try await sendPacket(operation: .fileRefOpen, headerPayload: headerPayload, bodyPayload: Data())
        guard response.operation == Operation.fileRefOpenResult.rawValue, response.headerPayload.count >= 8 else {
            throw AfcError.statusFailed(operation: "FileRefOpen(\(path))", code: response.statusCode)
        }
        let handle = response.headerPayload.withUnsafeBytes { $0.loadUnaligned(as: UInt64.self).littleEndian }
        return handle
    }

    public func writeChunk(handle: UInt64, data: Data) async throws {
        var handleLE = handle.littleEndian
        let headerPayload = Data(bytes: &handleLE, count: 8)
        let response = try await sendPacket(operation: .fileRefWrite, headerPayload: headerPayload, bodyPayload: data)
        guard response.statusCode == 0 else {
            throw AfcError.statusFailed(operation: "FileRefWrite", code: response.statusCode)
        }
    }

    public func closeFile(handle: UInt64) async throws {
        var handleLE = handle.littleEndian
        let headerPayload = Data(bytes: &handleLE, count: 8)
        let response = try await sendPacket(operation: .fileRefClose, headerPayload: headerPayload, bodyPayload: Data())
        guard response.statusCode == 0 else {
            throw AfcError.statusFailed(operation: "FileRefClose", code: response.statusCode)
        }
    }

    /// Streams a signed IPA from disk to `PublicStaging/<bundleId>.ipa` in 64KB chunks.
    public func uploadIPA(
        fileURL: URL,
        bundleIdentifier: String,
        chunkSize: Int = 65_536,
        progress: @Sendable (Double, Int64, Int64) -> Void
    ) async throws -> String {
        let clampedChunk = min(max(chunkSize, 32_768), 65_536)
        let remotePath = "PublicStaging/\(bundleIdentifier).ipa"

        let attrs = try FileManager.default.attributesOfItem(atPath: fileURL.path)
        let totalBytes = (attrs[.size] as? NSNumber)?.int64Value ?? 0
        guard totalBytes > 0 else {
            throw AfcError.emptyFile(fileURL.lastPathComponent)
        }

        try await makeDirectory("PublicStaging")
        let handle = try await openFileForWrite(remotePath)
        logger?(.afc, "Streaming \(totalBytes) bytes -> \(remotePath) in \(clampedChunk / 1024)KB CFA6LPAA chunks", false)

        let fileHandle = try FileHandle(forReadingFrom: fileURL)
        defer {
            try? fileHandle.close()
        }

        var uploaded: Int64 = 0
        var lastLoggedDecile = -1

        do {
            while uploaded < totalBytes {
                try Task.checkCancellation()
                guard let chunk = try fileHandle.read(upToCount: clampedChunk), !chunk.isEmpty else {
                    break
                }
                try await writeChunk(handle: handle, data: chunk)
                uploaded += Int64(chunk.count)

                let fraction = min(1.0, Double(uploaded) / Double(totalBytes))
                progress(fraction, uploaded, totalBytes)

                let decile = Int(fraction * 10)
                if decile > lastLoggedDecile && (decile % 2 == 0 || decile == 10) {
                    lastLoggedDecile = decile
                    logger?(.afc, "Uploaded \(uploaded / 1024)KB / \(totalBytes / 1024)KB (\(Int(fraction * 100))%)", false)
                }
            }
            try await closeFile(handle: handle)
        } catch {
            _ = try? await closeFile(handle: handle)
            throw error
        }

        return remotePath
    }

    public func close() {
        transport.close()
    }

    // MARK: - Binary Packet Framing (CFA6LPAA)

    private struct AfcResponse {
        let operation: UInt64
        let headerPayload: Data
        let bodyPayload: Data

        var statusCode: UInt64 {
            guard operation == Operation.status.rawValue, headerPayload.count >= 8 else { return 0 }
            return headerPayload.withUnsafeBytes { $0.loadUnaligned(as: UInt64.self).littleEndian }
        }
    }

    private func sendPacket(
        operation: Operation,
        headerPayload: Data,
        bodyPayload: Data
    ) async throws -> AfcResponse {
        let packetNumber = nextPacketNumber
        nextPacketNumber += 1

        let thisLength = UInt64(Self.headerSize + headerPayload.count)
        let entireLength = thisLength + UInt64(bodyPayload.count)

        var frame = Data()
        frame.reserveCapacity(Int(entireLength))
        frame.append(contentsOf: Self.magic)
        appendUInt64LE(entireLength, to: &frame)
        appendUInt64LE(thisLength, to: &frame)
        appendUInt64LE(packetNumber, to: &frame)
        appendUInt64LE(operation.rawValue, to: &frame)
        frame.append(headerPayload)
        frame.append(bodyPayload)

        try await transport.send(frame)
        return try await receivePacket()
    }

    private func receivePacket() async throws -> AfcResponse {
        let header = try await transport.receiveExact(Self.headerSize, timeout: 30.0)
        guard Array(header.prefix(8)) == Self.magic else {
            throw AfcError.invalidMagic
        }

        let entireLength = readUInt64LE(header, offset: 8)
        let thisLength = readUInt64LE(header, offset: 16)
        let operation = readUInt64LE(header, offset: 32)

        guard thisLength >= UInt64(Self.headerSize), entireLength >= thisLength else {
            throw AfcError.malformedPacket
        }

        let headerPayloadLen = Int(thisLength) - Self.headerSize
        let bodyPayloadLen = Int(entireLength - thisLength)

        let headerPayload = headerPayloadLen > 0
            ? try await transport.receiveExact(headerPayloadLen, timeout: 30.0)
            : Data()
        let bodyPayload = bodyPayloadLen > 0
            ? try await transport.receiveExact(bodyPayloadLen, timeout: 30.0)
            : Data()

        return AfcResponse(operation: operation, headerPayload: headerPayload, bodyPayload: bodyPayload)
    }

    private func appendUInt64LE(_ value: UInt64, to data: inout Data) {
        var le = value.littleEndian
        data.append(Data(bytes: &le, count: 8))
    }

    private func readUInt64LE(_ data: Data, offset: Int) -> UInt64 {
        data.withUnsafeBytes { raw in
            raw.loadUnaligned(fromByteOffset: offset, as: UInt64.self).littleEndian
        }
    }
}

public enum AfcError: LocalizedError {
    case invalidMagic
    case malformedPacket
    case emptyFile(String)
    case statusFailed(operation: String, code: UInt64)

    public var errorDescription: String? {
        switch self {
        case .invalidMagic: return "AFC packet header did not start with CFA6LPAA magic."
        case .malformedPacket: return "Received malformed AFC packet lengths."
        case .emptyFile(let name): return "Cannot upload empty IPA file: \(name)"
        case .statusFailed(let op, let code): return "AFC \(op) failed with status code \(code)."
        }
    }
}
