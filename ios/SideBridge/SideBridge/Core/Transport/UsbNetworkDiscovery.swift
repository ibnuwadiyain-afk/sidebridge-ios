import Foundation
import Network
import Darwin

/// Discovers peer iOS / iPadOS devices connected over a USB-C / Lightning OTG cable
/// via Apple USB Ethernet / NCM / tethered interfaces (`en*`, `bridge*`, link-local `169.254.x.x`,
/// and Personal Hotspot `172.20.10.x`) by probing TCP port `62078` with `LockdownClient.queryType()`.
public final class UsbNetworkDiscovery: @unchecked Sendable {
    public static let lockdownPort: UInt16 = 62078

    private var pathMonitor: NWPathMonitor?
    private let queue = DispatchQueue(label: "com.sidebridge.usb.network", qos: .utility)
    private var scanTask: Task<Void, Never>?
    private var onDevicesUpdated: (([DiscoveredDevice]) -> Void)?

    public init() {}

    public func start(onUpdate: @escaping ([DiscoveredDevice]) -> Void) {
        stop()
        self.onDevicesUpdated = onUpdate

        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] _ in
            self?.triggerProbe()
        }
        monitor.start(queue: queue)
        self.pathMonitor = monitor
        triggerProbe()
    }

    public func stop() {
        pathMonitor?.cancel()
        pathMonitor = nil
        scanTask?.cancel()
        scanTask = nil
    }

    public func triggerProbe() {
        scanTask?.cancel()
        scanTask = Task.detached(priority: .utility) { [weak self] in
            guard let self else { return }
            let candidates = Self.enumerateUsbEthernetCandidates()
            var discovered: [DiscoveredDevice] = []

            await withTaskGroup(of: DiscoveredDevice?.self) { group in
                for candidate in candidates {
                    group.addTask {
                        await Self.probeLockdown(host: candidate.peerHost, interfaceName: candidate.interfaceName)
                    }
                }
                for await device in group {
                    if let device {
                        discovered.append(device)
                    }
                }
            }

            if !Task.isCancelled {
                let sorted = discovered.sorted { $0.name < $1.name }
                self.onDevicesUpdated?(sorted)
            }
        }
    }

    struct InterfaceCandidate: Hashable {
        let interfaceName: String
        let localAddress: String
        let peerHost: String
    }

    /// Inspects active interfaces via `getifaddrs()` looking for USB Ethernet / NCM (`en2`..`en9`),
    /// tethered bridges (`bridge*`), link-local `169.254.x.x`, or Apple hotspot `172.20.10.x`.
    static func enumerateUsbEthernetCandidates() -> [InterfaceCandidate] {
        var results = Set<InterfaceCandidate>()
        var ifaddrPtr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddrPtr) == 0, let first = ifaddrPtr else { return [] }
        defer { freeifaddrs(first) }

        var ptr: UnsafeMutablePointer<ifaddrs>? = first
        while let current = ptr {
            let flags = Int32(current.pointee.ifa_flags)
            let isUp = (flags & IFF_UP) != 0 && (flags & IFF_RUNNING) != 0
            let isLoopback = (flags & IFF_LOOPBACK) != 0

            if isUp, !isLoopback, let addr = current.pointee.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET) {
                let name = String(cString: current.pointee.ifa_name)
                var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(addr, socklen_t(addr.pointee.sa_len), &hostname, socklen_t(hostname.count), nil, 0, NI_NUMERICHOST) == 0 {
                    let ip = String(cString: hostname)
                    let isUsbInterface = (name.hasPrefix("en") && name != "en0") || name.hasPrefix("bridge")
                    let isLinkLocal = ip.hasPrefix("169.254.")
                    let isHotspot = ip.hasPrefix("172.20.10.")

                    if isUsbInterface || isLinkLocal || isHotspot {
                        for peer in inferPeerHosts(localIP: ip) {
                            results.insert(InterfaceCandidate(interfaceName: name, localAddress: ip, peerHost: peer))
                        }
                    }
                }
            }
            ptr = current.pointee.ifa_next
        }
        return Array(results)
    }

    private static func inferPeerHosts(localIP: String) -> [String] {
        let parts = localIP.split(separator: ".")
        guard parts.count == 4, let lastOctet = Int(parts[3]) else { return [] }
        let prefix = "\(parts[0]).\(parts[1]).\(parts[2])"

        if localIP.hasPrefix("172.20.10.") {
            // Apple USB tethering gateway is almost always .1; peers occupy .2 - .6
            var peers = ["172.20.10.1", "172.20.10.2", "172.20.10.3", "172.20.10.4"]
            peers.removeAll { $0 == localIP }
            return peers
        }

        // Link-local or point-to-point USB NCM subnet neighbors
        var neighbors: [String] = []
        for candidateOctet in [1, 2, max(1, lastOctet - 1), min(254, lastOctet + 1)] {
            let candidate = "\(prefix).\(candidateOctet)"
            if candidate != localIP && !neighbors.contains(candidate) {
                neighbors.append(candidate)
            }
        }
        return neighbors
    }

    private static func probeLockdown(host: String, interfaceName: String) async -> DiscoveredDevice? {
        let transport = TcpDeviceTransport(host: host, port: lockdownPort)
        defer { transport.close() }
        do {
            try await transport.connect(timeout: 1.5)
            let client = LockdownClient(transport: transport)
            let queryType = try await client.queryType()
            guard queryType == "com.apple.mobile.lockdown" else { return nil }

            let udid = try? await client.getValue(key: "UniqueDeviceID") as? String
            let deviceName = (try? await client.getValue(key: "DeviceName") as? String) ?? "USB Peer (\(host))"
            let productVersion = try? await client.getValue(key: "ProductVersion") as? String
            let paired = udid.flatMap { PairingStorage.shared.record(forUDID: $0) } != nil

            return DiscoveredDevice(
                id: "usb:\(interfaceName):\(host)",
                udid: udid,
                name: deviceName,
                host: host,
                port: lockdownPort,
                interfaceName: interfaceName,
                connectionKind: .usbEthernetOTG,
                productVersion: productVersion,
                hasPairingRecord: paired,
                lastSeen: Date()
            )
        } catch {
            return nil
        }
    }
}
