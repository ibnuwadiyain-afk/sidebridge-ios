import Foundation
import NetworkExtension
import os.log

/// Local-only loopback VPN provider (no external server).
/// Routes virtual subnet 10.7.0.0/24 so connections from the sandboxed SideBridge app
/// to the virtual host address (10.7.0.1:62078) are reflected back onto the local device's
/// Wi-Fi/loopback interface where `lockdownd` listens on TCP port 62078.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    static let virtualInterfaceAddress = "10.7.0.1"
    static let virtualPeerAddress = "10.7.0.2"
    static let virtualSubnetMask = "255.255.255.0"
    static let tunnelRemoteAddress = "10.7.0.254"

    private let log = OSLog(subsystem: "com.sidebridge.ios.tunnel", category: "LoopbackVPN")
    private var isRunning = false
    private let packetQueue = DispatchQueue(label: "com.sidebridge.tunnel.packets", qos: .userInitiated)

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        os_log("Starting SideBridge local loopback tunnel on %{public}@", log: log, type: .info, Self.virtualInterfaceAddress)

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: Self.tunnelRemoteAddress)
        settings.mtu = 1500

        let ipv4 = NEIPv4Settings(
            addresses: [Self.virtualInterfaceAddress],
            subnetMasks: [Self.virtualSubnetMask]
        )
        // Route ONLY the private virtual /24 subnet; never capture normal internet traffic.
        let loopbackRoute = NEIPv4Route(
            destinationAddress: "10.7.0.0",
            subnetMask: Self.virtualSubnetMask
        )
        ipv4.includedRoutes = [loopbackRoute]
        ipv4.excludedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else {
                completionHandler(error)
                return
            }
            if let error {
                os_log("Failed to apply loopback tunnel settings: %{public}@", log: self.log, type: .error, error.localizedDescription)
                completionHandler(error)
                return
            }
            self.isRunning = true
            self.persistTunnelStatus(active: true)
            self.readPacketsLoop()
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log("Stopping SideBridge loopback tunnel (reason: %d)", log: log, type: .info, reason.rawValue)
        isRunning = false
        persistTunnelStatus(active: false)
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let status: [String: Any] = [
            "active": isRunning,
            "virtualIP": Self.virtualInterfaceAddress,
            "peerIP": Self.virtualPeerAddress,
            "lockdownPort": 62078
        ]
        let payload = try? JSONSerialization.data(withJSONObject: status)
        completionHandler?(payload)
    }

    /// Reads IPv4 packets routed into utun for 10.7.0.x, swaps source/destination IPv4 addresses
    /// (10.7.0.1 <-> 10.7.0.2), recomputes IPv4 + TCP/UDP checksums, and writes them back to the
    /// packetFlow so the kernel delivers traffic to the local host stack's `lockdownd` listener.
    private func readPacketsLoop() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self, self.isRunning else { return }

            self.packetQueue.async {
                var reflectedPackets: [Data] = []
                var reflectedProtocols: [NSNumber] = []
                reflectedPackets.reserveCapacity(packets.count)
                reflectedProtocols.reserveCapacity(packets.count)

                for (index, packet) in packets.enumerated() {
                    let proto = protocols[index]
                    if proto.int32Value == AF_INET, let reflected = Self.reflectIPv4LoopbackPacket(packet) {
                        reflectedPackets.append(reflected)
                        reflectedProtocols.append(proto)
                    }
                }

                if !reflectedPackets.isEmpty {
                    self.packetFlow.writePackets(reflectedPackets, withProtocols: reflectedProtocols)
                }
                self.readPacketsLoop()
            }
        }
    }

    /// Swaps IPv4 src/dst (10.7.0.1 <-> 10.7.0.2) and recalculates IPv4 header + TCP/UDP transport checksums.
    private static func reflectIPv4LoopbackPacket(_ packet: Data) -> Data? {
        guard packet.count >= 20 else { return nil }
        var bytes = [UInt8](packet)

        let version = bytes[0] >> 4
        guard version == 4 else { return nil }

        let ihl = Int(bytes[0] & 0x0F) * 4
        guard ihl >= 20, bytes.count >= ihl else { return nil }

        // Swap source IP (bytes 12...15) and destination IP (bytes 16...19)
        let srcIP = Array(bytes[12..<16])
        let dstIP = Array(bytes[16..<20])
        bytes[12..<16] = dstIP[...]
        bytes[16..<20] = srcIP[...]

        // Recompute IPv4 header checksum
        bytes[10] = 0
        bytes[11] = 0
        let ipChecksum = onesComplementChecksum(bytes[0..<ihl])
        bytes[10] = UInt8((ipChecksum >> 8) & 0xFF)
        bytes[11] = UInt8(ipChecksum & 0xFF)

        let transportProtocol = bytes[9]
        let payloadLength = bytes.count - ihl

        if transportProtocol == 6 && payloadLength >= 20 {
            // TCP checksum at ihl + 16..17
            bytes[ihl + 16] = 0
            bytes[ihl + 17] = 0
            let tcpChecksum = transportChecksum(
                srcIP: Array(bytes[12..<16]),
                dstIP: Array(bytes[16..<20]),
                proto: 6,
                segment: bytes[ihl..<bytes.count]
            )
            bytes[ihl + 16] = UInt8((tcpChecksum >> 8) & 0xFF)
            bytes[ihl + 17] = UInt8(tcpChecksum & 0xFF)
        } else if transportProtocol == 17 && payloadLength >= 8 {
            // UDP checksum at ihl + 6..7
            bytes[ihl + 6] = 0
            bytes[ihl + 7] = 0
            let udpChecksum = transportChecksum(
                srcIP: Array(bytes[12..<16]),
                dstIP: Array(bytes[16..<20]),
                proto: 17,
                segment: bytes[ihl..<bytes.count]
            )
            bytes[ihl + 6] = UInt8((udpChecksum >> 8) & 0xFF)
            bytes[ihl + 7] = UInt8(udpChecksum & 0xFF)
        }

        return Data(bytes)
    }

    private static func transportChecksum(srcIP: [UInt8], dstIP: [UInt8], proto: UInt8, segment: ArraySlice<UInt8>) -> UInt16 {
        var pseudo = [UInt8]()
        pseudo.reserveCapacity(12 + segment.count)
        pseudo.append(contentsOf: srcIP)
        pseudo.append(contentsOf: dstIP)
        pseudo.append(0)
        pseudo.append(proto)
        let len = UInt16(segment.count)
        pseudo.append(UInt8((len >> 8) & 0xFF))
        pseudo.append(UInt8(len & 0xFF))
        pseudo.append(contentsOf: segment)
        return onesComplementChecksum(pseudo[...])
    }

    private static func onesComplementChecksum(_ data: ArraySlice<UInt8>) -> UInt16 {
        var sum: UInt32 = 0
        var index = data.startIndex
        while index < data.endIndex {
            let high = UInt32(data[index]) << 8
            let next = data.index(after: index)
            let low = next < data.endIndex ? UInt32(data[next]) : 0
            sum &+= (high | low)
            index = next < data.endIndex ? data.index(after: next) : data.endIndex
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        return ~UInt16(sum & 0xFFFF)
    }

    private func persistTunnelStatus(active: Bool) {
        let defaults = UserDefaults(suiteName: "group.com.sidebridge.shared")
        defaults?.set(active, forKey: "sidebridge.tunnel.active")
        defaults?.set(Date().timeIntervalSince1970, forKey: "sidebridge.tunnel.updatedAt")
    }
}
