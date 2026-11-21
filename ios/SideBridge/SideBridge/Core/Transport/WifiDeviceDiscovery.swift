import Foundation
import Network

/// Discovers remote iOS / iPadOS devices on the local Wi-Fi network via Bonjour `_apple-mobdev2._tcp`.
/// CRITICAL: Maps Apple's byte-swapped mDNS placeholder port `32498` (`0x7EF2`)
/// to the real `lockdownd` TCP port `62078` (`0xF27E`).
public final class WifiDeviceDiscovery: @unchecked Sendable {
    public static let bonjourServiceType = "_apple-mobdev2._tcp"
    public static let appleSwappedPlaceholderPort: UInt16 = 32498 // 0x7EF2
    public static let realLockdownPort: UInt16 = 62078           // 0xF27E

    private var browser: NWBrowser?
    private let queue = DispatchQueue(label: "com.sidebridge.wifi.discovery", qos: .utility)
    private var resolvedDevices: [String: DiscoveredDevice] = [:]
    private let lock = NSLock()
    private var onDevicesUpdated: (([DiscoveredDevice]) -> Void)?

    public init() {}

    /// Translates Apple's byte-swapped mDNS port 32498 (0x7EF2) to 62078 (0xF27E).
    public static func normalizeLockdownPort(_ advertisedPort: UInt16) -> UInt16 {
        if advertisedPort == appleSwappedPlaceholderPort || advertisedPort == 0 {
            return realLockdownPort
        }
        return advertisedPort
    }

    public func start(onUpdate: @escaping ([DiscoveredDevice]) -> Void) {
        stop()
        self.onDevicesUpdated = onUpdate

        let parameters = NWParameters()
        parameters.includePeerToPeer = true
        let descriptor = NWBrowser.Descriptor.bonjour(type: Self.bonjourServiceType, domain: "local.")
        let browser = NWBrowser(for: descriptor, using: parameters)

        browser.browseResultsChangedHandler = { [weak self] results, _ in
            self?.handleBrowseResults(results)
        }

        browser.stateUpdateHandler = { _ in }
        browser.start(queue: queue)
        self.browser = browser
    }

    public func stop() {
        browser?.cancel()
        browser = nil
        lock.lock()
        resolvedDevices.removeAll()
        lock.unlock()
    }

    private func handleBrowseResults(_ results: Set<NWBrowser.Result>) {
        for result in results {
            guard case .service(let name, _, _, _) = result.endpoint else { continue }
            resolveEndpoint(result.endpoint, serviceName: name)
        }
    }

    private func resolveEndpoint(_ endpoint: NWEndpoint, serviceName: String) {
        let connection = NWConnection(to: endpoint, using: .tcp)
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                if let remoteEndpoint = connection.currentPath?.remoteEndpoint,
                   case .hostPort(let host, let port) = remoteEndpoint {
                    let hostString = Self.cleanHostString(host)
                    let realPort = Self.normalizeLockdownPort(port.rawValue)
                    self.recordResolvedDevice(serviceName: serviceName, host: hostString, port: realPort)
                }
                connection.cancel()
            case .failed, .cancelled:
                connection.cancel()
            default:
                break
            }
        }
        connection.start(queue: queue)

        // Ensure short resolution timeout
        queue.asyncAfter(deadline: .now() + 3.0) {
            if connection.state != .cancelled {
                connection.cancel()
            }
        }
    }

    private func recordResolvedDevice(serviceName: String, host: String, port: UInt16) {
        let id = "wifi:\(host):\(port)"
        let pairingRecords = PairingStorage.shared.allRecords()
        let matched = pairingRecords.first { record in
            if let wifi = record.wifiAddress?.lowercased(), serviceName.lowercased().contains(wifi) {
                return true
            }
            return false
        }

        let device = DiscoveredDevice(
            id: id,
            udid: matched?.udid,
            name: matched?.deviceName ?? serviceName,
            host: host,
            port: port,
            interfaceName: "en0",
            connectionKind: .wifiBonjour,
            hasPairingRecord: matched != nil,
            lastSeen: Date()
        )

        lock.lock()
        resolvedDevices[id] = device
        let snapshot = Array(resolvedDevices.values).sorted { $0.name < $1.name }
        lock.unlock()

        onDevicesUpdated?(snapshot)
    }

    private static func cleanHostString(_ host: NWEndpoint.Host) -> String {
        switch host {
        case .ipv4(let ipv4):
            return ipv4.debugDescription.components(separatedBy: "%").first ?? ipv4.debugDescription
        case .ipv6(let ipv6):
            return ipv6.debugDescription
        case .name(let name, _):
            return name
        @unknown default:
            return host.debugDescription
        }
    }
}
