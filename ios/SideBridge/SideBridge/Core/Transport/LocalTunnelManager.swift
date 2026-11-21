import Foundation
import NetworkExtension
import Combine

/// Manages the lifecycle of the `SideBridgeTunnel` (`NEPacketTunnelProvider`) loopback VPN
/// used to route `10.7.0.1:62078` back to the host device's `lockdownd` for same-device sideloading.
@MainActor
public final class LocalTunnelManager: ObservableObject {
    public static let shared = LocalTunnelManager()
    public static let tunnelBundleIdentifier = "com.sidebridge.ios.tunnel"
    public static let loopbackLockdownHost = "10.7.0.1"
    public static let loopbackLockdownPort: UInt16 = 62078

    @Published public private(set) var status: NEVPNStatus = .disconnected
    @Published public private(set) var lastErrorMessage: String?

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?

    public init() {
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let session = notification.object as? NEVPNConnection else { return }
            Task { @MainActor in
                self?.status = session.status
            }
        }
    }

    deinit {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
    }

    public var isConnected: Bool {
        status == .connected
    }

    public func loadOrCreateConfiguration() async throws -> NETunnelProviderManager {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        if let existing = managers.first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.tunnelBundleIdentifier
        }) {
            self.manager = existing
            self.status = existing.connection.status
            return existing
        }

        let newManager = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.tunnelBundleIdentifier
        proto.serverAddress = Self.loopbackLockdownHost
        proto.disconnectOnSleep = false

        newManager.protocolConfiguration = proto
        newManager.localizedDescription = "SideBridge Local Loopback"
        newManager.isEnabled = true

        try await newManager.saveToPreferences()
        try await newManager.loadFromPreferences()

        self.manager = newManager
        self.status = newManager.connection.status
        return newManager
    }

    public func startLoopbackTunnel() async throws {
        lastErrorMessage = nil
        do {
            let mgr = try await loadOrCreateConfiguration()
            if !mgr.isEnabled {
                mgr.isEnabled = true
                try await mgr.saveToPreferences()
                try await mgr.loadFromPreferences()
            }
            try mgr.connection.startVPNTunnel()
            self.status = mgr.connection.status
        } catch {
            lastErrorMessage = error.localizedDescription
            throw error
        }
    }

    public func stopLoopbackTunnel() {
        manager?.connection.stopVPNTunnel()
        status = manager?.connection.status ?? .disconnected
    }

    /// Polls until the loopback tunnel reaches `.connected` or times out.
    public func ensureConnected(timeout: TimeInterval = 8.0) async throws {
        if status != .connected {
            try await startLoopbackTunnel()
        }
        let deadline = Date().addingTimeInterval(timeout)
        while status != .connected {
            if Date() > deadline {
                throw TransportError.connectFailed("Local Loopback VPN tunnel did not connect within \(Int(timeout))s.")
            }
            try await Task.sleep(nanoseconds: 150_000_000)
        }
    }
}
