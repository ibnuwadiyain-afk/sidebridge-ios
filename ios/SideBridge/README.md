# SideBridge for iOS & iPadOS (Swift 5.9+, iOS 16.0+, arm64)

Native iOS and iPadOS port of the SideBridge signing and sideloading engine. Supports:
1. **Same-Device Loopback Sideloading** via the bundled `SideBridgeTunnel` (`NEPacketTunnelProvider`) local loopback VPN routing `10.7.0.1` to host `lockdownd` (`62078`).
2. **Wi-Fi Peer Sideloading** via Bonjour (`_apple-mobdev2._tcp`) with automatic port translation from Apple's byte-swapped mDNS placeholder `32498` (`0x7EF2`) to `62078` (`0xF27E`).
3. **USB-C / OTG Peer Sideloading** via Apple USB Ethernet / NCM / tethered interfaces (`en*`, `bridge*`, `169.254.x.x`, `172.20.10.x`) probing TCP `62078`, plus a pluggable `DeviceTransport` protocol for raw `usbmux` on unsandboxed builds.

## Building with XcodeGen

```bash
brew install xcodegen
cd SideBridge
xcodegen generate
open SideBridge.xcodeproj
```

### Signing & Capabilities Setup
1. Select your **Development Team** on both `SideBridge` (`com.sidebridge.ios`) and `SideBridgeTunnel` (`com.sidebridge.ios.tunnel`).
2. Ensure **App Groups** (`group.com.sidebridge.shared`), **Keychain Sharing**, and **Personal VPN / Network Extensions (Packet Tunnel)** are enabled for your bundle identifiers.
3. Wait for Swift Package Manager to resolve `ZIPFoundation` and `OpenSSL` (BoringSSL/OpenSSL 3 XCFramework).
4. Build and run on a physical `arm64` iPhone or iPad running iOS 16.0+.

## First-Time Device Setup
1. Generate a `.mobiledevicepairing` file for your target device (or "This Device") using JitterbugPair, `idevicepair`, or an Android SideBridge export.
2. Import the pairing file inside **SideBridge -> Setup Wizard** (or **Devices**).
3. Enable the **Local Loopback VPN** (`SideBridgeTunnel`) when sideloading onto the same device.
4. Enable **Settings -> Privacy & Security -> Developer Mode** on iOS 16+.
5. After installing an app signed with a Free Personal Team certificate, trust the profile in **Settings -> General -> VPN & Device Management**.

## Automated GitHub Actions IPA Build & Release
This repository includes `.github/workflows/build-ipa-release.yml` to compile `SideBridge.app` + `PlugIns/SideBridgeTunnel.appex` on `macos-15` and publish the `.ipa` + `SHA256SUMS.txt` directly to **GitHub Releases**.

- **Trigger automatically**: Push a semantic tag (`git tag v1.0.0 && git push origin v1.0.0`).
- **Trigger manually**: Go to **Actions -> Build iOS IPA & Publish GitHub Release -> Run workflow**.
- **Unsigned Sideload Mode (Default, zero secrets)**: Works out of the box and publishes `SideBridge-<tag>-unsigned.ipa` ready for SideStore, AltStore, Sideloadly, TrollStore, or SideBridge.
- **Signed Release Mode (Optional)**: Configure repository secrets `IOS_DIST_CERT_P12_BASE64`, `IOS_DIST_CERT_PASSWORD`, `IOS_APP_PROVISION_BASE64`, `IOS_TUNNEL_PROVISION_BASE64`, and optionally `IOS_EXPORT_METHOD` (`ad-hoc`, `enterprise`, or `development`). The workflow automatically detects these secrets, imports them into an ephemeral macOS keychain, exports a signed `.ipa`, and cleans up all signing material.
