import React from 'react';
import { ChevronRight, ShieldCheck, Usb, Wifi, Smartphone } from 'lucide-react';

interface ArchitectureViewProps {
  onInspectSwiftFile: (path: string) => void;
}

const TRANSPORT_MODES = [
  {
    title: '01. Same-Device Loopback VPN',
    icon: Smartphone,
    endpoint: '10.7.0.1 -> lockdownd :62078',
    summary:
      'Local-only NEPacketTunnelProvider (SideBridgeTunnel) binds virtual interface 10.7.0.1/24 with no external server, reflects IPv4 packets (10.7.0.1 <-> 10.7.0.2) with recomputed IP/TCP checksums, and unlocks AFC + InstallationProxy on the same iPhone or iPad.',
    file: 'SideBridgeTunnel/PacketTunnelProvider.swift',
  },
  {
    title: '02. Remote Wi-Fi Bonjour',
    icon: Wifi,
    endpoint: '_apple-mobdev2._tcp (32498 -> 62078)',
    summary:
      'NWBrowser discovers peer iOS/iPadOS devices over local Wi-Fi and explicitly translates Apple’s byte-swapped mDNS placeholder port 32498 (0x7EF2) to real lockdownd TCP port 62078 (0xF27E).',
    file: 'SideBridge/Core/Transport/WifiDeviceDiscovery.swift',
  },
  {
    title: '03. USB-C / OTG Peer Ethernet',
    icon: Usb,
    endpoint: 'en* / bridge* / 169.254.x.x / 172.20.10.x :62078',
    summary:
      'NWPathMonitor and getifaddrs() enumerate Apple USB Ethernet/NCM and tethered interfaces, probing TCP 62078 with automatic fallback to Wi-Fi Bonjour. Abstract DeviceTransport also exposes RawUsbmuxDeviceTransport for unsandboxed builds.',
    file: 'SideBridge/Core/Transport/UsbNetworkDiscovery.swift',
  },
];

const CORETRUST_MATRIX = [
  {
    requirement: 'Strict Definite-Length DER CMS (0xfade0b01)',
    implementation: 'DEREncoder.swift encodes every TLV using definite-length ASN.1 DER; zero indefinite-length BER 0x80 tags.',
    file: 'SideBridge/Core/Signing/DEREncoder.swift',
  },
  {
    requirement: 'Omit RFC 6211 cmsAlgorithmProtect (1.2.840.113549.1.9.52)',
    implementation: 'SignerInfo.signedAttrs contains ONLY Apple’s exact 5 attributes: contentType, signingTime, messageDigest, 1.2.840.113635.100.9.1, and 1.2.840.113635.100.9.2.',
    file: 'SideBridge/Core/Signing/DEREncoder.swift',
  },
  {
    requirement: 'Apple WWDR G1 through G6 Intermediate Chain',
    implementation: 'AppleWWDRCertificates resolves issuer-matched G1–G6 intermediate PEMs via OpenSSL X509_check_issued and embeds [leafDER, intermediateDER] in CMS SignedData.',
    file: 'SideBridge/Core/Signing/AppleWWDRCertificates.swift',
  },
  {
    requirement: 'Bottom-Up Nested Frameworks & Untouched bplist00',
    implementation: 'IpaSigner signs nested .framework bundles, .appex plugins, and standalone .dylibs bottom-up before generating _CodeSignature/CodeResources (SHA-1 & SHA-256). Nested .framework/Info.plist remains byte-for-byte untouched unless CFBundleResourceSpecification is present.',
    file: 'SideBridge/Core/Signing/IpaSigner.swift',
  },
  {
    requirement: 'Standalone Mach-O __TEXT,__info_plist Slot -1',
    implementation: 'MachOSigner scans __TEXT segment sections for __info_plist in standalone binaries and hashes it directly into CodeDirectory Special Slot -1.',
    file: 'SideBridge/Core/Signing/MachOSigner.swift',
  },
  {
    requirement: 'STORED Directory Entries & Unix 0755 (0x81ED)',
    implementation: 'repackSignedIPA emits uncompressed STORED directory entries (size = 0, crc = 0) and enforces 0o755 permissions on all arm64/FAT Mach-O executables.',
    file: 'SideBridge/Core/Signing/IpaSigner.swift',
  },
  {
    requirement: 'Active Portal Cert Check & Thumbprint Match',
    implementation: 'AppleDeveloperProvisioner calls listAllDevelopmentCerts before every sign (auto-revoking/re-issuing via RSA-2048 CSR if revoked externally) and confirms .mobileprovision DeveloperCertificates contains the active .p12 SHA-1/SHA-256 thumbprint.',
    file: 'SideBridge/Core/Provisioning/AppleDeveloperProvisioner.swift',
  },
  {
    requirement: 'OpenSSL In-Memory BIO TLS 1.2 Lockdown Upgrade',
    implementation: 'TlsDeviceTransport wraps SSL_new + BIO_s_mem() pinned strictly to TLS1_2_VERSION using PairingRecord HostCertificate, HostPrivateKey, and RootCertificate — avoiding SecTrust rejections on self-signed lockdownd certificates.',
    file: 'SideBridge/Core/Transport/TlsDeviceTransport.swift',
  },
];

export const ArchitectureView: React.FC<ArchitectureViewProps> = ({ onInspectSwiftFile }) => {
  return (
    <div className="mx-auto max-w-[1440px] px-6 py-6 space-y-10">
      {/* Header */}
      <div className="border-b border-slate-800/80 pb-5">
        <h1 className="text-xl font-semibold tracking-tight text-slate-100">
          Target Architecture &amp; XNU CoreTrust Invariants
        </h1>
        <p className="mt-1.5 max-w-3xl text-sm text-slate-400 leading-relaxed">
          1:1 Swift 5.9+ port of Android SideBridge across two Xcode targets (<span className="font-mono text-slate-200">SideBridge</span> +{' '}
          <span className="font-mono text-slate-200">SideBridgeTunnel</span>) sharing{' '}
          <span className="font-mono text-slate-200">group.com.sidebridge.shared</span> and Keychain Access Groups.
        </p>
      </div>

      {/* 3 Transport Pathways */}
      <section className="space-y-4">
        <h2 className="text-base font-semibold text-white">Three Device Transport Pathways</h2>
        <div className="grid grid-cols-1 gap-5 md:grid-cols-3">
          {TRANSPORT_MODES.map((mode) => {
            const Icon = mode.icon;
            return (
              <div
                key={mode.title}
                className="flex flex-col justify-between rounded-xl border border-slate-800 bg-[#11151E] p-5"
              >
                <div>
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-semibold text-white">{mode.title}</h3>
                    <Icon className="h-4 w-4 text-blue-400" />
                  </div>
                  <div className="mt-1.5 font-mono text-xs text-slate-400">{mode.endpoint}</div>
                  <p className="mt-3 text-xs text-slate-300 leading-relaxed">{mode.summary}</p>
                </div>

                <div className="mt-5 border-t border-slate-800/80 pt-3">
                  <button
                    type="button"
                    onClick={() => onInspectSwiftFile(mode.file)}
                    className="inline-flex items-center gap-1 font-mono text-xs text-blue-400 hover:text-blue-300"
                  >
                    <span>{mode.file}</span>
                    <ChevronRight className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* CoreTrust & Protocol Compliance Matrix */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-white">XNU CoreTrust &amp; Protocol Verification Matrix</h2>
            <p className="mt-0.5 text-xs text-slate-400">
              Click any module path to inspect the exact Swift 5.9+ implementation in the Xcode Project explorer.
            </p>
          </div>
          <ShieldCheck className="h-5 w-5 text-emerald-400" />
        </div>

        <div className="overflow-x-auto rounded-xl border border-slate-800 bg-[#11151E]">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-[#0D1017] text-slate-400">
                <th className="px-4 py-3 font-semibold">Critical Invariant</th>
                <th className="px-4 py-3 font-semibold">Swift Implementation Detail</th>
                <th className="px-4 py-3 font-semibold">Source Module</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {CORETRUST_MATRIX.map((row) => (
                <tr key={row.requirement} className="hover:bg-slate-800/20">
                  <td className="px-4 py-3.5 align-top font-medium text-slate-100 whitespace-nowrap">
                    {row.requirement}
                  </td>
                  <td className="px-4 py-3.5 align-top text-slate-300 leading-relaxed max-w-xl">
                    {row.implementation}
                  </td>
                  <td className="px-4 py-3.5 align-top whitespace-nowrap">
                    <button
                      type="button"
                      onClick={() => onInspectSwiftFile(row.file)}
                      className="inline-flex items-center gap-1 font-mono text-blue-400 hover:text-blue-300"
                    >
                      <span>{row.file.split('/').pop()}</span>
                      <ChevronRight className="h-3.5 w-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
