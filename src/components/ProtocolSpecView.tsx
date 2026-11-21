import React, { useState } from 'react';
import { Check, ChevronRight, Copy, FileCode2, Terminal } from 'lucide-react';

interface ProtocolSpecViewProps {
  onInspectFile: (relativePath: string) => void;
}

export const ProtocolSpecView: React.FC<ProtocolSpecViewProps> = ({ onInspectFile }) => {
  const [selectedFrame, setSelectedFrame] = useState<'lockdown' | 'afc' | 'superblob'>('afc');
  const [copiedCmd, setCopiedCmd] = useState(false);

  const buildCommands = `brew install xcodegen
unzip SideBridge-iOS-Swift59.zip -d SideBridge
cd SideBridge
xcodegen generate
open SideBridge.xcodeproj`;

  const copyCommands = async () => {
    await navigator.clipboard.writeText(buildCommands);
    setCopiedCmd(true);
    window.setTimeout(() => setCopiedCmd(false), 1800);
  };

  return (
    <div className="mx-auto max-w-[1440px] px-6 py-6 space-y-10">
      <div className="border-b border-slate-800/80 pb-5">
        <h1 className="text-xl font-semibold tracking-tight text-slate-100">
          Wire Protocol Layout, Xcode Build &amp; GitHub Actions Release
        </h1>
        <p className="mt-1.5 max-w-3xl text-sm text-slate-400">
          Binary framing reference matching Android SideBridge byte-for-byte, plus local XcodeGen steps and automated GitHub Actions IPA release configuration.
        </p>
      </div>

      {/* Interactive Wire Frame Inspector */}
      <section className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <h2 className="text-base font-semibold text-white">Wire Format &amp; Signature Binary Layouts</h2>
          <div className="flex items-center gap-1 rounded-lg border border-slate-800 bg-[#11151E] p-1">
            {(
              [
                { id: 'lockdown', label: 'Lockdown Plist Frame' },
                { id: 'afc', label: 'AFC CFA6LPAA Header' },
                { id: 'superblob', label: 'Mach-O SuperBlob & CMS' },
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setSelectedFrame(tab.id)}
                className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  selectedFrame === tab.id
                    ? 'bg-slate-800 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#11151E] p-5">
          {selectedFrame === 'lockdown' && (
            <div className="space-y-4">
              <div className="text-xs text-slate-300">
                Used by <span className="font-mono text-white">LockdownClient.swift</span> and{' '}
                <span className="font-mono text-white">InstallationProxyClient.swift</span> over TCP port{' '}
                <span className="font-mono text-white">62078</span> (plain until <span className="font-mono text-white">StartSession</span> upgrades to OpenSSL TLS 1.2 BIO).
              </div>
              <div className="grid grid-cols-1 gap-3 md:grid-cols-3 font-mono text-xs">
                <div className="rounded-lg border border-slate-800 bg-[#0D1017] p-3.5">
                  <div className="text-slate-400">Bytes 0..3 (4B)</div>
                  <div className="mt-1 font-semibold text-blue-400">UInt32 Big-Endian Length</div>
                  <div className="mt-1 text-[11px] text-slate-500">Payload byte count N (max 32 MiB)</div>
                </div>
                <div className="rounded-lg border border-slate-800 bg-[#0D1017] p-3.5 md:col-span-2">
                  <div className="text-slate-400">Bytes 4..(4+N-1)</div>
                  <div className="mt-1 font-semibold text-slate-100">UTF-8 XML Property List (&lt;?xml version=&quot;1.0&quot;...&gt;)</div>
                  <div className="mt-1 text-[11px] text-slate-500">
                    Requests: QueryType, GetValue, StartSession, StartService(&quot;com.apple.afc&quot; / &quot;com.apple.mobile.installation_proxy&quot;)
                  </div>
                </div>
              </div>
            </div>
          )}

          {selectedFrame === 'afc' && (
            <div className="space-y-4">
              <div className="text-xs text-slate-300">
                40-byte little-endian binary packet header implemented in <span className="font-mono text-white">AfcClient.swift</span> streaming 32KB–64KB chunks to{' '}
                <span className="font-mono text-white">PublicStaging/&lt;bundleId&gt;.ipa</span>.
              </div>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5 font-mono text-xs">
                {[
                  { range: '0..7 (8B)', field: 'Magic', value: 'CFA6LPAA' },
                  { range: '8..15 (8B)', field: 'EntireLength', value: 'UInt64 LE (Header+Body)' },
                  { range: '16..23 (8B)', field: 'ThisLength', value: 'UInt64 LE (40 + HdrData)' },
                  { range: '24..31 (8B)', field: 'PacketNumber', value: 'UInt64 LE (Monotonic)' },
                  { range: '32..39 (8B)', field: 'Operation', value: '0x09 MkDir / 0x0D Open / 0x10 Write / 0x14 Close' },
                ].map((cell) => (
                  <div key={cell.field} className="rounded-lg border border-slate-800 bg-[#0D1017] p-3.5">
                    <div className="text-[11px] text-slate-500">{cell.range}</div>
                    <div className="mt-1 font-semibold text-blue-400">{cell.field}</div>
                    <div className="mt-1 text-[11px] text-slate-300">{cell.value}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {selectedFrame === 'superblob' && (
            <div className="space-y-4">
              <div className="text-xs text-slate-300">
                Embedded inside <span className="font-mono text-white">LC_CODE_SIGNATURE</span> by{' '}
                <span className="font-mono text-white">MachOSigner.swift</span> and{' '}
                <span className="font-mono text-white">DEREncoder.swift</span> for XNU CoreTrust verification on arm64 iOS 16+.
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-2 pr-4">Slot Index</th>
                      <th className="py-2 pr-4">Magic</th>
                      <th className="py-2">Contents &amp; CoreTrust Requirement</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70 text-slate-200">
                    <tr>
                      <td className="py-2.5 pr-4 text-blue-400">0x00000000</td>
                      <td className="py-2.5 pr-4">0xfade0c02</td>
                      <td className="py-2.5">Primary SHA-1 CodeDirectory (Special Slots -1 Info.plist / __TEXT,__info_plist, -2 Req, -3 CodeResources, -5/-7 Entitlements)</td>
                    </tr>
                    <tr>
                      <td className="py-2.5 pr-4 text-blue-400">0x00000002</td>
                      <td className="py-2.5 pr-4">0xfade0c01</td>
                      <td className="py-2.5">Requirements SuperBlob (12 bytes)</td>
                    </tr>
                    <tr>
                      <td className="py-2.5 pr-4 text-blue-400">0x00000005 / 0x07</td>
                      <td className="py-2.5 pr-4">0xfade7171 / 7172</td>
                      <td className="py-2.5">XML Entitlements + DER Entitlements extracted from embedded.mobileprovision</td>
                    </tr>
                    <tr>
                      <td className="py-2.5 pr-4 text-blue-400">0x00001000</td>
                      <td className="py-2.5 pr-4">0xfade0c02</td>
                      <td className="py-2.5">Alternate SHA-256 CodeDirectory (4KB page hashes, version 0x20400 with TeamID)</td>
                    </tr>
                    <tr>
                      <td className="py-2.5 pr-4 text-blue-400">0x00010000</td>
                      <td className="py-2.5 pr-4">0xfade0b01</td>
                      <td className="py-2.5">Strict definite-length DER CMS SignedData: Leaf + WWDR G1–G6 chain, exact 5 Apple signedAttrs (NO RFC 6211 cmsAlgorithmProtect)</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* Automated GitHub Actions IPA Build & Release */}
      <section className="rounded-xl border border-slate-800 bg-[#11151E] p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-semibold text-white">GitHub Actions IPA Build &amp; Auto-Release</h2>
            <p className="mt-1 text-xs text-slate-400">
              Bundled at <span className="font-mono text-slate-200">.github/workflows/build-ipa-release.yml</span>. Runs on <span className="font-mono text-slate-200">macos-15</span>, embeds <span className="font-mono text-slate-200">SideBridgeTunnel.appex</span>, generates <span className="font-mono text-slate-200">SHA256SUMS.txt</span>, and publishes directly to GitHub Releases on <span className="font-mono text-slate-200">v*.*.*</span> tags or manual dispatch.
            </p>
          </div>
          <button
            type="button"
            onClick={() => onInspectFile('.github/workflows/build-ipa-release.yml')}
            className="flex items-center gap-1.5 rounded-lg bg-blue-600 px-3.5 py-2 text-xs font-medium text-white hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0"
          >
            <FileCode2 className="h-3.5 w-3.5" />
            <span>Open Workflow YAML</span>
            <ChevronRight className="h-3.5 w-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-2 pr-4 font-semibold">Repository Secret</th>
                <th className="py-2 pr-4 font-semibold">Required For</th>
                <th className="py-2 font-semibold">Purpose</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 text-slate-300">
              <tr>
                <td className="py-2.5 pr-4 font-mono text-slate-100">None (Default Auto Mode)</td>
                <td className="py-2.5 pr-4 whitespace-nowrap">Unsigned Sideload IPA</td>
                <td className="py-2.5">Compiles arm64 release binaries and packages SideBridge-&lt;tag&gt;-unsigned.ipa with SideBridgeTunnel.appex for SideStore, AltStore, Sideloadly, or TrollStore.</td>
              </tr>
              <tr>
                <td className="py-2.5 pr-4 font-mono text-slate-100">IOS_DIST_CERT_P12_BASE64</td>
                <td className="py-2.5 pr-4 whitespace-nowrap">Signed IPA</td>
                <td className="py-2.5">Base64-encoded distribution or development .p12 signing identity imported into an ephemeral runner keychain.</td>
              </tr>
              <tr>
                <td className="py-2.5 pr-4 font-mono text-slate-100">IOS_DIST_CERT_PASSWORD</td>
                <td className="py-2.5 pr-4 whitespace-nowrap">Signed IPA</td>
                <td className="py-2.5">Passphrase unlocking the .p12 certificate during security import.</td>
              </tr>
              <tr>
                <td className="py-2.5 pr-4 font-mono text-slate-100">IOS_APP_PROVISION_BASE64</td>
                <td className="py-2.5 pr-4 whitespace-nowrap">Signed IPA</td>
                <td className="py-2.5">Base64-encoded .mobileprovision profile for com.sidebridge.ios (App Group + Packet Tunnel).</td>
              </tr>
              <tr>
                <td className="py-2.5 pr-4 font-mono text-slate-100">IOS_TUNNEL_PROVISION_BASE64</td>
                <td className="py-2.5 pr-4 whitespace-nowrap">Signed IPA</td>
                <td className="py-2.5">Base64-encoded .mobileprovision profile for com.sidebridge.ios.tunnel Network Extension.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* XcodeGen Build Steps */}
      <section className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <div className="lg:col-span-6 rounded-xl border border-slate-800 bg-[#11151E] p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm font-semibold text-white">
              <Terminal className="h-4 w-4 text-blue-400" />
              <span>Generate &amp; Build Locally in Xcode 15+</span>
            </div>
            <button
              type="button"
              onClick={copyCommands}
              className="flex items-center gap-1.5 rounded-md bg-slate-800 px-2.5 py-1 text-xs text-slate-200 hover:bg-slate-700"
            >
              {copiedCmd ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
              {copiedCmd ? 'Copied' : 'Copy'}
            </button>
          </div>
          <pre className="overflow-x-auto rounded-lg border border-slate-800 bg-[#080A0F] p-4 font-mono text-xs leading-6 text-slate-200">
            {buildCommands}
          </pre>
        </div>

        <div className="lg:col-span-6 rounded-xl border border-slate-800 bg-[#11151E] p-5 space-y-3">
          <h3 className="text-sm font-semibold text-white">Signing &amp; Capability Checklist</h3>
          <ol className="space-y-2.5 text-xs text-slate-300 leading-relaxed list-decimal list-inside">
            <li>
              Assign your Apple Development Team in Xcode Signing &amp; Capabilities for both{' '}
              <span className="font-mono text-white">SideBridge</span> and{' '}
              <span className="font-mono text-white">SideBridgeTunnel</span>.
            </li>
            <li>
              Verify <span className="font-mono text-white">group.com.sidebridge.shared</span> App Group and{' '}
              <span className="font-mono text-white">packet-tunnel-provider</span> Network Extension entitlements match your provisioning profiles.
            </li>
            <li>
              Let Swift Package Manager resolve <span className="font-mono text-white">ZIPFoundation</span> and{' '}
              <span className="font-mono text-white">OpenSSL</span> (for TLS 1.2 <span className="font-mono text-white">BIO_s_mem()</span> and PKCS#12/CSR).
            </li>
            <li>
              Deploy to an arm64 iPhone or iPad (iOS 16.0+), import a <span className="font-mono text-white">.mobiledevicepairing</span> file, and enable Developer Mode.
            </li>
          </ol>
        </div>
      </section>
    </div>
  );
};
