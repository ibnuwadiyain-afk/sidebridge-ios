import JSZip from 'jszip';

export type SimTab = 'devices' | 'library' | 'apps' | 'queue' | 'account' | 'setup';

export type ConnectionKind = 'Loopback VPN' | 'USB-C / OTG' | 'Wi-Fi Bonjour';

export type InstallStage = 0 | 1 | 2 | 3; // Provisioning | Signing | AFC Uploading | Installing

export type LogCategory =
  | 'LOCKDOWN_TX'
  | 'LOCKDOWN_RX'
  | 'AFC'
  | 'INSTPROXY'
  | 'SIGN'
  | 'PROVISION'
  | 'TRANSPORT';

export interface SimDevice {
  id: string;
  udid: string;
  name: string;
  host: string;
  port: number;
  advertisedPort?: number; // e.g. 32498 for Bonjour before mapping to 62078
  interfaceName: string;
  kind: ConnectionKind;
  iosVersion: string;
  paired: boolean;
  hostId?: string;
  systemBuid?: string;
}

export interface SimIPA {
  id: string;
  name: string;
  bundleId: string;
  version: string;
  fileName: string;
  sizeMB: number;
  nestedFrameworks: number;
  standaloneDylibs: number;
  hasFairPlaySinf: boolean;
  source: string;
}

export interface SimRepoApp {
  id: string;
  name: string;
  bundleId: string;
  version: string;
  developer: string;
  sizeMB: number;
  source: string;
  summary: string;
  downloadUrl: string;
}

export interface SimLogEntry {
  id: string;
  timestamp: string;
  category: LogCategory;
  message: string;
  isError?: boolean;
}

export interface SimAppIdRecord {
  id: string;
  name: string;
  identifier: string;
  expiresInDays: number;
}

export interface SimAppleAccount {
  appleId: string;
  teamId: string;
  teamName: string;
  isFreePersonalTeam: boolean;
  certSerial: string;
  certSha1: string;
  certSha256: string;
  certStatus: 'Active' | 'Revoked Externally';
  wwdrGeneration: 'G3' | 'G4' | 'G5' | 'G6';
}

export type FaultSimulationMode =
  | 'none'
  | 'usb_fallback_wifi'
  | 'cert_revoked_auto_reissue'
  | 'developer_mode_off'
  | 'device_locked';

export const INITIAL_DEVICES: SimDevice[] = [
  {
    id: 'this-device-loopback',
    udid: '00008130-001A4C2E1180001E',
    name: 'This iPhone 15 Pro',
    host: '10.7.0.1',
    port: 62078,
    interfaceName: 'utun4 (Loopback VPN)',
    kind: 'Loopback VPN',
    iosVersion: '17.6.1',
    paired: true,
    hostId: '8F3A12C4-4E91-4B08-A2D1-99817B0C5A12',
    systemBuid: '3D9E4120-B7C3-411F-9881-52F8A9C7E001',
  },
  {
    id: 'usb-peer-ipad',
    udid: '00008112-000C284A3E02401E',
    name: 'iPad Pro M2 (USB-C)',
    host: '169.254.14.2',
    port: 62078,
    interfaceName: 'en2 (Apple USB NCM)',
    kind: 'USB-C / OTG',
    iosVersion: '17.5',
    paired: true,
    hostId: '41B09E11-2D3F-4A10-9F02-7C8344B21E09',
    systemBuid: '9A2201C4-12F8-44C1-B610-33A8D11E9042',
  },
  {
    id: 'wifi-peer-iphone',
    udid: '00008120-00181D9C0A42002E',
    name: 'Studio iPhone 14',
    host: '192.168.1.48',
    port: 62078,
    advertisedPort: 32498,
    interfaceName: 'en0 (_apple-mobdev2._tcp)',
    kind: 'Wi-Fi Bonjour',
    iosVersion: '16.7.8',
    paired: true,
    hostId: '77E4D012-8A10-4D32-9C01-1B883A9F0214',
    systemBuid: '1C4098E2-66B1-492D-A7C2-00F1938B4421',
  },
];

export const INITIAL_IPAS: SimIPA[] = [
  {
    id: 'ipa-delta',
    name: 'Delta Emulator',
    bundleId: 'com.rileytestut.Delta',
    version: '1.6.1',
    fileName: 'Delta-1.6.1-decrypted.ipa',
    sizeMB: 48.4,
    nestedFrameworks: 6,
    standaloneDylibs: 3,
    hasFairPlaySinf: false,
    source: 'Local Library',
  },
  {
    id: 'ipa-utm',
    name: 'UTM SE',
    bundleId: 'com.utmapp.UTM-SE',
    version: '4.5.3',
    fileName: 'UTM-SE-4.5.3.ipa',
    sizeMB: 132.8,
    nestedFrameworks: 9,
    standaloneDylibs: 5,
    hasFairPlaySinf: false,
    source: 'Local Library',
  },
  {
    id: 'ipa-fairplay-sample',
    name: 'Encrypted App Store Sample',
    bundleId: 'com.example.FairPlayProtected',
    version: '2.1.0',
    fileName: 'FairPlaySample-encrypted.ipa',
    sizeMB: 21.2,
    nestedFrameworks: 2,
    standaloneDylibs: 0,
    hasFairPlaySinf: true,
    source: 'Local Library',
  },
];

export const REPO_CATALOG: SimRepoApp[] = [
  {
    id: 'repo-provenance',
    name: 'Provenance Multi-Emulator',
    bundleId: 'org.provenance-emu.provenance',
    version: '2.3.0',
    developer: 'Provenance EMU',
    sizeMB: 64.2,
    source: 'Archive.org Collection',
    summary: 'Open-source multi-system retro emulator decrypted arm64 IPA.',
    downloadUrl: 'https://archive.org/download/provenance-ios-2.3.0/Provenance-2.3.0.ipa',
  },
  {
    id: 'repo-ish',
    name: 'iSH Shell',
    bundleId: 'app.ish.iSH',
    version: '1.3.2',
    developer: 'Theodore Dubois',
    sizeMB: 18.6,
    source: 'Archive.org Collection',
    summary: 'Linux Alpine x86 usermode shell environment for iOS and iPadOS.',
    downloadUrl: 'https://archive.org/download/ish-shell-ios/iSH-1.3.2.ipa',
  },
  {
    id: 'repo-enmity',
    name: 'RetroArch Metal',
    bundleId: 'com.libretro.RetroArch',
    version: '1.19.1',
    developer: 'Libretro Team',
    sizeMB: 184.5,
    source: 'Archive.org Collection',
    summary: 'Cross-platform libretro frontend with Metal renderer and core bundles.',
    downloadUrl: 'https://archive.org/download/retroarch-ios-1.19.1/RetroArch-1.19.1.ipa',
  },
  {
    id: 'repo-pojav',
    name: 'PojavLauncher iOS',
    bundleId: 'net.kdt.pojavlaunch',
    version: '2.2.0',
    developer: 'PojavLauncherTeam',
    sizeMB: 76.9,
    source: 'Archive.org Collection',
    summary: 'JVM launcher with OpenJDK runtime frameworks for arm64 iOS.',
    downloadUrl: 'https://archive.org/download/pojavlauncher-ios/PojavLauncher-2.2.0.ipa',
  },
];

export const INITIAL_APP_IDS: SimAppIdRecord[] = [
  { id: 'A1', name: 'SideBridge Delta', identifier: 'com.rileytestut.Delta.9K4M2P7X1Q', expiresInDays: 6 },
  { id: 'A2', name: 'SideBridge UTM SE', identifier: 'com.utmapp.UTM-SE.9K4M2P7X1Q', expiresInDays: 5 },
  { id: 'A3', name: 'SideBridge Loopback', identifier: 'com.sidebridge.ios.9K4M2P7X1Q', expiresInDays: 7 },
];

export const DEFAULT_APPLE_ACCOUNT: SimAppleAccount = {
  appleId: 'dev.team@icloud.com',
  teamId: '9K4M2P7X1Q',
  teamName: 'Personal Team (Free)',
  isFreePersonalTeam: true,
  certSerial: '4A8E91C0B73D22F4',
  certSha1: 'c7f194b82e10a44d9103f8a1b7c2d09e41f8821c',
  certSha256: '8a19c4e2d70b55a13f6e2081c49d72b1e0a3f9845120c774d1b208f3a9e64c10',
  certStatus: 'Active',
  wwdrGeneration: 'G3',
};

export function nowTimestamp(): string {
  const d = new Date();
  const pad = (n: number, len = 2) => String(n).padStart(len, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
}

/**
 * Parses a real `.mobiledevicepairing` or `.plist` XML file selected by the user.
 */
export async function parseRealPairingFile(file: File): Promise<{
  udid: string;
  deviceName: string;
  hostId: string;
  systemBuid: string;
  hasHostCert: boolean;
  hasHostKey: boolean;
  hasRootCert: boolean;
}> {
  const text = await file.text();
  const extractString = (key: string): string | null => {
    const regex = new RegExp(`<key>${key}</key>\\s*<string>([^<]+)</string>`, 'i');
    return text.match(regex)?.[1]?.trim() ?? null;
  };
  const hasKey = (key: string) => text.includes(`<key>${key}</key>`);

  const hostId = extractString('HostID') ?? crypto.randomUUID().toUpperCase();
  const systemBuid = extractString('SystemBUID') ?? crypto.randomUUID().toUpperCase();
  const udid =
    extractString('UDID') ??
    extractString('UniqueDeviceID') ??
    file.name.replace(/\.(mobiledevicepairing|plist)$/i, '').slice(0, 40);
  const deviceName = extractString('DeviceName') ?? `Paired Device (${udid.slice(0, 8)})`;

  return {
    udid,
    deviceName,
    hostId,
    systemBuid,
    hasHostCert: hasKey('HostCertificate'),
    hasHostKey: hasKey('HostPrivateKey'),
    hasRootCert: hasKey('RootCertificate'),
  };
}

/**
 * Inspects a real `.ipa` archive selected by the user using JSZip.
 */
export async function inspectRealIPAFile(file: File): Promise<SimIPA> {
  let nestedFrameworks = 0;
  let standaloneDylibs = 0;
  let hasFairPlaySinf = false;
  let detectedAppName = file.name.replace(/\.ipa$/i, '');
  let detectedBundleId = `com.imported.${detectedAppName.toLowerCase().replace(/[^a-z0-9]/g, '') || 'app'}`;
  let detectedVersion = '1.0.0';

  try {
    const zip = await JSZip.loadAsync(file);
    const frameworkSet = new Set<string>();

    zip.forEach((relPath) => {
      const appMatch = relPath.match(/^Payload\/([^/]+)\.app\//);
      if (appMatch) detectedAppName = appMatch[1];

      const fwMatch = relPath.match(/Frameworks\/([^/]+\.framework)\//);
      if (fwMatch) frameworkSet.add(fwMatch[1]);

      if (/Frameworks\/[^/]+\.dylib$/i.test(relPath)) standaloneDylibs += 1;
      if (/SC_Info\/.*\.sinf$/i.test(relPath)) hasFairPlaySinf = true;
    });
    nestedFrameworks = frameworkSet.size;

    const infoPlistEntry = Object.values(zip.files).find((f) =>
      /^Payload\/[^/]+\.app\/Info\.plist$/.test(f.name)
    );
    if (infoPlistEntry) {
      const content = await infoPlistEntry.async('string');
      const idMatch = content.match(/<key>CFBundleIdentifier<\/key>\s*<string>([^<]+)<\/string>/);
      const verMatch = content.match(/<key>CFBundleShortVersionString<\/key>\s*<string>([^<]+)<\/string>/);
      const dispMatch = content.match(/<key>CFBundleDisplayName<\/key>\s*<string>([^<]+)<\/string>/);
      if (idMatch?.[1]) detectedBundleId = idMatch[1];
      if (verMatch?.[1]) detectedVersion = verMatch[1];
      if (dispMatch?.[1]) detectedAppName = dispMatch[1];
    }
  } catch {
    // Fallback to filename metadata if not a standard ZIP
  }

  return {
    id: `ipa-${Date.now()}`,
    name: detectedAppName,
    bundleId: detectedBundleId,
    version: detectedVersion,
    fileName: file.name,
    sizeMB: Number(Math.max(0.1, file.size / (1024 * 1024)).toFixed(1)),
    nestedFrameworks,
    standaloneDylibs,
    hasFairPlaySinf,
    source: 'Imported File',
  };
}
