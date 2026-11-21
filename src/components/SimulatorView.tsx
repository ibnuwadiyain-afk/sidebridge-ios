import React, { useEffect, useRef, useState } from 'react';
import {
  Check,
  ChevronRight,
  Copy,
  Download,
  FileCode2,
  FolderOpen,
  HardDrive,
  KeyRound,
  ListChecks,
  Package,
  Play,
  RefreshCw,
  ShieldCheck,
  Smartphone,
  Tablet,
  Terminal,
  Upload,
  Usb,
  Wifi,
  AlertTriangle,
  Trash2,
} from 'lucide-react';
import {
  ConnectionKind,
  DEFAULT_APPLE_ACCOUNT,
  FaultSimulationMode,
  INITIAL_APP_IDS,
  INITIAL_DEVICES,
  INITIAL_IPAS,
  InstallStage,
  LogCategory,
  REPO_CATALOG,
  SimAppIdRecord,
  SimAppleAccount,
  SimDevice,
  SimIPA,
  SimLogEntry,
  SimTab,
  inspectRealIPAFile,
  nowTimestamp,
  parseRealPairingFile,
} from '../lib/simulatorEngine';

interface SimulatorViewProps {
  onInspectSwiftFile: (relativePath: string) => void;
}

const STAGE_LABELS = ['Provisioning', 'Signing', 'AFC Uploading', 'Installing'] as const;

const TAB_SWIFT_MAP: Record<SimTab, { title: string; files: { label: string; path: string }[] }> = {
  devices: {
    title: 'Transport, Tunnel & Discovery Modules',
    files: [
      { label: 'DevicesView.swift', path: 'SideBridge/Views/DevicesView.swift' },
      { label: 'PacketTunnelProvider.swift', path: 'SideBridgeTunnel/PacketTunnelProvider.swift' },
      { label: 'WifiDeviceDiscovery.swift', path: 'SideBridge/Core/Transport/WifiDeviceDiscovery.swift' },
      { label: 'UsbNetworkDiscovery.swift', path: 'SideBridge/Core/Transport/UsbNetworkDiscovery.swift' },
      { label: 'TlsDeviceTransport.swift', path: 'SideBridge/Core/Transport/TlsDeviceTransport.swift' },
    ],
  },
  library: {
    title: 'On-Device Mach-O & IPA Signing Engine',
    files: [
      { label: 'LibraryView.swift', path: 'SideBridge/Views/LibraryView.swift' },
      { label: 'IpaSigner.swift', path: 'SideBridge/Core/Signing/IpaSigner.swift' },
      { label: 'MachOSigner.swift', path: 'SideBridge/Core/Signing/MachOSigner.swift' },
      { label: 'DEREncoder.swift', path: 'SideBridge/Core/Signing/DEREncoder.swift' },
      { label: 'AppleWWDRCertificates.swift', path: 'SideBridge/Core/Signing/AppleWWDRCertificates.swift' },
    ],
  },
  apps: {
    title: 'Repository & Direct IPA Downloader',
    files: [
      { label: 'AppsView.swift', path: 'SideBridge/Views/AppsView.swift' },
      { label: 'SideBridgeViewModel.swift', path: 'SideBridge/App/SideBridgeViewModel.swift' },
    ],
  },
  queue: {
    title: '4-Stage Installer & Apple Protocol Stack',
    files: [
      { label: 'QueueView.swift', path: 'SideBridge/Views/QueueView.swift' },
      { label: 'DeviceInstaller.swift', path: 'SideBridge/Core/Installer/DeviceInstaller.swift' },
      { label: 'LockdownClient.swift', path: 'SideBridge/Core/Protocol/LockdownClient.swift' },
      { label: 'AfcClient.swift', path: 'SideBridge/Core/Protocol/AfcClient.swift' },
      { label: 'InstallationProxyClient.swift', path: 'SideBridge/Core/Protocol/InstallationProxyClient.swift' },
    ],
  },
  account: {
    title: 'Anisette v3, GrandSlam SRP-6a & QH65B2 Portal',
    files: [
      { label: 'AccountView.swift', path: 'SideBridge/Views/AccountView.swift' },
      { label: 'GrandSlamSRP.swift', path: 'SideBridge/Core/Provisioning/GrandSlamSRP.swift' },
      { label: 'AppleDeveloperProvisioner.swift', path: 'SideBridge/Core/Provisioning/AppleDeveloperProvisioner.swift' },
      { label: 'AnisetteClient.swift', path: 'SideBridge/Core/Provisioning/AnisetteClient.swift' },
    ],
  },
  setup: {
    title: 'Pairing Storage & Onboarding Wizard',
    files: [
      { label: 'SetupWizardView.swift', path: 'SideBridge/Views/SetupWizardView.swift' },
      { label: 'PairingStorage.swift', path: 'SideBridge/Core/Storage/PairingStorage.swift' },
      { label: 'LocalTunnelManager.swift', path: 'SideBridge/Core/Transport/LocalTunnelManager.swift' },
    ],
  },
};

export const SimulatorView: React.FC<SimulatorViewProps> = ({ onInspectSwiftFile }) => {
  const [formFactor, setFormFactor] = useState<'iphone' | 'ipad'>('iphone');
  const [activeTab, setActiveTab] = useState<SimTab>('devices');

  // Device & Tunnel State
  const [devices, setDevices] = useState<SimDevice[]>(INITIAL_DEVICES);
  const [tunnelActive, setTunnelActive] = useState<boolean>(true);
  const [selectedDeviceId, setSelectedDeviceId] = useState<string>(INITIAL_DEVICES[0].id);
  const [connectionBanner, setConnectionBanner] = useState<string | null>(null);

  // Library & Signing State
  const [ipas, setIpas] = useState<SimIPA[]>(INITIAL_IPAS);
  const [useCustomP12, setUseCustomP12] = useState<boolean>(false);
  const [customP12Name, setCustomP12Name] = useState<string | null>(null);
  const [customProfileName, setCustomProfileName] = useState<string | null>(null);
  const [customP12Pass, setCustomP12Pass] = useState<string>('');
  const [enableOTAFallback, setEnableOTAFallback] = useState<boolean>(false);

  // Apps / Repo State
  const [repoSearch, setRepoSearch] = useState<string>('');
  const [directUrl, setDirectUrl] = useState<string>('');
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  // Queue & Protocol Log State
  const [isInstalling, setIsInstalling] = useState<boolean>(false);
  const [installStage, setInstallStage] = useState<InstallStage>(0);
  const [stageProgress, setStageProgress] = useState<number>(0);
  const [stageMessage, setStageMessage] = useState<string>('Ready to sign and sideload an IPA package');
  const [installError, setInstallError] = useState<string | null>(null);
  const [logFilter, setLogFilter] = useState<LogCategory | 'ALL'>('ALL');
  const [copiedLogs, setCopiedLogs] = useState<boolean>(false);
  const [faultMode, setFaultMode] = useState<FaultSimulationMode>('none');
  const [logs, setLogs] = useState<SimLogEntry[]>([
    {
      id: 'init-1',
      timestamp: '10:35:02.114',
      category: 'TRANSPORT',
      message: 'SideBridgeTunnel NEPacketTunnelProvider bound to 10.7.0.1/24 -> lockdownd :62078',
    },
    {
      id: 'init-2',
      timestamp: '10:35:02.482',
      category: 'TRANSPORT',
      message: 'NWBrowser discovered _apple-mobdev2._tcp (192.168.1.48) — mapped mDNS port 32498 (0x7EF2) -> 62078 (0xF27E)',
    },
    {
      id: 'init-3',
      timestamp: '10:35:02.910',
      category: 'TRANSPORT',
      message: 'UsbNetworkDiscovery probed en2 (169.254.14.2:62078) -> QueryType = com.apple.mobile.lockdown',
    },
  ]);

  // Account State
  const [account, setAccount] = useState<SimAppleAccount | null>(DEFAULT_APPLE_ACCOUNT);
  const [appIds, setAppIds] = useState<SimAppIdRecord[]>(INITIAL_APP_IDS);
  const [loginEmail, setLoginEmail] = useState<string>('');
  const [loginPass, setLoginPass] = useState<string>('');
  const [awaiting2FA, setAwaiting2FA] = useState<boolean>(false);
  const [twoFactorCode, setTwoFactorCode] = useState<string>('');

  // Setup Wizard State
  const [devModeEnabled, setDevModeEnabled] = useState<boolean>(true);
  const [profileTrusted, setProfileTrusted] = useState<boolean>(true);

  const pairingInputRef = useRef<HTMLInputElement>(null);
  const ipaInputRef = useRef<HTMLInputElement>(null);
  const p12InputRef = useRef<HTMLInputElement>(null);
  const provInputRef = useRef<HTMLInputElement>(null);
  const logEndRef = useRef<HTMLDivElement>(null);
  const timersRef = useRef<number[]>([]);

  useEffect(() => {
    return () => {
      timersRef.current.forEach((id) => window.clearTimeout(id));
    };
  }, []);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs.length, logFilter]);

  const appendLog = (category: LogCategory, message: string, isError = false) => {
    setLogs((prev) => [
      ...prev.slice(-250),
      {
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        timestamp: nowTimestamp(),
        category,
        message,
        isError,
      },
    ]);
  };

  const selectedDevice = devices.find((d) => d.id === selectedDeviceId) ?? devices[0];

  const handleToggleTunnel = () => {
    const next = !tunnelActive;
    setTunnelActive(next);
    appendLog(
      'TRANSPORT',
      next
        ? 'LocalTunnelManager started SideBridgeTunnel (utun4 10.7.0.1 <-> 10.7.0.2 loopback reflection)'
        : 'LocalTunnelManager stopped SideBridgeTunnel loopback VPN'
    );
  };

  const handleTestConnection = (device: SimDevice) => {
    if (device.kind === 'Loopback VPN' && !tunnelActive) {
      const msg = 'Local Loopback VPN is stopped. Enable SideBridgeTunnel to reach 10.7.0.1:62078.';
      setConnectionBanner(msg);
      appendLog('TRANSPORT', msg, true);
      return;
    }

    setConnectionBanner(`Testing TLS 1.2 handshake with ${device.name} (${device.host}:${device.port})...`);
    appendLog('TRANSPORT', `TCP connect ${device.host}:${device.port} (TCP_NODELAY=1, SO_KEEPALIVE=1)`);
    appendLog('LOCKDOWN_TX', `{ Label="SideBridge", Request="QueryType" }`);

    const t1 = window.setTimeout(() => {
      appendLog('LOCKDOWN_RX', `{ Request="QueryType", Type="com.apple.mobile.lockdown" }`);
      appendLog(
        'LOCKDOWN_TX',
        `{ HostID="${device.hostId?.slice(0, 8) ?? '8F3A12C4'}...", Label="SideBridge", ProtocolVersion="2", Request="StartSession", SystemBUID="${device.systemBuid?.slice(0, 8) ?? '3D9E4120'}..." }`
      );
    }, 300);

    const t2 = window.setTimeout(() => {
      appendLog('LOCKDOWN_RX', `{ EnableSessionSSL=1, Request="StartSession", SessionID=<REDACTED> }`);
      appendLog('TRANSPORT', `OpenSSL BIO_s_mem() upgraded to TLS 1.2 using HostCertificate + RootCertificate`);
      appendLog('LOCKDOWN_TX', `{ Label="SideBridge", Request="StopSession", SessionID=<REDACTED> }`);
      setConnectionBanner(
        `Verified TLS 1.2 session with ${device.name} (iOS ${device.iosVersion}) via ${device.kind}`
      );
    }, 750);

    timersRef.current.push(t1, t2);
  };

  const handleImportPairingFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const parsed = await parseRealPairingFile(file);

    setDevices((prev) => {
      const updated = [...prev];
      updated[0] = {
        ...updated[0],
        udid: parsed.udid,
        name: parsed.deviceName,
        hostId: parsed.hostId,
        systemBuid: parsed.systemBuid,
        paired: true,
      };
      return updated;
    });

    appendLog(
      'TRANSPORT',
      `Imported pairing plist "${file.name}" -> UDID=${parsed.udid.slice(0, 12)}... HostCert=${parsed.hasHostCert ? 'OK' : 'Fallback'} Key=${parsed.hasHostKey ? 'OK' : 'Fallback'}`
    );
    setConnectionBanner(`Imported pairing record for ${parsed.deviceName} into Keychain.`);
    e.target.value = '';
  };

  const handleImportIPA = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const inspected = await inspectRealIPAFile(file);
    setIpas((prev) => [inspected, ...prev]);
    appendLog(
      'SIGN',
      `Imported ${inspected.fileName} (${inspected.sizeMB} MB, ${inspected.nestedFrameworks} frameworks, ${inspected.standaloneDylibs} dylibs, FairPlay=${inspected.hasFairPlaySinf})`
    );
    e.target.value = '';
  };

  const handleDownloadRepoApp = (app: (typeof REPO_CATALOG)[number]) => {
    if (downloadingId) return;
    setDownloadingId(app.id);
    appendLog('TRANSPORT', `Downloading decrypted IPA from ${app.source}: ${app.downloadUrl}`);

    const t = window.setTimeout(() => {
      const exists = ipas.some((i) => i.bundleId === app.bundleId);
      if (!exists) {
        setIpas((prev) => [
          {
            id: `ipa-${Date.now()}`,
            name: app.name,
            bundleId: app.bundleId,
            version: app.version,
            fileName: `${app.name.replace(/\s+/g, '-')}-${app.version}.ipa`,
            sizeMB: app.sizeMB,
            nestedFrameworks: 4,
            standaloneDylibs: 2,
            hasFairPlaySinf: false,
            source: app.source,
          },
          ...prev,
        ]);
      }
      setDownloadingId(null);
      appendLog('TRANSPORT', `Saved ${app.name} (${app.sizeMB} MB) to Library`);
    }, 900);
    timersRef.current.push(t);
  };

  const handleDirectUrlFetch = () => {
    const trimmed = directUrl.trim();
    if (!trimmed) return;
    const guessedName = trimmed.split('/').pop()?.replace(/\.ipa$/i, '') || 'RemotePackage';
    setDownloadingId('direct-url');
    appendLog('TRANSPORT', `Fetching direct IPA URL: ${trimmed}`);
    const t = window.setTimeout(() => {
      setIpas((prev) => [
        {
          id: `ipa-${Date.now()}`,
          name: guessedName,
          bundleId: `com.direct.${guessedName.toLowerCase().replace(/[^a-z0-9]/g, '') || 'app'}`,
          version: '1.0.0',
          fileName: `${guessedName}.ipa`,
          sizeMB: 34.6,
          nestedFrameworks: 3,
          standaloneDylibs: 1,
          hasFairPlaySinf: false,
          source: 'Direct URL',
        },
        ...prev,
      ]);
      setDirectUrl('');
      setDownloadingId(null);
      appendLog('TRANSPORT', `Imported ${guessedName}.ipa into Library`);
    }, 850);
    timersRef.current.push(t);
  };

  const runInstallPipeline = (ipa: SimIPA) => {
    if (isInstalling) return;
    timersRef.current.forEach((id) => window.clearTimeout(id));
    timersRef.current = [];

    setActiveTab('queue');
    setIsInstalling(true);
    setInstallError(null);
    setInstallStage(0);
    setStageProgress(0.1);
    setStageMessage(`Starting 4-stage pipeline for ${ipa.name} -> ${selectedDevice.name}`);

    if (!useCustomP12 && !account) {
      setInstallError('Sign in with your Apple ID in Account, or switch to Custom .p12 signing.');
      setIsInstalling(false);
      return;
    }

    if (selectedDevice.kind === 'Loopback VPN' && !tunnelActive) {
      setInstallError('Local Loopback VPN (SideBridgeTunnel) is stopped. Start it in Devices or Setup Wizard.');
      appendLog('TRANSPORT', 'Loopback VPN unavailable for 10.7.0.1:62078', true);
      setIsInstalling(false);
      return;
    }

    const effectiveTeamId = account?.teamId ?? 'CUSTOM1234';
    const effectiveBundleId = useCustomP12 ? ipa.bundleId : `${ipa.bundleId}.${effectiveTeamId}`;

    const steps: { delay: number; fn: () => void }[] = [
      {
        delay: 350,
        fn: () => {
          setInstallStage(0);
          setStageProgress(0.35);
          setStageMessage('Minting Anisette v3 headers & verifying active certificates...');
          if (useCustomP12) {
            appendLog('PROVISION', `Loaded custom .p12 (${customP12Name ?? 'enterprise.p12'}) and .mobileprovision`);
          } else {
            appendLog('PROVISION', `Anisette v3 headers minted (X-Apple-I-MD=<REDACTED>)`);
            appendLog('PROVISION', `QH65B2 listAllDevelopmentCerts(teamId=${effectiveTeamId})`);
            if (faultMode === 'cert_revoked_auto_reissue' || account?.certStatus === 'Revoked Externally') {
              appendLog('PROVISION', 'Cached local cert was revoked externally (Sideloadly/AltStore) — revoking stale entry & submitting RSA-2048 CSR', true);
              appendLog('PROVISION', 'submitDevelopmentCSR issued fresh cert serial=7F2B90A14E10C831');
              setAccount((prev) => (prev ? { ...prev, certSerial: '7F2B90A14E10C831', certStatus: 'Active' } : prev));
            } else {
              appendLog('PROVISION', `Active certificate verified on portal (serial=${account?.certSerial})`);
            }
          }
        },
      },
      {
        delay: 950,
        fn: () => {
          setStageProgress(0.85);
          setStageMessage('Downloading team provisioning profile & validating thumbprint...');
          appendLog('PROVISION', `downloadTeamProvisioningProfile(${effectiveBundleId})`);
          appendLog(
            'PROVISION',
            `Verified DeveloperCertificates contains leaf SHA-1 ${account?.certSha1.slice(0, 12) ?? 'c7f194b82e10'}... & SHA-256 match`
          );
          if (!appIds.some((a) => a.identifier === effectiveBundleId)) {
            setAppIds((prev) => [
              { id: `A${prev.length + 1}`, name: `SideBridge ${ipa.name}`, identifier: effectiveBundleId, expiresInDays: 7 },
              ...prev,
            ]);
          }
        },
      },
      {
        delay: 1450,
        fn: () => {
          setInstallStage(1);
          setStageProgress(0.2);
          setStageMessage(`Unpacking ${ipa.fileName} & scanning FairPlay .sinf...`);
          appendLog('SIGN', `Unpacking ${ipa.fileName} via ZIPFoundation`);

          if (ipa.hasFairPlaySinf) {
            const err = `${ipa.name} is FairPlay-encrypted (SC_Info/*.sinf / cryptid != 0). Only decrypted IPAs can be re-signed.`;
            appendLog('SIGN', err, true);
            setInstallError(err);
            setStageMessage('Signing aborted: FairPlay encryption detected');
            setIsInstalling(false);
            timersRef.current.forEach((id) => window.clearTimeout(id));
            return;
          }

          appendLog('SIGN', `Embedded mobileprovision & updated main Info.plist CFBundleIdentifier -> ${effectiveBundleId}`);
          appendLog(
            'SIGN',
            `Bottom-up signing ${ipa.nestedFrameworks} .framework bundles (bplist00 Info.plist byte-for-byte untouched) & ${ipa.standaloneDylibs} standalone .dylibs (__TEXT,__info_plist -> Slot -1)`
          );
        },
      },
      {
        delay: 2150,
        fn: () => {
          setStageProgress(0.75);
          setStageMessage('Building CoreTrust DER CMS (0xfade0b01) & repacking IPA...');
          appendLog(
            'SIGN',
            `Encoded strict definite-length DER CMS (0xfade0b01): 5 Apple signedAttrs, omitted RFC 6211 cmsAlgorithmProtect, WWDR ${account?.wwdrGeneration ?? 'G3'} chain`
          );
          appendLog('SIGN', `Generated _CodeSignature/CodeResources (SHA-1 & SHA-256)`);
          appendLog('SIGN', `Repacked signed IPA with STORED directory entries (size=0, crc=0) and Unix 0755 (0x81ED) on Mach-O executables`);
        },
      },
      {
        delay: 2750,
        fn: () => {
          setInstallStage(2);
          setStageProgress(0.15);
          let routeHost = selectedDevice.host;
          let routePort = selectedDevice.port;
          if (selectedDevice.kind === 'USB-C / OTG' && faultMode === 'usb_fallback_wifi') {
            const wifiFallback = devices.find((d) => d.kind === 'Wi-Fi Bonjour');
            routeHost = wifiFallback?.host ?? '192.168.1.48';
            routePort = 62078;
            appendLog('TRANSPORT', `USB-C/OTG probe timed out on ${selectedDevice.host}:62078 — automatic fallback to Wi-Fi Bonjour ${routeHost}:${routePort}`);
          }
          setStageMessage(`Lockdown StartSession -> com.apple.afc on ${routeHost}:${routePort}`);
          appendLog('LOCKDOWN_TX', `{ Request="StartSession", HostID="${selectedDevice.hostId?.slice(0, 8) ?? '8F3A12C4'}...", ProtocolVersion="2" }`);
          appendLog('LOCKDOWN_RX', `{ EnableSessionSSL=1, SessionID=<REDACTED> } -> OpenSSL BIO TLS 1.2 ready`);
          appendLog('LOCKDOWN_TX', `{ Request="StartService", Service="com.apple.afc" }`);
          appendLog('LOCKDOWN_RX', `{ Port=51422, EnableServiceSSL=1, Service="com.apple.afc" }`);
          appendLog('AFC', `Streaming ${ipa.sizeMB} MB -> PublicStaging/${effectiveBundleId}.ipa in 64KB CFA6LPAA chunks`);
        },
      },
      {
        delay: 3350,
        fn: () => {
          setStageProgress(0.58);
          setStageMessage(`AFC uploading ${(ipa.sizeMB * 0.58).toFixed(1)} / ${ipa.sizeMB.toFixed(1)} MB (64KB chunks)`);
          appendLog('AFC', `Uploaded ${(ipa.sizeMB * 0.58).toFixed(1)} MB / ${ipa.sizeMB.toFixed(1)} MB (58%)`);
        },
      },
      {
        delay: 3900,
        fn: () => {
          setStageProgress(1.0);
          setStageMessage(`AFC upload complete (${ipa.sizeMB.toFixed(1)} MB)`);
          appendLog('AFC', `Uploaded ${ipa.sizeMB.toFixed(1)} MB / ${ipa.sizeMB.toFixed(1)} MB (100%) — FileRefClose status=0`);
        },
      },
      {
        delay: 4350,
        fn: () => {
          setInstallStage(3);
          setStageProgress(0.25);
          setStageMessage('Starting com.apple.mobile.installation_proxy...');
          appendLog('LOCKDOWN_TX', `{ Request="StartService", Service="com.apple.mobile.installation_proxy" }`);
          appendLog('LOCKDOWN_RX', `{ Port=51428, EnableServiceSSL=1, Service="com.apple.mobile.installation_proxy" }`);
          appendLog('INSTPROXY', `TX Command="Install" PackagePath="PublicStaging/${effectiveBundleId}.ipa" CFBundleIdentifier="${effectiveBundleId}"`);
          appendLog('INSTPROXY', `RX Status="ExtractingPackage" PercentComplete=25%`);
        },
      },
      {
        delay: 4950,
        fn: () => {
          if (faultMode === 'developer_mode_off') {
            const err =
              'iOS 16+ Developer Mode is disabled. Open Settings -> Privacy & Security -> Developer Mode, enable it, restart the device, and retry.';
            appendLog('INSTPROXY', `RX Error="DeveloperModeNotEnabled" (${err})`, true);
            setInstallError(err);
            setStageMessage('Installation halted: Developer Mode required');
            setIsInstalling(false);
            timersRef.current.forEach((id) => window.clearTimeout(id));
            return;
          }
          if (faultMode === 'device_locked') {
            const err =
              'Target iOS device is locked. Unlock the device and keep the screen awake during installation.';
            appendLog('INSTPROXY', `RX Error="PasswordProtected" (${err})`, true);
            setInstallError(err);
            setStageMessage('Installation halted: Device passcode locked');
            setIsInstalling(false);
            timersRef.current.forEach((id) => window.clearTimeout(id));
            return;
          }
          setStageProgress(0.65);
          setStageMessage('VerifyingApplication (65%) — XNU CoreTrust CMS check');
          appendLog('INSTPROXY', `RX Status="VerifyingApplication" PercentComplete=65%`);
        },
      },
      {
        delay: 5550,
        fn: () => {
          setStageProgress(1.0);
          setStageMessage(`Complete (100%) — ${ipa.name} installed on ${selectedDevice.name}`);
          appendLog('INSTPROXY', `RX Status="GeneratingApplicationMap" PercentComplete=90%`);
          appendLog('INSTPROXY', `RX Status="Complete" PercentComplete=100%`);
          if (enableOTAFallback && useCustomP12) {
            appendLog('TRANSPORT', `OTA manifest ready: itms-services://?action=download-manifest&url=https%3A%2F%2Flocal.sidebridge%2Fmanifest.plist`);
          }
          setIsInstalling(false);
        },
      },
    ];

    for (const step of steps) {
      const id = window.setTimeout(step.fn, step.delay);
      timersRef.current.push(id);
    }
  };

  const handleCopyLogs = async () => {
    const text = logs.map((l) => `[${l.timestamp}] [${l.category}] ${l.message}`).join('\n');
    await navigator.clipboard.writeText(text);
    setCopiedLogs(true);
    window.setTimeout(() => setCopiedLogs(false), 1800);
  };

  const handleExportLogs = () => {
    const text = logs.map((l) => `[${l.timestamp}] [${l.category}] ${l.message}`).join('\n');
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sidebridge-protocol-${Date.now()}.log`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const filteredLogs = logFilter === 'ALL' ? logs : logs.filter((l) => l.category === logFilter);
  const filteredRepoApps = REPO_CATALOG.filter(
    (app) =>
      app.name.toLowerCase().includes(repoSearch.toLowerCase()) ||
      app.developer.toLowerCase().includes(repoSearch.toLowerCase())
  );

  const handleAppleSignIn = () => {
    if (!loginEmail.trim() || !loginPass.trim()) return;
    appendLog('PROVISION', `GrandSlam SRP-6a init (s2k/s2k_fo) for ${loginEmail.trim()}`);
    setAwaiting2FA(true);
    appendLog('PROVISION', 'GrandSlam returned trustedDeviceSecondaryAuth — awaiting 6-digit 2FA code');
  };

  const handleVerify2FA = () => {
    if (twoFactorCode.trim().length < 6) return;
    appendLog('PROVISION', '2FA verified — decrypted com.apple.gs.xcode.auth token via AES-256-GCM');
    setAccount({
      ...DEFAULT_APPLE_ACCOUNT,
      appleId: loginEmail.trim() || DEFAULT_APPLE_ACCOUNT.appleId,
    });
    setAwaiting2FA(false);
    setTwoFactorCode('');
    setLoginPass('');
  };

  const activeSwiftMap = TAB_SWIFT_MAP[activeTab];

  return (
    <div className="mx-auto max-w-[1440px] px-6 py-6">
      {/* Hidden Real File Inputs */}
      <input
        ref={pairingInputRef}
        type="file"
        accept=".mobiledevicepairing,.plist,.xml"
        className="hidden"
        onChange={handleImportPairingFile}
      />
      <input
        ref={ipaInputRef}
        type="file"
        accept=".ipa,.zip"
        className="hidden"
        onChange={handleImportIPA}
      />
      <input
        ref={p12InputRef}
        type="file"
        accept=".p12,.pfx"
        className="hidden"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) {
            setCustomP12Name(f.name);
            appendLog('PROVISION', `Stored custom .p12 identity (${f.name}) in shared Keychain`);
          }
        }}
      />
      <input
        ref={provInputRef}
        type="file"
        accept=".mobileprovision"
        className="hidden"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) {
            setCustomProfileName(f.name);
            appendLog('PROVISION', `Stored custom provisioning profile (${f.name})`);
          }
        }}
      />

      {/* Workspace Toolbar */}
      <div className="mb-6 flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-slate-100">
            Interactive SideBridge iOS 16+ Preview
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Test all 6 SwiftUI views, import real <span className="font-mono text-slate-300">.ipa</span> or{' '}
            <span className="font-mono text-slate-300">.mobiledevicepairing</span> files, and inspect live protocol frames.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1 rounded-lg border border-slate-800 bg-[#11151E] p-1">
            <button
              type="button"
              onClick={() => setFormFactor('iphone')}
              className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                formFactor === 'iphone'
                  ? 'bg-slate-800 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Smartphone className="h-3.5 w-3.5" />
              iPhone
            </button>
            <button
              type="button"
              onClick={() => setFormFactor('ipad')}
              className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                formFactor === 'ipad'
                  ? 'bg-slate-800 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Tablet className="h-3.5 w-3.5" />
              iPadOS
            </button>
          </div>
        </div>
      </div>

      {/* Main 2-Column Workspace Split */}
      <div className="grid grid-cols-1 items-start gap-6 lg:grid-cols-12">
        {/* Left/Center Column: Interactive SwiftUI iOS App */}
        <div className={formFactor === 'ipad' ? 'lg:col-span-8' : 'lg:col-span-7'}>
          <div
            className={`mx-auto overflow-hidden rounded-2xl border border-slate-800 bg-[#0D1017] ${
              formFactor === 'iphone' ? 'max-w-[440px]' : 'w-full'
            }`}
          >
            {/* iOS Status Bar */}
            <div className="flex items-center justify-between border-b border-slate-800/80 bg-[#0A0D13] px-5 py-2.5 text-xs font-medium text-slate-300 tabular-nums">
              <span>10:38</span>
              <span className="font-mono text-[11px] text-slate-400">
                {tunnelActive ? 'VPN · 10.7.0.1' : 'No Loopback VPN'}
              </span>
              <span className="font-mono text-[11px] text-slate-400">5G · 98%</span>
            </div>

            {/* Navigation Title Header */}
            <div className="flex items-center justify-between border-b border-slate-800/70 px-5 py-3.5">
              <div>
                <h2 className="text-lg font-semibold tracking-tight text-white capitalize">
                  {activeTab === 'setup' ? 'Setup Wizard' : activeTab}
                </h2>
                <div className="mt-0.5 text-xs text-slate-400">
                  Target: {selectedDevice.name} · <span className="font-mono">{selectedDevice.host}:{selectedDevice.port}</span>
                </div>
              </div>
              {activeTab === 'devices' && (
                <button
                  type="button"
                  onClick={() => pairingInputRef.current?.click()}
                  className="rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0"
                >
                  Import Pairing
                </button>
              )}
              {activeTab === 'library' && (
                <button
                  type="button"
                  onClick={() => ipaInputRef.current?.click()}
                  className="rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0"
                >
                  Import .ipa
                </button>
              )}
            </div>

            {/* Tab Viewport Body */}
            <div className="h-[580px] overflow-y-auto px-5 py-4">
              {/* TAB 1: DEVICES */}
              {activeTab === 'devices' && (
                <div className="space-y-5">
                  {connectionBanner && (
                    <div className="rounded-lg border border-slate-700/80 bg-slate-900/90 px-3.5 py-2.5 text-xs font-mono text-slate-200">
                      {connectionBanner}
                    </div>
                  )}

                  {/* This Device Loopback VPN */}
                  <section>
                    <div className="mb-2 flex items-center justify-between text-xs font-medium text-slate-400">
                      <span>This Device (Loopback VPN)</span>
                      <span className="font-mono">{tunnelActive ? 'Active' : 'Stopped'}</span>
                    </div>
                    <div className="rounded-xl border border-slate-800 bg-[#121722] p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="text-sm font-semibold text-white">{devices[0].name}</div>
                          <div className="mt-1 font-mono text-xs text-slate-400">
                            {devices[0].host}:{devices[0].port} · iOS {devices[0].iosVersion} · {devices[0].paired ? 'Paired' : 'Unpaired'}
                          </div>
                          <div className="mt-1 font-mono text-[11px] text-slate-500 truncate">
                            UDID {devices[0].udid}
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={handleToggleTunnel}
                          className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                            tunnelActive
                              ? 'bg-emerald-600/20 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-600/30'
                              : 'bg-blue-600 text-white hover:bg-blue-500'
                          }`}
                        >
                          {tunnelActive ? 'Stop VPN' : 'Start VPN'}
                        </button>
                      </div>
                      <div className="mt-3.5 flex flex-wrap items-center gap-2 border-t border-slate-800/80 pt-3">
                        <button
                          type="button"
                          onClick={() => setSelectedDeviceId(devices[0].id)}
                          className={`rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                            selectedDeviceId === devices[0].id
                              ? 'bg-blue-600 text-white'
                              : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                          }`}
                        >
                          {selectedDeviceId === devices[0].id ? 'Selected Target' : 'Select Target'}
                        </button>
                        <button
                          type="button"
                          onClick={() => handleTestConnection(devices[0])}
                          className="rounded-md bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0"
                        >
                          Test Connection
                        </button>
                        <button
                          type="button"
                          onClick={() => pairingInputRef.current?.click()}
                          className="rounded-md bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0"
                        >
                          Replace Pairing
                        </button>
                      </div>
                    </div>
                  </section>

                  {/* USB-C / OTG Peer Devices */}
                  <section>
                    <div className="mb-2 flex items-center justify-between text-xs font-medium text-slate-400">
                      <span>USB-C / OTG Ethernet Peers</span>
                      <button
                        type="button"
                        onClick={() => appendLog('TRANSPORT', 'UsbNetworkDiscovery scanned getifaddrs() en*/bridge* -> 1 peer on 169.254.14.2:62078')}
                        className="text-blue-400 hover:text-blue-300"
                      >
                        Probe Interfaces
                      </button>
                    </div>
                    {devices
                      .filter((d) => d.kind === 'USB-C / OTG')
                      .map((device) => (
                        <div key={device.id} className="rounded-xl border border-slate-800 bg-[#121722] p-4">
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <div className="flex items-center gap-2 text-sm font-semibold text-white">
                                <Usb className="h-4 w-4 text-slate-400" />
                                {device.name}
                              </div>
                              <div className="mt-1 font-mono text-xs text-slate-400">
                                {device.host}:{device.port} · {device.interfaceName} · iOS {device.iosVersion}
                              </div>
                            </div>
                          </div>
                          <div className="mt-3 flex items-center gap-2">
                            <button
                              type="button"
                              onClick={() => setSelectedDeviceId(device.id)}
                              className={`rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                                selectedDeviceId === device.id
                                  ? 'bg-blue-600 text-white'
                                  : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                              }`}
                            >
                              {selectedDeviceId === device.id ? 'Selected Target' : 'Select Target'}
                            </button>
                            <button
                              type="button"
                              onClick={() => handleTestConnection(device)}
                              className="rounded-md bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0"
                            >
                              Test Connection
                            </button>
                          </div>
                        </div>
                      ))}
                  </section>

                  {/* Wi-Fi Bonjour Devices */}
                  <section>
                    <div className="mb-2 flex items-center justify-between text-xs font-medium text-slate-400">
                      <span>Wi-Fi Bonjour (_apple-mobdev2._tcp)</span>
                      <span className="font-mono text-slate-500">32498 -&gt; 62078</span>
                    </div>
                    {devices
                      .filter((d) => d.kind === 'Wi-Fi Bonjour')
                      .map((device) => (
                        <div key={device.id} className="rounded-xl border border-slate-800 bg-[#121722] p-4">
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <div className="flex items-center gap-2 text-sm font-semibold text-white">
                                <Wifi className="h-4 w-4 text-slate-400" />
                                {device.name}
                              </div>
                              <div className="mt-1 font-mono text-xs text-slate-400">
                                {device.host}:{device.port} (mapped from mDNS {device.advertisedPort}) · iOS {device.iosVersion}
                              </div>
                            </div>
                          </div>
                          <div className="mt-3 flex items-center gap-2">
                            <button
                              type="button"
                              onClick={() => setSelectedDeviceId(device.id)}
                              className={`rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                                selectedDeviceId === device.id
                                  ? 'bg-blue-600 text-white'
                                  : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                              }`}
                            >
                              {selectedDeviceId === device.id ? 'Selected Target' : 'Select Target'}
                            </button>
                            <button
                              type="button"
                              onClick={() => handleTestConnection(device)}
                              className="rounded-md bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0"
                            >
                              Test Connection
                            </button>
                          </div>
                        </div>
                      ))}
                  </section>
                </div>
              )}

              {/* TAB 2: LIBRARY */}
              {activeTab === 'library' && (
                <div className="space-y-5">
                  {/* Signing & Target Controls */}
                  <div className="rounded-xl border border-slate-800 bg-[#121722] p-4 space-y-3">
                    <div className="flex items-center justify-between gap-3">
                      <label htmlFor="sim-target-select" className="text-xs font-medium text-slate-300">
                        Install Target
                      </label>
                      <select
                        id="sim-target-select"
                        value={selectedDeviceId}
                        onChange={(e) => setSelectedDeviceId(e.target.value)}
                        className="rounded-lg border border-slate-700 bg-[#0A0D13] px-2.5 py-1.5 text-xs text-slate-100 focus:border-blue-500 focus:outline-none"
                      >
                        {devices.map((d) => (
                          <option key={d.id} value={d.id}>
                            {d.name} ({d.kind})
                          </option>
                        ))}
                      </select>
                    </div>

                    <div className="flex items-center justify-between border-t border-slate-800/80 pt-3">
                      <div>
                        <div className="text-xs font-medium text-slate-200">Custom .p12 &amp; .mobileprovision</div>
                        <div className="text-[11px] text-slate-400">
                          {useCustomP12
                            ? 'Using imported Ad-Hoc / Enterprise certificate'
                            : 'Using Free Apple ID Personal Team provisioner'}
                        </div>
                      </div>
                      <button
                        type="button"
                        role="switch"
                        aria-checked={useCustomP12}
                        onClick={() => setUseCustomP12(!useCustomP12)}
                        className={`relative h-5 w-9 rounded-full transition-colors ${
                          useCustomP12 ? 'bg-blue-600' : 'bg-slate-700'
                        }`}
                      >
                        <span
                          className={`block h-4 w-4 rounded-full bg-white transition-transform ${
                            useCustomP12 ? 'translate-x-4.5' : 'translate-x-0.5'
                          }`}
                        />
                      </button>
                    </div>

                    {useCustomP12 && (
                      <div className="space-y-2.5 border-t border-slate-800/80 pt-3">
                        <div className="flex flex-wrap gap-2">
                          <button
                            type="button"
                            onClick={() => p12InputRef.current?.click()}
                            className="rounded-md bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
                          >
                            {customP12Name ? `Loaded: ${customP12Name}` : 'Import .p12'}
                          </button>
                          <button
                            type="button"
                            onClick={() => provInputRef.current?.click()}
                            className="rounded-md bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
                          >
                            {customProfileName ? `Loaded: ${customProfileName}` : 'Import .mobileprovision'}
                          </button>
                        </div>
                        <input
                          type="password"
                          value={customP12Pass}
                          onChange={(e) => setCustomP12Pass(e.target.value)}
                          placeholder="PKCS#12 certificate passphrase"
                          className="w-full rounded-lg border border-slate-700 bg-[#0A0D13] px-3 py-1.5 text-xs text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
                        />
                        <label className="flex items-center gap-2 text-xs text-slate-300">
                          <input
                            type="checkbox"
                            checked={enableOTAFallback}
                            onChange={(e) => setEnableOTAFallback(e.target.checked)}
                            className="rounded border-slate-600 bg-slate-900"
                          />
                          Generate <span className="font-mono text-slate-200">itms-services://</span> OTA manifest fallback
                        </label>
                      </div>
                    )}
                  </div>

                  {/* IPA Package List */}
                  <div className="space-y-2.5">
                    <div className="flex items-center justify-between text-xs font-medium text-slate-400">
                      <span>Imported IPA Packages ({ipas.length})</span>
                      <button
                        type="button"
                        onClick={() => ipaInputRef.current?.click()}
                        className="text-blue-400 hover:text-blue-300"
                      >
                        + Add .ipa from disk
                      </button>
                    </div>

                    {ipas.map((ipa) => (
                      <div
                        key={ipa.id}
                        className="flex items-center justify-between gap-3 rounded-xl border border-slate-800 bg-[#121722] p-3.5"
                      >
                        <div className="min-w-0">
                          <div className="text-sm font-semibold text-white truncate">{ipa.name}</div>
                          <div className="mt-0.5 font-mono text-xs text-slate-400 truncate">
                            {ipa.bundleId} · v{ipa.version} · {ipa.sizeMB} MB
                          </div>
                          <div className="mt-1 text-[11px] text-slate-500">
                            {ipa.nestedFrameworks} frameworks · {ipa.standaloneDylibs} dylibs
                            {ipa.hasFairPlaySinf ? (
                              <span className="ml-1.5 text-amber-400">· FairPlay .sinf detected</span>
                            ) : (
                              <span> · Decrypted arm64</span>
                            )}
                          </div>
                        </div>

                        <button
                          type="button"
                          disabled={isInstalling}
                          onClick={() => runInstallPipeline(ipa)}
                          className="flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-50 transition-colors whitespace-nowrap shrink-0"
                        >
                          <Play className="h-3 w-3" />
                          Install
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* TAB 3: APPS / REPOSITORIES */}
              {activeTab === 'apps' && (
                <div className="space-y-5">
                  <div className="rounded-xl border border-slate-800 bg-[#121722] p-4 space-y-2.5">
                    <div className="text-xs font-medium text-slate-300">Direct IPA URL Download</div>
                    <div className="flex gap-2">
                      <input
                        type="url"
                        value={directUrl}
                        onChange={(e) => setDirectUrl(e.target.value)}
                        placeholder="https://archive.org/download/.../app.ipa"
                        className="flex-1 rounded-lg border border-slate-700 bg-[#0A0D13] px-3 py-1.5 font-mono text-xs text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
                      />
                      <button
                        type="button"
                        onClick={handleDirectUrlFetch}
                        disabled={!directUrl.trim() || downloadingId !== null}
                        className="rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-50 whitespace-nowrap shrink-0"
                      >
                        {downloadingId === 'direct-url' ? 'Fetching...' : 'Fetch'}
                      </button>
                    </div>
                  </div>

                  <div className="space-y-2.5">
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-xs font-medium text-slate-400">Archive.org Decrypted IPA Collection</span>
                      <input
                        type="text"
                        value={repoSearch}
                        onChange={(e) => setRepoSearch(e.target.value)}
                        placeholder="Filter packages..."
                        className="w-40 rounded-lg border border-slate-800 bg-[#121722] px-2.5 py-1 text-xs text-slate-200 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
                      />
                    </div>

                    {filteredRepoApps.map((app) => (
                      <div key={app.id} className="rounded-xl border border-slate-800 bg-[#121722] p-3.5">
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="text-sm font-semibold text-white">{app.name}</div>
                            <div className="mt-0.5 font-mono text-xs text-slate-400">
                              {app.developer} · v{app.version} · {app.sizeMB} MB
                            </div>
                            <p className="mt-1.5 text-xs text-slate-400 leading-relaxed">{app.summary}</p>
                          </div>
                          <button
                            type="button"
                            disabled={downloadingId !== null}
                            onClick={() => handleDownloadRepoApp(app)}
                            className="rounded-lg bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-100 hover:bg-slate-700 disabled:opacity-50 whitespace-nowrap shrink-0"
                          >
                            {downloadingId === app.id ? 'Saving...' : 'Get'}
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* TAB 4: QUEUE & PROTOCOL CONSOLE */}
              {activeTab === 'queue' && (
                <div className="flex h-full flex-col space-y-4">
                  {/* 4-Stage Stepper */}
                  <div className="rounded-xl border border-slate-800 bg-[#121722] p-4">
                    <div className="grid grid-cols-4 gap-2">
                      {STAGE_LABELS.map((label, idx) => {
                        const completed = idx < installStage || (!isInstalling && idx === 3 && stageProgress === 1 && !installError);
                        const active = idx === installStage && isInstalling;
                        const failed = idx === installStage && !!installError;
                        return (
                          <div key={label} className="space-y-1.5">
                            <div
                              className={`h-1.5 rounded-full transition-colors ${
                                failed
                                  ? 'bg-red-500'
                                  : completed
                                  ? 'bg-emerald-500'
                                  : active
                                  ? 'bg-blue-500'
                                  : 'bg-slate-800'
                              }`}
                            />
                            <div
                              className={`text-[11px] font-medium truncate ${
                                failed
                                  ? 'text-red-400'
                                  : active || completed
                                  ? 'text-slate-100'
                                  : 'text-slate-500'
                              }`}
                            >
                              {label}
                            </div>
                          </div>
                        );
                      })}
                    </div>

                    <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                      <div
                        className={`h-full transition-all duration-300 ${
                          installError ? 'bg-red-500' : 'bg-blue-500'
                        }`}
                        style={{ width: `${Math.round(stageProgress * 100)}%` }}
                      />
                    </div>
                    <div className="mt-2 font-mono text-xs text-slate-300">{stageMessage}</div>
                    {installError && (
                      <div className="mt-2.5 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-950/40 p-2.5 text-xs text-red-200">
                        <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-red-400" />
                        <span>{installError}</span>
                      </div>
                    )}
                  </div>

                  {/* Filter Bar & Log Actions */}
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap gap-1">
                      {(['ALL', 'LOCKDOWN_TX', 'LOCKDOWN_RX', 'AFC', 'INSTPROXY', 'SIGN', 'PROVISION'] as const).map(
                        (cat) => (
                          <button
                            key={cat}
                            type="button"
                            onClick={() => setLogFilter(cat)}
                            className={`rounded-md px-2 py-1 font-mono text-[10px] font-medium transition-colors whitespace-nowrap shrink-0 ${
                              logFilter === cat
                                ? 'bg-blue-600 text-white'
                                : 'bg-slate-800/80 text-slate-400 hover:text-slate-200'
                            }`}
                          >
                            {cat}
                          </button>
                        )
                      )}
                    </div>
                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={handleCopyLogs}
                        className="flex items-center gap-1 rounded-md bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700"
                      >
                        {copiedLogs ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                        {copiedLogs ? 'Copied' : 'Copy'}
                      </button>
                      <button
                        type="button"
                        onClick={handleExportLogs}
                        className="flex items-center gap-1 rounded-md bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700"
                      >
                        <Download className="h-3 w-3" />
                        Export
                      </button>
                      <button
                        type="button"
                        onClick={() => setLogs([])}
                        aria-label="Clear logs"
                        className="rounded-md bg-slate-800 p-1 text-slate-400 hover:text-slate-200"
                      >
                        <Trash2 className="h-3 w-3" />
                      </button>
                    </div>
                  </div>

                  {/* Redacted Diagnostic Protocol Log Console */}
                  <div className="flex-1 overflow-y-auto rounded-xl border border-slate-800 bg-[#080A0F] p-3 font-mono text-[11px] leading-relaxed">
                    {filteredLogs.length === 0 ? (
                      <div className="py-8 text-center text-slate-500">
                        No protocol logs matching filter. Run Test Connection or Install an IPA.
                      </div>
                    ) : (
                      <div className="space-y-1.5">
                        {filteredLogs.map((entry) => (
                          <div key={entry.id} className="flex items-start gap-2">
                            <span className="shrink-0 text-slate-500 tabular-nums">{entry.timestamp}</span>
                            <span
                              className={`w-[86px] shrink-0 font-semibold ${
                                entry.isError ? 'text-red-400' : 'text-blue-400'
                              }`}
                            >
                              {entry.category}
                            </span>
                            <span className={entry.isError ? 'text-red-300 break-all' : 'text-slate-200 break-all'}>
                              {entry.message}
                            </span>
                          </div>
                        ))}
                        <div ref={logEndRef} />
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* TAB 5: ACCOUNT */}
              {activeTab === 'account' && (
                <div className="space-y-5">
                  {account ? (
                    <>
                      <div className="rounded-xl border border-slate-800 bg-[#121722] p-4 space-y-3">
                        <div className="flex items-center justify-between">
                          <div>
                            <div className="text-sm font-semibold text-white">{account.appleId}</div>
                            <div className="mt-0.5 font-mono text-xs text-slate-400">
                              Team {account.teamId} · {account.teamName}
                            </div>
                          </div>
                          <button
                            type="button"
                            onClick={() => setAccount(null)}
                            className="rounded-lg border border-red-500/30 bg-red-950/30 px-2.5 py-1 text-xs font-medium text-red-300 hover:bg-red-950/60"
                          >
                            Sign Out
                          </button>
                        </div>

                        <div className="border-t border-slate-800/80 pt-3 space-y-1.5 text-xs">
                          <div className="flex justify-between">
                            <span className="text-slate-400">Portal Certificate Status</span>
                            <span
                              className={`font-mono font-medium ${
                                account.certStatus === 'Active' ? 'text-emerald-400' : 'text-amber-400'
                              }`}
                            >
                              {account.certStatus} (WWDR {account.wwdrGeneration})
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-400">Serial Number</span>
                            <span className="font-mono text-slate-200">{account.certSerial}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-400">Leaf SHA-1 Thumbprint</span>
                            <span className="font-mono text-slate-200">{account.certSha1.slice(0, 18)}...</span>
                          </div>
                        </div>

                        <div className="flex gap-2 pt-1">
                          <button
                            type="button"
                            onClick={() => {
                              appendLog('PROVISION', `listAllDevelopmentCerts(teamId=${account.teamId}) -> verified ${account.certSerial}`);
                              setAccount((prev) => (prev ? { ...prev, certStatus: 'Active' } : prev));
                            }}
                            className="rounded-md bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
                          >
                            Verify Active Cert
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              setAccount((prev) => (prev ? { ...prev, certStatus: 'Revoked Externally' } : prev));
                              appendLog('PROVISION', 'Simulated external cert revocation (Sideloadly/AltStore) — next install will auto-recreate CSR', true);
                            }}
                            className="rounded-md bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-amber-300 hover:bg-slate-700"
                          >
                            Simulate External Revoke
                          </button>
                        </div>
                      </div>

                      <div className="rounded-xl border border-slate-800 bg-[#121722] p-4 space-y-3">
                        <div className="flex items-center justify-between text-xs">
                          <span className="font-medium text-slate-200">Weekly App ID Quota</span>
                          <span className="font-mono text-slate-300 tabular-nums">{appIds.length} / 10 slots used</span>
                        </div>
                        <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                          <div
                            className="h-full bg-blue-500"
                            style={{ width: `${Math.min(100, (appIds.length / 10) * 100)}%` }}
                          />
                        </div>
                        <div className="divide-y divide-slate-800/70">
                          {appIds.map((rec) => (
                            <div key={rec.id} className="flex items-center justify-between py-2 text-xs">
                              <div className="min-w-0">
                                <div className="font-medium text-slate-200">{rec.name}</div>
                                <div className="font-mono text-[11px] text-slate-500 truncate">{rec.identifier}</div>
                              </div>
                              <span className="shrink-0 font-mono text-[11px] text-slate-400 tabular-nums">
                                {rec.expiresInDays}d left
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </>
                  ) : (
                    <div className="rounded-xl border border-slate-800 bg-[#121722] p-4 space-y-3">
                      <div className="text-sm font-semibold text-white">GrandSlam SRP-6a Sign In</div>
                      <p className="text-xs text-slate-400">
                        Authenticates directly with <span className="font-mono text-slate-300">gsa.apple.com</span> using
                        Anisette v3 headers and decrypts <span className="font-mono text-slate-300">com.apple.gs.xcode.auth</span> via AES-256-GCM.
                      </p>
                      <input
                        type="email"
                        value={loginEmail}
                        onChange={(e) => setLoginEmail(e.target.value)}
                        placeholder="Apple ID email"
                        className="w-full rounded-lg border border-slate-700 bg-[#0A0D13] px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
                      />
                      <input
                        type="password"
                        value={loginPass}
                        onChange={(e) => setLoginPass(e.target.value)}
                        placeholder="Password"
                        className="w-full rounded-lg border border-slate-700 bg-[#0A0D13] px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
                      />
                      <button
                        type="button"
                        onClick={handleAppleSignIn}
                        className="w-full rounded-lg bg-blue-600 py-2 text-xs font-medium text-white hover:bg-blue-500"
                      >
                        Authenticate via SRP-6a
                      </button>

                      {awaiting2FA && (
                        <div className="space-y-2 border-t border-slate-800 pt-3">
                          <div className="text-xs font-medium text-slate-200">Trusted Device / SMS 2FA Code</div>
                          <div className="flex gap-2">
                            <input
                              type="text"
                              maxLength={6}
                              value={twoFactorCode}
                              onChange={(e) => setTwoFactorCode(e.target.value)}
                              placeholder="6-digit code (e.g. 482910)"
                              className="flex-1 rounded-lg border border-slate-700 bg-[#0A0D13] px-3 py-1.5 font-mono text-xs text-slate-100 focus:border-blue-500 focus:outline-none"
                            />
                            <button
                              type="button"
                              onClick={handleVerify2FA}
                              className="rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-emerald-500"
                            >
                              Verify
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* TAB 6: SETUP WIZARD */}
              {activeTab === 'setup' && (
                <div className="space-y-3">
                  {[
                    {
                      step: '01',
                      title: 'Import .mobiledevicepairing File',
                      detail: 'Generate via JitterbugPair, idevicepair, or Android SideBridge export and import into shared Keychain.',
                      done: devices[0].paired,
                      actionLabel: 'Import File',
                      onAction: () => pairingInputRef.current?.click(),
                    },
                    {
                      step: '02',
                      title: 'Enable Local Loopback VPN Tunnel',
                      detail: 'Starts local-only SideBridgeTunnel NEPacketTunnelProvider routing 10.7.0.1 to host lockdownd :62078.',
                      done: tunnelActive,
                      actionLabel: tunnelActive ? 'Stop Tunnel' : 'Enable Tunnel',
                      onAction: handleToggleTunnel,
                    },
                    {
                      step: '03',
                      title: 'Enable iOS 16+ Developer Mode',
                      detail: 'Settings -> Privacy & Security -> Developer Mode -> Toggle On and restart device.',
                      done: devModeEnabled,
                      actionLabel: devModeEnabled ? 'Confirmed' : 'Mark Enabled',
                      onAction: () => setDevModeEnabled(!devModeEnabled),
                    },
                    {
                      step: '04',
                      title: 'Trust Developer Profile',
                      detail: 'Settings -> General -> VPN & Device Management -> Tap Trust on your Personal Team profile.',
                      done: profileTrusted,
                      actionLabel: profileTrusted ? 'Trusted' : 'Mark Trusted',
                      onAction: () => setProfileTrusted(!profileTrusted),
                    },
                  ].map((item) => (
                    <div key={item.step} className="rounded-xl border border-slate-800 bg-[#121722] p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <div className="text-sm font-semibold text-white">
                            {item.step}. {item.title}
                          </div>
                          <p className="mt-1 text-xs text-slate-400 leading-relaxed">{item.detail}</p>
                        </div>
                        <span
                          className={`shrink-0 font-mono text-xs font-medium ${
                            item.done ? 'text-emerald-400' : 'text-amber-400'
                          }`}
                        >
                          {item.done ? 'Ready' : 'Pending'}
                        </span>
                      </div>
                      <div className="mt-3">
                        <button
                          type="button"
                          onClick={item.onAction}
                          className="rounded-md bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
                        >
                          {item.actionLabel}
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* iOS 6-Tab Bottom TabBar */}
            <div className="grid grid-cols-6 border-t border-slate-800/80 bg-[#0A0D13] px-1 py-2">
              {(
                [
                  { id: 'devices', label: 'Devices', icon: Wifi },
                  { id: 'library', label: 'Library', icon: Package },
                  { id: 'apps', label: 'Apps', icon: FolderOpen },
                  { id: 'queue', label: 'Queue', icon: Terminal },
                  { id: 'account', label: 'Account', icon: KeyRound },
                  { id: 'setup', label: 'Setup', icon: ListChecks },
                ] as const
              ).map(({ id, label, icon: Icon }) => {
                const active = activeTab === id;
                return (
                  <button
                    key={id}
                    type="button"
                    onClick={() => setActiveTab(id)}
                    className={`flex flex-col items-center gap-1 py-1 text-[10px] font-medium transition-colors ${
                      active ? 'text-blue-400' : 'text-slate-500 hover:text-slate-300'
                    }`}
                  >
                    <Icon className="h-4 w-4" />
                    <span className="truncate">{label}</span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right Column: Synchronized Engineering & Fault Injection Inspector */}
        <div className={`space-y-5 ${formFactor === 'ipad' ? 'lg:col-span-4' : 'lg:col-span-5'}`}>
          {/* Quick Actions & Fault Injection Scenarios */}
          <div className="rounded-xl border border-slate-800 bg-[#11151E] p-5 space-y-4">
            <div>
              <h3 className="text-sm font-semibold text-white">Pipeline Verification Scenarios</h3>
              <p className="mt-1 text-xs text-slate-400">
                Select a runtime condition before clicking <span className="text-slate-200">Install</span> in Library to verify SideBridge&apos;s error handling and automatic recovery.
              </p>
            </div>

            <div className="space-y-1.5">
              {(
                [
                  { id: 'none', label: 'Nominal Install (Full 4-Stage Success)' },
                  { id: 'usb_fallback_wifi', label: 'USB-C OTG Unplugged -> Auto Wi-Fi Bonjour Fallback' },
                  { id: 'cert_revoked_auto_reissue', label: 'External Cert Revocation -> Auto CSR Re-Issue' },
                  { id: 'developer_mode_off', label: 'iOS 16+ Developer Mode Disabled Error' },
                  { id: 'device_locked', label: 'Target Device Passcode Locked Error' },
                ] as const
              ).map((scenario) => (
                <button
                  key={scenario.id}
                  type="button"
                  onClick={() => setFaultMode(scenario.id)}
                  className={`flex w-full items-center justify-between rounded-lg border px-3 py-2 text-left text-xs font-medium transition-colors ${
                    faultMode === scenario.id
                      ? 'border-blue-500/60 bg-blue-500/10 text-blue-200'
                      : 'border-slate-800 bg-[#0D1017] text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <span>{scenario.label}</span>
                  {faultMode === scenario.id && <Check className="h-3.5 w-3.5 shrink-0 text-blue-400" />}
                </button>
              ))}
            </div>

            <div className="flex flex-wrap gap-2 border-t border-slate-800 pt-3">
              <button
                type="button"
                disabled={isInstalling}
                onClick={() => runInstallPipeline(ipas[0])}
                className="flex items-center gap-1.5 rounded-lg bg-blue-600 px-3.5 py-2 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-50 transition-colors whitespace-nowrap shrink-0"
              >
                <Play className="h-3.5 w-3.5" />
                Run Full 4-Stage Install
              </button>
              <button
                type="button"
                onClick={() => ipaInputRef.current?.click()}
                className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/60 px-3 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
              >
                <Upload className="h-3.5 w-3.5" />
                Inspect Local .ipa
              </button>
            </div>
          </div>

          {/* Active Route & CoreTrust Invariants Summary */}
          <div className="rounded-xl border border-slate-800 bg-[#11151E] p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white">Active Transport &amp; Signing Context</h3>
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
            </div>

            <div className="divide-y divide-slate-800/70 text-xs">
              <div className="flex items-center justify-between py-2">
                <span className="text-slate-400">Selected Endpoint</span>
                <span className="font-mono text-slate-200">
                  {selectedDevice.host}:{selectedDevice.port}
                </span>
              </div>
              <div className="flex items-center justify-between py-2">
                <span className="text-slate-400">TLS Layer</span>
                <span className="font-mono text-slate-200">OpenSSL BIO_s_mem (TLS 1.2)</span>
              </div>
              <div className="flex items-center justify-between py-2">
                <span className="text-slate-400">AFC Wire Framing</span>
                <span className="font-mono text-slate-200">CFA6LPAA · 64KB chunks</span>
              </div>
              <div className="flex items-center justify-between py-2">
                <span className="text-slate-400">CMS Attributes</span>
                <span className="font-mono text-slate-200">Exact 5 (No RFC 6211)</span>
              </div>
              <div className="flex items-center justify-between py-2">
                <span className="text-slate-400">WWDR Chain</span>
                <span className="font-mono text-slate-200">Bundled G1 – G6 PEM</span>
              </div>
              <div className="flex items-center justify-between py-2">
                <span className="text-slate-400">ZIP Packaging</span>
                <span className="font-mono text-slate-200">STORED dirs · 0755 (0x81ED)</span>
              </div>
            </div>
          </div>

          {/* Synchronized Swift Implementation Links */}
          <div className="rounded-xl border border-slate-800 bg-[#11151E] p-5 space-y-3">
            <div>
              <h3 className="text-sm font-semibold text-white">{activeSwiftMap.title}</h3>
              <p className="mt-0.5 text-xs text-slate-400">
                Inspect the native Swift 5.9+ modules backing the active simulator view.
              </p>
            </div>
            <div className="space-y-1.5">
              {activeSwiftMap.files.map((item) => (
                <button
                  key={item.path}
                  type="button"
                  onClick={() => onInspectSwiftFile(item.path)}
                  className="flex w-full items-center justify-between rounded-lg border border-slate-800/80 bg-[#0D1017] px-3 py-2 text-left transition-colors hover:border-slate-700 hover:bg-slate-900"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <FileCode2 className="h-3.5 w-3.5 shrink-0 text-blue-400" />
                    <span className="font-mono text-xs text-slate-200 truncate">{item.label}</span>
                  </div>
                  <ChevronRight className="h-3.5 w-3.5 shrink-0 text-slate-500" />
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
