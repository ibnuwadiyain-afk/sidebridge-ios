import JSZip from 'jszip';

export interface ProjectFile {
  path: string;          // e.g. "SideBridge/Core/Signing/DEREncoder.swift"
  name: string;          // e.g. "DEREncoder.swift"
  group: string;         // e.g. "Core / Signing"
  language: 'swift' | 'xml' | 'yaml' | 'c' | 'markdown';
  content: string;
  lines: number;
  bytes: number;
}

const rawModules = import.meta.glob(
  ['/ios/SideBridge/**/*', '/ios/SideBridge/.github/**/*'],
  {
    query: '?raw',
    import: 'default',
    eager: true,
  }
) as Record<string, string>;

function detectLanguage(path: string): ProjectFile['language'] {
  if (path.endsWith('.swift')) return 'swift';
  if (path.endsWith('.plist') || path.endsWith('.entitlements')) return 'xml';
  if (path.endsWith('.yml') || path.endsWith('.yaml')) return 'yaml';
  if (path.endsWith('.h')) return 'c';
  return 'markdown';
}

function detectGroup(relativePath: string): string {
  if (relativePath === 'project.yml' || relativePath === 'README.md') return 'Project Root';
  if (relativePath.startsWith('.github/')) return 'CI / CD (GitHub Actions)';
  if (relativePath.startsWith('SideBridgeTunnel/')) return 'Network Extension';
  if (relativePath.startsWith('SideBridge/Resources/') || relativePath.startsWith('SideBridge/Bridging/')) {
    return 'Entitlements & Bridging';
  }
  if (relativePath.startsWith('SideBridge/Core/Storage/')) return 'Core / Storage';
  if (relativePath.startsWith('SideBridge/Core/Transport/')) return 'Core / Transport';
  if (relativePath.startsWith('SideBridge/Core/Protocol/')) return 'Core / Protocol';
  if (relativePath.startsWith('SideBridge/Core/Provisioning/')) return 'Core / Provisioning';
  if (relativePath.startsWith('SideBridge/Core/Signing/')) return 'Core / Signing';
  if (relativePath.startsWith('SideBridge/Core/Installer/')) return 'Core / Installer';
  if (relativePath.startsWith('SideBridge/App/')) return 'App & ViewModel';
  if (relativePath.startsWith('SideBridge/Views/')) return 'SwiftUI Views';
  return 'Other';
}

const GROUP_ORDER = [
  'Project Root',
  'CI / CD (GitHub Actions)',
  'Entitlements & Bridging',
  'Network Extension',
  'Core / Storage',
  'Core / Transport',
  'Core / Protocol',
  'Core / Provisioning',
  'Core / Signing',
  'Core / Installer',
  'App & ViewModel',
  'SwiftUI Views',
];

export const IOS_PROJECT_FILES: ProjectFile[] = Object.entries(rawModules)
  .map(([fullPath, content]) => {
    const relativePath = fullPath.replace(/^\/ios\/SideBridge\//, '');
    const name = relativePath.split('/').pop() ?? relativePath;
    const text = typeof content === 'string' ? content : '';
    return {
      path: relativePath,
      name,
      group: detectGroup(relativePath),
      language: detectLanguage(relativePath),
      content: text,
      lines: text.split('\n').length,
      bytes: new TextEncoder().encode(text).length,
    };
  })
  .sort((a, b) => {
    const ga = GROUP_ORDER.indexOf(a.group);
    const gb = GROUP_ORDER.indexOf(b.group);
    if (ga !== gb) return (ga === -1 ? 99 : ga) - (gb === -1 ? 99 : gb);
    return a.path.localeCompare(b.path);
  });

export const PROJECT_GROUPS: string[] = GROUP_ORDER.filter((g) =>
  IOS_PROJECT_FILES.some((f) => f.group === g)
);

export const PROJECT_STATS = {
  totalFiles: IOS_PROJECT_FILES.length,
  swiftFiles: IOS_PROJECT_FILES.filter((f) => f.language === 'swift').length,
  totalLines: IOS_PROJECT_FILES.reduce((acc, f) => acc + f.lines, 0),
  totalBytes: IOS_PROJECT_FILES.reduce((acc, f) => acc + f.bytes, 0),
};

export async function downloadXcodeProjectZip(): Promise<void> {
  const zip = new JSZip();
  const root = zip.folder('SideBridge');
  if (!root) return;

  for (const file of IOS_PROJECT_FILES) {
    root.file(file.path, file.content);
  }

  const blob = await zip.generateAsync({ type: 'blob', compression: 'DEFLATE' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'SideBridge-iOS-Swift59.zip';
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function downloadSingleProjectFile(file: ProjectFile): void {
  const blob = new Blob([file.content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = file.name;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
