import React, { useState } from 'react';
import { Download } from 'lucide-react';
import { SimulatorView } from './components/SimulatorView';
import { XcodeExplorerView } from './components/XcodeExplorerView';
import { ArchitectureView } from './components/ArchitectureView';
import { ProtocolSpecView } from './components/ProtocolSpecView';
import { IOS_PROJECT_FILES, downloadXcodeProjectZip } from './lib/iosProjectFiles';

type WorkspaceRoute = 'simulator' | 'explorer' | 'architecture' | 'spec';

export default function App() {
  const [route, setRoute] = useState<WorkspaceRoute>('simulator');
  const [selectedFilePath, setSelectedFilePath] = useState<string>(
    IOS_PROJECT_FILES.find((f) => f.path.endsWith('DEREncoder.swift'))?.path ??
      IOS_PROJECT_FILES[0]?.path ??
      'project.yml'
  );
  const [isExporting, setIsExporting] = useState(false);

  const handleInspectSwiftFile = (relativePath: string) => {
    setSelectedFilePath(relativePath);
    setRoute('explorer');
  };

  const handleDownloadZip = async () => {
    if (isExporting) return;
    setIsExporting(true);
    try {
      await downloadXcodeProjectZip();
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#090B10] text-slate-100">
      {/* Strict 1-Row, 3-Zone Top Bar Contract */}
      <header className="sticky top-0 z-30 border-b border-slate-800/80 bg-[#090B10]/95 backdrop-blur">
        <div className="mx-auto flex max-w-[1440px] items-center justify-between gap-8 px-6 py-3.5">
          {/* Zone 1: Single text element wordmark */}
          <button
            type="button"
            onClick={() => setRoute('simulator')}
            className="text-lg font-bold tracking-tight text-white whitespace-nowrap shrink-0"
          >
            SideBridge
          </button>

          {/* Zone 2: 4 concise single-line text nav links */}
          <nav className="flex items-center gap-6 overflow-x-auto text-sm font-medium">
            {(
              [
                { id: 'simulator', label: 'Simulator' },
                { id: 'explorer', label: 'Xcode Project' },
                { id: 'architecture', label: 'Architecture' },
                { id: 'spec', label: 'Protocol Spec' },
              ] as const
            ).map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => setRoute(item.id)}
                className={`border-b-2 py-1 transition-colors whitespace-nowrap shrink-0 ${
                  route === item.id
                    ? 'border-blue-500 text-white'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                {item.label}
              </button>
            ))}
          </nav>

          {/* Zone 3: 1 primary CTA button */}
          <div className="shrink-0">
            <button
              type="button"
              disabled={isExporting}
              onClick={handleDownloadZip}
              className="flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-60 transition-colors whitespace-nowrap shrink-0"
            >
              <Download className="h-3.5 w-3.5" />
              {isExporting ? 'Packing ZIP...' : 'Download Xcode ZIP'}
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main>
        {route === 'simulator' && (
          <SimulatorView onInspectSwiftFile={handleInspectSwiftFile} />
        )}
        {route === 'explorer' && (
          <XcodeExplorerView
            selectedFilePath={selectedFilePath}
            onSelectFilePath={setSelectedFilePath}
          />
        )}
        {route === 'architecture' && (
          <ArchitectureView onInspectSwiftFile={handleInspectSwiftFile} />
        )}
        {route === 'spec' && (
          <ProtocolSpecView onInspectFile={handleInspectSwiftFile} />
        )}
      </main>
    </div>
  );
}
