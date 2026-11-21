import React, { useMemo, useState } from 'react';
import { Check, Copy, Download, FileCode2, Folder, Search } from 'lucide-react';
import {
  IOS_PROJECT_FILES,
  PROJECT_GROUPS,
  PROJECT_STATS,
  ProjectFile,
  downloadSingleProjectFile,
} from '../lib/iosProjectFiles';

interface XcodeExplorerViewProps {
  selectedFilePath: string;
  onSelectFilePath: (path: string) => void;
}

export const XcodeExplorerView: React.FC<XcodeExplorerViewProps> = ({
  selectedFilePath,
  onSelectFilePath,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [copied, setCopied] = useState(false);

  const filteredFiles = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return IOS_PROJECT_FILES;
    return IOS_PROJECT_FILES.filter(
      (f) =>
        f.path.toLowerCase().includes(q) ||
        f.group.toLowerCase().includes(q) ||
        f.content.toLowerCase().includes(q)
    );
  }, [searchQuery]);

  const activeFile: ProjectFile =
    IOS_PROJECT_FILES.find((f) => f.path === selectedFilePath) ?? IOS_PROJECT_FILES[0];

  const handleCopy = async () => {
    if (!activeFile) return;
    await navigator.clipboard.writeText(activeFile.content);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  };

  const lines = useMemo(() => activeFile?.content.split('\n') ?? [], [activeFile]);

  return (
    <div className="mx-auto max-w-[1440px] px-6 py-6">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-slate-100">
            Native iOS Xcode Project Source
          </h1>
          <div className="mt-1 text-xs text-slate-400 tabular-nums">
            {PROJECT_STATS.totalFiles} files · {PROJECT_STATS.swiftFiles} Swift 5.9+ modules ·{' '}
            {PROJECT_STATS.totalLines.toLocaleString()} lines · iOS 16.0+ arm64
          </div>
        </div>

        <div className="relative w-full max-w-xs">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search files or symbols (e.g. CFA6LPAA)..."
            className="w-full rounded-lg border border-slate-800 bg-[#11151E] py-1.5 pl-9 pr-3 text-xs text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
          />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left File Tree Sidebar */}
        <aside className="lg:col-span-4 xl:col-span-3">
          <div className="h-[680px] overflow-y-auto rounded-xl border border-slate-800 bg-[#11151E] p-3">
            {PROJECT_GROUPS.map((group) => {
              const groupFiles = filteredFiles.filter((f) => f.group === group);
              if (groupFiles.length === 0) return null;

              return (
                <div key={group} className="mb-4 last:mb-0">
                  <div className="mb-1.5 flex items-center gap-1.5 px-2 text-[11px] font-semibold text-slate-400">
                    <Folder className="h-3.5 w-3.5 text-slate-500" />
                    <span>{group}</span>
                  </div>
                  <div className="space-y-0.5">
                    {groupFiles.map((file) => {
                      const isActive = activeFile?.path === file.path;
                      return (
                        <button
                          key={file.path}
                          type="button"
                          onClick={() => onSelectFilePath(file.path)}
                          className={`flex w-full items-center justify-between rounded-lg px-2.5 py-1.5 text-left transition-colors ${
                            isActive
                              ? 'bg-blue-600/15 text-blue-300'
                              : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
                          }`}
                        >
                          <div className="flex items-center gap-2 min-w-0">
                            <FileCode2
                              className={`h-3.5 w-3.5 shrink-0 ${
                                isActive ? 'text-blue-400' : 'text-slate-500'
                              }`}
                            />
                            <span className="font-mono text-xs truncate">{file.name}</span>
                          </div>
                          <span className="ml-2 shrink-0 font-mono text-[10px] text-slate-500 tabular-nums">
                            {file.lines}L
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              );
            })}

            {filteredFiles.length === 0 && (
              <div className="py-12 text-center text-xs text-slate-500">
                No files match &ldquo;{searchQuery}&rdquo;.
              </div>
            )}
          </div>
        </aside>

        {/* Right Code Viewer */}
        <section className="lg:col-span-8 xl:col-span-9">
          {activeFile && (
            <div className="flex h-[680px] flex-col overflow-hidden rounded-xl border border-slate-800 bg-[#0D1017]">
              {/* File Header */}
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 bg-[#11151E] px-4 py-3">
                <div className="min-w-0">
                  <div className="font-mono text-xs font-semibold text-slate-100 truncate">
                    ios/SideBridge/{activeFile.path}
                  </div>
                  <div className="mt-0.5 text-[11px] text-slate-400 tabular-nums">
                    {activeFile.group} · {activeFile.lines} lines · {(activeFile.bytes / 1024).toFixed(1)} KB
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handleCopy}
                    className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0"
                  >
                    {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                    {copied ? 'Copied' : 'Copy File'}
                  </button>
                  <button
                    type="button"
                    onClick={() => downloadSingleProjectFile(activeFile)}
                    className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0"
                  >
                    <Download className="h-3.5 w-3.5" />
                    Save File
                  </button>
                </div>
              </div>

              {/* Code Content with Line Numbers */}
              <div className="flex-1 overflow-auto p-4 font-mono text-xs leading-5">
                <table className="w-full border-collapse">
                  <tbody>
                    {lines.map((line, index) => (
                      <tr key={index} className="hover:bg-slate-800/30">
                        <td className="w-12 select-none pr-4 text-right align-top text-slate-600 tabular-nums">
                          {index + 1}
                        </td>
                        <td className="whitespace-pre text-slate-200">{line || ' '}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </section>
      </div>
    </div>
  );
};
