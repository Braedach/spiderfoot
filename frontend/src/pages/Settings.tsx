import { useState, useMemo, useRef, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  configApi,
} from '../lib/api';
import {
  isCredentialOption, metaForGlobalKey, GLOBAL_GROUPS, type SettingsTab,
} from '../lib/settingsMeta';
import {
  Settings as SettingsIcon, Globe, Upload, Download,
  RotateCcw, Save, Eye, EyeOff, AlertTriangle,
  Loader2, Database, Sparkles,
} from 'lucide-react';
import {
  PageHeader, SearchInput, Toast, ConfirmDialog, EmptyState, Tabs, InfoNote,
  Skeleton,
  type ToastType,
} from '../components/ui';
import { useDocumentTitle } from '../hooks/useDocumentTitle';
import { LOG_FONT_SIZES, setLogFontSize, useLogFontSize, type LogFontSize } from '../lib/logFontSize';

export default function SettingsPage() {
  useDocumentTitle('Settings');
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<SettingsTab>('system');
  const logFontSize = useLogFontSize();
  const [selectedSection, setActiveSection] = useState('global:core');
  const [search, setSearch] = useState('');
  const [toast, setToast] = useState<{ type: ToastType; message: string } | null>(null);
  const [confirmReset, setConfirmReset] = useState(false);
  const [editedValues, setEditedValues] = useState<Record<string, string>>({});
  const [showPasswords, setShowPasswords] = useState<Set<string>>(new Set());
  const importInputRef = useRef<HTMLInputElement>(null);

  /* Queries */
  const { data: configData, isLoading: configLoading } = useQuery({
    queryKey: ['config'],
    queryFn: ({ signal }) => configApi.get(signal),
  });

  const config = configData?.config ?? {};

  /* Global options: config keys that are not internal */
  const globalOptions = useMemo(() => {
    return Object.entries(config).filter(([k]) => !k.startsWith('__'));
  }, [config]);

  /* Sidebar sections: one per non-empty global group, plus one per module
     that has non-credential opts. Modules whose *only* opts are
     credentials (API keys, tokens, passwords) don't appear here at all —
     they live on the Data Source Credentials page instead. */
  const sections = useMemo(() => {
    const groupCounts = new Map<string, number>();
    for (const [k] of globalOptions) {
      const g = metaForGlobalKey(k).group;
      groupCounts.set(g, (groupCounts.get(g) ?? 0) + 1);
    }
    const items: { key: string; label: string; count: number }[] = [];
    for (const [groupId, meta] of Object.entries(GLOBAL_GROUPS).sort((a, b) => a[1].order - b[1].order)) {
      if (meta.hideFromSettingsSidebar || meta.tab !== tab) continue;
      const count = groupCounts.get(groupId) ?? 0;
      if (count === 0) continue;
      items.push({ key: `global:${groupId}`, label: meta.label, count });
    }

    if (search) {
      const q = search.toLowerCase();
      return items.filter((i) => i.label.toLowerCase().includes(q) || i.key.toLowerCase().includes(q));
    }
    return items;
  }, [globalOptions, search, tab]);

  /* The selection can belong to another tab; fall back to this tab's first section. */
  const activeSection = sections.some((x) => x.key === selectedSection) ? selectedSection : (sections[0]?.key ?? '');

  const activeGroup = activeSection.startsWith('global:') ? activeSection.slice(7) : null;

  /* Current section options */
  const currentOptions = useMemo(() => {
    if (!activeGroup) return [];
    return globalOptions
      .filter(([k]) => metaForGlobalKey(k).group === activeGroup)
      .map(([k, v]) => {
        const meta = metaForGlobalKey(k);
        return { key: k, value: v, description: meta.description, label: meta.label };
      });
  }, [activeGroup, globalOptions]);

  /* Save: global options via PATCH /config. Module options are edited on the Modules page. */
  const saveMut = useMutation({
    mutationFn: async (edited: Record<string, string>) => {
      await configApi.update(edited);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['config'] });
      queryClient.invalidateQueries({ queryKey: ['modules'] });
      setEditedValues({});
      setToast({ type: 'success', message: 'Settings saved' });
    },
    onError: () => setToast({ type: 'error', message: 'Failed to save settings' }),
  });

  /* Import/Export */
  const handleExport = async () => {
    try {
      const data = await configApi.exportConfig();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'spiderfoot-config.json';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setToast({ type: 'success', message: 'Configuration exported' });
    } catch {
      setToast({ type: 'error', message: 'Export failed' });
    }
  };

  const handleImport = () => {
    importInputRef.current?.click();
  };

  const onImportFileChange = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      await configApi.importConfig(parsed);
      queryClient.invalidateQueries({ queryKey: ['config'] });
      setToast({ type: 'success', message: 'Configuration imported' });
    } catch {
      setToast({ type: 'error', message: 'Import failed — invalid JSON' });
    }
    // Reset the input so the same file can be re-imported
    if (importInputRef.current) importInputRef.current.value = '';
  }, [queryClient]);

  /* Reset */
  const handleReset = async () => {
    try {
      await configApi.reload();
      queryClient.invalidateQueries({ queryKey: ['config'] });
      queryClient.invalidateQueries({ queryKey: ['modules'] });
      setConfirmReset(false);
      setEditedValues({});
      setToast({ type: 'success', message: 'Reset to factory defaults' });
    } catch {
      setToast({ type: 'error', message: 'Reset failed' });
    }
  };

  const handleSave = () => {
    if (Object.keys(editedValues).length === 0) return;
    saveMut.mutate(editedValues);
  };

  const togglePassword = (key: string) => {
    const next = new Set(showPasswords);
    next.has(key) ? next.delete(key) : next.add(key);
    setShowPasswords(next);
  };

  return (
    <div className="space-y-6">
      {/* Hidden file input for config import (ref-based to avoid orphan DOM nodes) */}
      <input
        ref={importInputRef}
        type="file"
        accept=".json"
        className="hidden"
        onChange={onImportFileChange}
      />
      <PageHeader title="Settings" subtitle="Core platform configuration. Module options and API keys are edited on the Modules page; the LLM provider on AI Connections.">
        <div className="flex gap-2">
          <button className="btn-secondary text-sm" onClick={handleImport}>
            <Upload className="h-3.5 w-3.5" /> Import
          </button>
          <button className="btn-secondary text-sm" onClick={handleExport}>
            <Download className="h-3.5 w-3.5" /> Export
          </button>
          <button className="btn-ghost text-sm text-red-400" onClick={() => setConfirmReset(true)}>
            <RotateCcw className="h-3.5 w-3.5" /> Reset
          </button>
        </div>
      </PageHeader>

      <Tabs<SettingsTab>
        tabs={[
          { key: 'system', label: 'System', icon: SettingsIcon },
          { key: 'data', label: 'Data & Storage', icon: Database },
          { key: 'ai', label: 'AI & Search', icon: Sparkles },
        ]}
        active={tab}
        onChange={setTab}
      />

      <InfoNote className="mt-4">
        {tab === 'system' && (
          <p>How the scan engine behaves, how outbound lookups and requests are made, and where the web UI and API listen. The DNS server set under Network &amp; Proxy is used only to look up scan targets and other public names; the stack&apos;s own services are always found through the container network&apos;s built-in DNS.</p>
        )}
        {tab === 'data' && (
          <p>Where scan results, cache, queues and files are stored. These point at the database, Redis and object storage services the stack runs; change them only if you move those services.</p>
        )}
        {tab === 'ai' && (
          <p>The embedding, reranking and vector-search settings behind correlation and AI reports. The LLM provider itself (and its API key) is set on AI Connections.</p>
        )}
      </InfoNote>

      {tab === 'system' && (
        <div className="card mt-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-foreground">Log text size</h3>
            <p className="text-xs text-dark-400 mt-1">Size of the text in a scan&apos;s Log tab. Saved in this browser only.</p>
          </div>
          <select
            aria-label="Log text size"
            className="input-field w-auto min-w-[160px] text-sm"
            value={logFontSize}
            onChange={(e) => setLogFontSize(e.target.value as LogFontSize)}
          >
            {(Object.keys(LOG_FONT_SIZES) as LogFontSize[]).map((k) => (
              <option key={k} value={k}>{LOG_FONT_SIZES[k].label}</option>
            ))}
          </select>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mt-4">
        {/* Sidebar */}
        <div className="card p-0 overflow-hidden h-fit lg:sticky lg:top-4">
          <div className="p-3 border-b border-dark-700/50">
            <SearchInput value={search} onChange={setSearch} placeholder="Find section..." className="w-full" />
          </div>
          <div className="overflow-y-auto max-h-[600px]">
            {sections.map((s) => (
              <button
                key={s.key}
                onClick={() => setActiveSection(s.key)}
                className={`w-full flex items-center justify-between px-3 py-2.5 text-left text-sm transition-colors ${
                  activeSection === s.key
                    ? 'bg-spider-600/10 text-spider-400 border-l-2 border-spider-500'
                    : 'text-dark-300 hover:bg-dark-700/30 border-l-2 border-transparent'
                }`}
              >
                <div className="flex items-center gap-2 min-w-0">
                  <Globe className="h-3.5 w-3.5 flex-shrink-0 text-dark-500" />
                  <span className="truncate">{s.label}</span>
                </div>
                <span className="text-xs text-dark-600 tabular-nums">{s.count}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Options Panel */}
        <div className="lg:col-span-3 space-y-4">
          {/* Global group header */}
          {activeGroup && (
            <div className="card animate-fade-in">
              <h3 className="text-sm font-semibold text-foreground">{GLOBAL_GROUPS[activeGroup]?.label}</h3>
              <p className="text-xs text-dark-400 mt-1">{GLOBAL_GROUPS[activeGroup]?.description}</p>
            </div>
          )}

          {/* Options */}
          <div className="card animate-fade-in">
            {configLoading ? (
              <div className="space-y-4">
                {Array.from({ length: 5 }).map((_, i) => (
                  <div key={i} className="space-y-2">
                    <Skeleton className="h-4 w-32" />
                    <Skeleton className="h-10 w-full" />
                  </div>
                ))}
              </div>
            ) : currentOptions.length > 0 ? (
              <div className="space-y-5">
                {currentOptions.map((opt) => {
                  const optKey = opt.key;
                  const val = opt.value;
                  const optDesc = opt.description;
                  const editedVal = editedValues[optKey];
                  const currentVal = editedVal ?? String(val ?? '');
                  const shortKey = optKey.includes(':') ? optKey.split(':').slice(1).join(':') : optKey;
                  const displayLabel = opt.label || shortKey;
                  const isSensitive = isCredentialOption(shortKey);
                  const isHidden = isSensitive && !showPasswords.has(optKey);

                  // Detect value type for appropriate control
                  const rawVal = val as unknown;
                  const isBool = rawVal === true || rawVal === false || currentVal === 'true' || currentVal === 'false' || currentVal === 'True' || currentVal === 'False';
                  const isNumber = !isBool && !isSensitive && /^\d+(\.\d+)?$/.test(String(rawVal ?? ''));
                  const isMultiLine = !isBool && !isNumber && String(val ?? '').includes(',') && String(val ?? '').length > 40;

                  return (
                    <div key={optKey}>
                      <div className="flex items-center gap-2 mb-1">
                        <label className="text-sm text-dark-300 font-medium">{displayLabel}</label>
                        {isSensitive && (
                          <button
                            onClick={() => togglePassword(optKey)}
                            className="text-dark-500 hover:text-dark-300 transition-colors"
                          >
                            {isHidden ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                          </button>
                        )}
                        {isSensitive && !currentVal && (
                          <span className="text-yellow-500 text-[10px] flex items-center gap-0.5">
                            <AlertTriangle className="h-3 w-3" /> Not set
                          </span>
                        )}
                        {editedVal !== undefined && (
                          <span className="text-spider-400 text-[10px]">Modified</span>
                        )}
                      </div>
                      {optDesc && (
                        <p className="text-xs text-dark-500 mb-1.5">{optDesc}</p>
                      )}

                      {/* Boolean toggle */}
                      {isBool ? (
                        <button
                          onClick={() => {
                            const boolVal = currentVal === 'true' || currentVal === 'True';
                            setEditedValues((prev) => ({ ...prev, [optKey]: boolVal ? 'false' : 'true' }));
                          }}
                          className={`relative inline-flex h-7 w-12 items-center rounded-full transition-colors ${
                            (currentVal === 'true' || currentVal === 'True') ? 'bg-spider-500' : 'bg-dark-600'
                          }`}
                        >
                          <span className={`inline-block h-5 w-5 transform rounded-full bg-white shadow-sm transition-transform ${
                            (currentVal === 'true' || currentVal === 'True') ? 'translate-x-6' : 'translate-x-1'
                          }`} />
                        </button>
                      ) : isNumber ? (
                        <input
                          type="number"
                          className="input-field text-sm font-mono w-40"
                          value={currentVal}
                          onChange={(e) => {
                            setEditedValues((prev) => ({ ...prev, [optKey]: e.target.value }));
                          }}
                        />
                      ) : isMultiLine ? (
                        <textarea
                          className="input-field text-sm font-mono h-24 resize-y"
                          value={currentVal}
                          onChange={(e) => {
                            setEditedValues((prev) => ({ ...prev, [optKey]: e.target.value }));
                          }}
                          placeholder="Comma-separated values..."
                        />
                      ) : (
                        <input
                          type={isHidden ? 'password' : 'text'}
                          className="input-field text-sm font-mono"
                          value={currentVal}
                          onChange={(e) => {
                            setEditedValues((prev) => ({ ...prev, [optKey]: e.target.value }));
                          }}
                          placeholder={isSensitive ? 'Enter API key...' : ''}
                        />
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <EmptyState
                icon={SettingsIcon}
                title="No options"
                description="This section has no configurable options."
              />
            )}
          </div>

          {/* Save Bar */}
          {Object.keys(editedValues).length > 0 && (
            <div className="sticky bottom-4 card flex items-center justify-between animate-fade-in-up border border-spider-600/30">
              <p className="text-sm text-dark-300">
                {Object.keys(editedValues).length} unsaved change(s)
              </p>
              <div className="flex gap-2">
                <button className="btn-secondary" onClick={() => setEditedValues({})}>Discard</button>
                <button className="btn-primary" onClick={handleSave} disabled={saveMut.isPending}>
                  {saveMut.isPending ? (
                    <><Loader2 className="h-4 w-4 animate-spin" /> Saving...</>
                  ) : (
                    <><Save className="h-4 w-4" /> Save Changes</>
                  )}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Dialogs */}
      <ConfirmDialog
        open={confirmReset}
        title="Reset to Factory Defaults"
        message="This will reset ALL settings to their factory defaults. API keys and custom configurations will be lost."
        confirmLabel="Reset Everything"
        danger
        onConfirm={handleReset}
        onCancel={() => setConfirmReset(false)}
      />

      {toast && <Toast type={toast.type} message={toast.message} onClose={() => setToast(null)} />}
    </div>
  );
}
