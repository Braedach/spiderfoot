import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { dataApi, type Module } from '../lib/api';
import { useDocumentTitle } from '../hooks/useDocumentTitle';
import {
  Cpu, Lock, Unlock, KeyRound,
  ChevronDown, ChevronRight, Shield,
} from 'lucide-react';
import {
  PageHeader, SearchInput, StatCard, EmptyState, TableSkeleton, Toast, InfoNote, type ToastType,
} from '../components/ui';
import ModuleOptionsEditor from '../components/ModuleOptionsEditor';
import { moduleHasCredential, moduleCredentialStatus } from '../lib/settingsMeta';

type FilterKey = 'all' | 'needs_credential' | 'credential_missing';

export default function ModulesPage() {
  useDocumentTitle('Modules');
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<FilterKey>('all');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [toast, setToast] = useState<{ type: ToastType; message: string } | null>(null);

  const { data: modulesData, isLoading } = useQuery({
    queryKey: ['modules', { page: 1, page_size: 500 }],
    queryFn: ({ signal }) => dataApi.modules({ page: 1, page_size: 500 }, signal),
  });

  const modules: Module[] = modulesData?.items ?? [];

  // Derived from the modules themselves, not GET /api/data/module-categories —
  // that endpoint reliably returns an empty list live (confirmed 2026-10-25)
  // despite every module carrying real category data.
  const moduleCategory = (m: Module) =>
    (Array.isArray(m.cats) && m.cats[0]) || (Array.isArray(m.group) ? m.group[0] : m.group) || m.category || 'Other';
  const categories = useMemo(
    () => [...new Set(modules.map(moduleCategory))],
    [modules],
  );

  /* Filter & search */
  const filteredModules = useMemo(() => {
    let list = modules;
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(
        (m) =>
          m.name?.toLowerCase().includes(q) ||
          (m.descr || m.description || '').toLowerCase().includes(q) ||
          (Array.isArray(m.group) ? m.group.join(' ') : (m.group || '')).toLowerCase().includes(q) ||
          (Array.isArray(m.cats) ? m.cats.join(' ') : '').toLowerCase().includes(q),
      );
    }
    if (filter === 'needs_credential') list = list.filter((m) => moduleHasCredential(m.opts));
    if (filter === 'credential_missing') list = list.filter((m) => moduleCredentialStatus(m.opts) === 'missing');
    return list;
  }, [modules, search, filter]);

  /* Group by category */
  const grouped = useMemo(() => {
    const map = new Map<string, Module[]>();
    filteredModules.forEach((m) => {
      const cat = moduleCategory(m);
      if (!map.has(cat)) map.set(cat, []);
      map.get(cat)!.push(m);
    });
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [filteredModules]);

  const needsCredentialCount = useMemo(
    () => modules.filter((m) => moduleHasCredential(m.opts)).length,
    [modules],
  );

  return (
    <div className="space-y-6">
      <PageHeader title="Modules" subtitle={`${modules.length} data collection modules. Open one to edit its options and API key`} />

      <InfoNote title="What modules are" className="mb-4">
        <p>Each module collects one kind of information (DNS, certificates, breach data, web content, port scans and so on). A scan runs the modules you pick, and each one reacts to what the others find.</p>
        <p>
          <strong className="text-dark-100">Options</strong> tune how a module behaves.{' '}
          <strong className="text-dark-100">API keys</strong> unlock modules that query a third-party service; a module marked &quot;needs a key&quot; skips that service until one is saved here. Keys are stored encrypted.
        </p>
      </InfoNote>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
        <StatCard label="Total" value={modules.length} icon={Cpu} color="text-spider-400" loading={isLoading} delay={0} />
        <StatCard label="Categories" value={categories.length} icon={Shield} color="text-blue-400" loading={isLoading} delay={60} />
        <StatCard label="Need an API Key" value={needsCredentialCount} icon={KeyRound} color="text-yellow-400" loading={isLoading} delay={120} />
      </div>

      {/* Toolbar */}
      <div className="flex flex-col sm:flex-row gap-3 items-start sm:items-center">
        <SearchInput
          value={search}
          onChange={setSearch}
          placeholder="Search modules..."
          className="flex-1 max-w-md"
        />
        <div className="flex gap-2">
          {([
            ['all', 'All'],
            ['needs_credential', 'Needs API Key'],
            ['credential_missing', 'Key Missing'],
          ] as [FilterKey, string][]).map(([f, label]) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={filter === f ? 'tab-button-active text-xs' : 'tab-button text-xs'}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Module list */}
      {isLoading ? (
        <div className="card"><TableSkeleton rows={10} cols={5} /></div>
      ) : grouped.length > 0 ? (
        <div className="space-y-4">
          {grouped.map(([cat, mods]) => (
            <div key={cat} className="animate-fade-in">
              <h3 className="section-label mb-3 flex items-center gap-2">
                {cat}
                <span className="text-dark-600 text-[10px] tabular-nums">{mods.length}</span>
              </h3>
              <div className="space-y-1">
                {mods.map((m) => {
                  const credStatus = moduleCredentialStatus(m.opts);
                  const isExpanded = expanded === m.name;

                  return (
                    <div key={m.name} className="card-hover p-0 overflow-hidden">
                      <div className="flex items-center gap-3 px-4 py-3">
                        {/* Info */}
                        <div className="flex-1 min-w-0" onClick={() => setExpanded(isExpanded ? null : m.name)}>
                          <div className="flex items-center gap-2 cursor-pointer">
                            <span className="text-sm font-medium text-foreground">{m.name.replace('sfp_', '')}</span>
                            {credStatus === 'missing' && (
                              <span className="text-yellow-500" title="Needs an API key — set it on Data Source Credentials">
                                <Lock className="h-3 w-3" />
                              </span>
                            )}
                            {credStatus === 'configured' && (
                              <span className="text-green-400" title="API key configured">
                                <Unlock className="h-3 w-3" />
                              </span>
                            )}
                            {m.flags?.includes('slow') && (
                              <span className="badge bg-yellow-900/30 text-yellow-400 text-[9px] px-1 py-0">Slow</span>
                            )}
                            {m.flags?.includes('invasive') && (
                              <span className="badge bg-red-900/30 text-red-400 text-[9px] px-1 py-0">Invasive</span>
                            )}
                          </div>
                          <p className="text-xs text-dark-500 truncate">{m.descr || m.description}</p>
                        </div>

                        {/* Expand */}
                        <button
                          onClick={() => setExpanded(isExpanded ? null : m.name)}
                          className="btn-icon"
                        >
                          {isExpanded
                            ? <ChevronDown className="h-4 w-4 text-dark-400" />
                            : <ChevronRight className="h-4 w-4 text-dark-400" />}
                        </button>
                      </div>

                      {/* Expanded details */}
                      {isExpanded && (
                        <div className="px-4 pb-4 pt-1 border-t border-dark-700/30 animate-fade-in">
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div>
                              <p className="text-xs text-dark-500 mb-1">Category</p>
                              <p className="text-sm text-dark-300">{Array.isArray(m.group) ? m.group.join(', ') : (m.group || m.category || 'N/A')}</p>
                            </div>
                            {m.provides && m.provides.length > 0 && (
                              <div>
                                <p className="text-xs text-dark-500 mb-1">Produces</p>
                                <div className="flex flex-wrap gap-1">
                                  {m.provides.map((p) => (
                                    <span key={p} className="badge badge-info text-[10px]">{p}</span>
                                  ))}
                                </div>
                              </div>
                            )}
                            {m.consumes && m.consumes.length > 0 && (
                              <div>
                                <p className="text-xs text-dark-500 mb-1">Consumes</p>
                                <div className="flex flex-wrap gap-1">
                                  {m.consumes.map((c) => (
                                    <span key={c} className="badge badge-low text-[10px]">{c}</span>
                                  ))}
                                </div>
                              </div>
                            )}
                            <ModuleOptionsEditor module={m} onResult={(type, message) => setToast({ type, message })} />
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="card">
          <EmptyState
            icon={Cpu}
            title="No modules found"
            description={search ? 'Try adjusting your search query.' : 'No modules available.'}
          />
        </div>
      )}

      {toast && <Toast type={toast.type} message={toast.message} onClose={() => setToast(null)} />}
    </div>
  );
}
