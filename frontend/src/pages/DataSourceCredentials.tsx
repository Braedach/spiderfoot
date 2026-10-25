import { useMemo, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { configApi, dataApi, type Module } from '../lib/api';
import { isCredentialOption } from '../lib/settingsMeta';
import {
  KeyRound, Eye, EyeOff, AlertTriangle, CheckCircle2, Save, Loader2,
} from 'lucide-react';
import {
  PageHeader, SearchInput, Toast, EmptyState, Expandable, Skeleton,
  type ToastType,
} from '../components/ui';
import { useDocumentTitle } from '../hooks/useDocumentTitle';

type StatusFilter = 'all' | 'configured' | 'unconfigured';

export default function DataSourceCredentialsPage() {
  useDocumentTitle('Data Source Credentials');
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [editedValues, setEditedValues] = useState<Record<string, string>>({});
  const [showValues, setShowValues] = useState<Set<string>>(new Set());
  const [toast, setToast] = useState<{ type: ToastType; message: string } | null>(null);

  const { data: modulesData, isLoading } = useQuery({
    queryKey: ['modules', { page: 1, page_size: 500 }],
    queryFn: ({ signal }) => dataApi.modules({ page: 1, page_size: 500 }, signal),
  });

  const modules: Module[] = modulesData?.items ?? [];

  /* Only modules with at least one credential-style option */
  const credentialModules = useMemo(() => {
    return modules
      .map((m) => ({
        module: m,
        fields: Object.keys(m.opts ?? {}).filter(isCredentialOption),
      }))
      .filter((m) => m.fields.length > 0)
      .sort((a, b) => a.module.name.localeCompare(b.module.name));
  }, [modules]);

  const isConfigured = (m: Module, fields: string[]) =>
    fields.some((f) => String(m.opts?.[f] ?? '').trim() !== '');

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return credentialModules.filter(({ module, fields }) => {
      if (q) {
        const label = ((module.meta?.['name'] as string) || module.name).toLowerCase();
        if (!label.includes(q) && !module.name.toLowerCase().includes(q)) return false;
      }
      if (statusFilter === 'all') return true;
      const configured = isConfigured(module, fields);
      return statusFilter === 'configured' ? configured : !configured;
    });
  }, [credentialModules, search, statusFilter]);

  const configuredCount = useMemo(
    () => credentialModules.filter(({ module, fields }) => isConfigured(module, fields)).length,
    [credentialModules],
  );

  const saveMut = useMutation({
    mutationFn: async (edited: Record<string, string>) => {
      const moduleOpts = new Map<string, Record<string, unknown>>();
      for (const [key, val] of Object.entries(edited)) {
        const [mod, ...rest] = key.split(':');
        const optKey = rest.join(':');
        if (!moduleOpts.has(mod)) moduleOpts.set(mod, {});
        moduleOpts.get(mod)![optKey] = val;
      }
      await Promise.all(
        [...moduleOpts].map(([mod, opts]) => configApi.updateModuleOptions(mod, opts)),
      );
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['modules'] });
      setEditedValues({});
      setToast({ type: 'success', message: 'Credentials saved' });
    },
    onError: () => setToast({ type: 'error', message: 'Failed to save credentials' }),
  });

  const toggleShow = (key: string) => {
    const next = new Set(showValues);
    next.has(key) ? next.delete(key) : next.add(key);
    setShowValues(next);
  };

  const handleSave = () => {
    if (Object.keys(editedValues).length === 0) return;
    saveMut.mutate(editedValues);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Data Source Credentials"
        subtitle={`Third-party API keys and tokens that scan modules need. ${configuredCount} of ${credentialModules.length} configured.`}
      />

      <div className="flex flex-wrap items-center gap-3">
        <SearchInput value={search} onChange={setSearch} placeholder="Find a service..." className="flex-1 min-w-[200px]" />
        <div className="flex gap-1 p-1 bg-dark-800 border border-dark-700 rounded-lg">
          {([
            ['all', 'All'],
            ['configured', 'Configured'],
            ['unconfigured', 'Not Set'],
          ] as [StatusFilter, string][]).map(([key, label]) => (
            <button
              key={key}
              onClick={() => setStatusFilter(key)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                statusFilter === key ? 'bg-spider-600 text-white' : 'text-dark-400 hover:text-dark-200'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {isLoading ? (
        <div className="card space-y-3">
          {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}
        </div>
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={KeyRound}
          title="No matching modules"
          description={search ? 'Try a different search term.' : 'No data-source modules need a credential.'}
        />
      ) : (
        <div className="space-y-2">
          {filtered.map(({ module, fields }) => {
            const label = (module.meta?.['name'] as string) || module.name.replace(/^sfp_/, '');
            const configured = isConfigured(module, fields);
            return (
              <Expandable
                key={module.name}
                title={label}
                badge={
                  configured ? (
                    <span className="flex items-center gap-1 text-[10px] text-green-400">
                      <CheckCircle2 className="h-3 w-3" /> Configured
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 text-[10px] text-yellow-500">
                      <AlertTriangle className="h-3 w-3" /> Not set
                    </span>
                  )
                }
              >
                <p className="text-xs text-dark-500 mb-3">
                  {module.descr || module.description || 'No description available.'}
                </p>
                <div className="space-y-4">
                  {fields.map((field) => {
                    const optKey = `${module.name}:${field}`;
                    const editedVal = editedValues[optKey];
                    const currentVal = editedVal ?? String(module.opts?.[field] ?? '');
                    const desc = module.optdescs?.[field] || '';
                    const hidden = !showValues.has(optKey);
                    return (
                      <div key={optKey}>
                        <div className="flex items-center gap-2 mb-1">
                          <label className="text-sm text-dark-300 font-medium">{field}</label>
                          <button
                            onClick={() => toggleShow(optKey)}
                            className="text-dark-500 hover:text-dark-300 transition-colors"
                          >
                            {hidden ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                          </button>
                          {editedVal !== undefined && (
                            <span className="text-spider-400 text-[10px]">Modified</span>
                          )}
                        </div>
                        {desc && <p className="text-xs text-dark-500 mb-1.5">{desc}</p>}
                        <input
                          type={hidden ? 'password' : 'text'}
                          className="input-field text-sm font-mono"
                          value={currentVal}
                          onChange={(e) => setEditedValues((prev) => ({ ...prev, [optKey]: e.target.value }))}
                          placeholder="Enter API key..."
                        />
                      </div>
                    );
                  })}
                </div>
              </Expandable>
            );
          })}
        </div>
      )}

      {Object.keys(editedValues).length > 0 && (
        <div className="sticky bottom-4 card flex items-center justify-between animate-fade-in-up border border-spider-600/30">
          <p className="text-sm text-dark-300">{Object.keys(editedValues).length} unsaved change(s)</p>
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

      {toast && <Toast type={toast.type} message={toast.message} onClose={() => setToast(null)} />}
    </div>
  );
}
