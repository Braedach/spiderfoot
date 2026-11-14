import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Eye, EyeOff, Save, Loader2, AlertTriangle } from 'lucide-react';
import { configApi, type Module } from '../lib/api';
import { isCredentialOption } from '../lib/settingsMeta';

const isTrue = (v: string) => v === 'true' || v === 'True';
const isBoolStr = (v: string) => ['true', 'false', 'True', 'False'].includes(v);

/** Edit every option of one module, API keys and tokens included. */
export default function ModuleOptionsEditor({
  module,
  onResult,
}: {
  module: Module;
  onResult: (type: 'success' | 'error', message: string) => void;
}) {
  const queryClient = useQueryClient();
  const [edited, setEdited] = useState<Record<string, string>>({});
  const [shown, setShown] = useState<Set<string>>(new Set());

  const saveMut = useMutation({
    mutationFn: () => configApi.updateModuleOptions(module.name, edited),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['modules'] });
      setEdited({});
      onResult('success', `${module.name} saved`);
    },
    onError: () => onResult('error', `Failed to save ${module.name}`),
  });

  // Credentials first: it is what people come here for.
  const entries = Object.entries(module.opts ?? {}).sort(
    ([a], [b]) => Number(isCredentialOption(b)) - Number(isCredentialOption(a)) || a.localeCompare(b),
  );
  if (entries.length === 0) return null;

  const set = (k: string, v: string) => setEdited((p) => ({ ...p, [k]: v }));
  const toggleShown = (k: string) =>
    setShown((p) => {
      const n = new Set(p);
      if (n.has(k)) n.delete(k); else n.add(k);
      return n;
    });
  const dirty = Object.keys(edited).length > 0;

  return (
    <div className="sm:col-span-2" onClick={(e) => e.stopPropagation()}>
      <div className="space-y-4">
        {entries.map(([k, v]) => {
          const raw = String(v ?? '');
          const cur = edited[k] ?? raw;
          const sensitive = isCredentialOption(k);
          const bool = !sensitive && (v === true || v === false || isBoolStr(cur));
          const num = !bool && !sensitive && /^\d+(\.\d+)?$/.test(raw);
          const long = !bool && !num && !sensitive && raw.includes(',') && raw.length > 40;
          const desc = module.optdescs?.[k];
          return (
            <div key={k}>
              <div className="flex items-center gap-2 mb-1">
                <label className="text-sm text-dark-300 font-medium font-mono">{k}</label>
                {sensitive && (
                  <button
                    type="button"
                    onClick={() => toggleShown(k)}
                    aria-label={shown.has(k) ? `Hide ${k}` : `Show ${k}`}
                    className="text-dark-500 hover:text-dark-300 transition-colors"
                  >
                    {shown.has(k) ? <Eye className="h-3 w-3" /> : <EyeOff className="h-3 w-3" />}
                  </button>
                )}
                {sensitive && !cur && (
                  <span className="text-yellow-500 text-[10px] flex items-center gap-0.5">
                    <AlertTriangle className="h-3 w-3" /> Not set
                  </span>
                )}
                {edited[k] !== undefined && <span className="text-spider-400 text-[10px]">Modified</span>}
              </div>
              {desc && <p className="text-xs text-dark-500 mb-1.5">{desc}</p>}
              {bool ? (
                <button
                  type="button"
                  role="switch"
                  aria-checked={isTrue(cur) || v === true}
                  aria-label={k}
                  onClick={() => set(k, isTrue(cur) || (v === true && edited[k] === undefined) ? 'false' : 'true')}
                  className={`relative inline-flex h-7 w-12 items-center rounded-full transition-colors ${
                    isTrue(cur) || (v === true && edited[k] === undefined) ? 'bg-spider-500' : 'bg-dark-600'
                  }`}
                >
                  <span className={`inline-block h-5 w-5 transform rounded-full bg-white shadow-sm transition-transform ${
                    isTrue(cur) || (v === true && edited[k] === undefined) ? 'translate-x-6' : 'translate-x-1'
                  }`} />
                </button>
              ) : num ? (
                <input type="number" aria-label={k} className="input-field text-sm font-mono w-40"
                  value={cur} onChange={(e) => set(k, e.target.value)} />
              ) : long ? (
                <textarea aria-label={k} className="input-field text-sm font-mono h-24 resize-y"
                  value={cur} onChange={(e) => set(k, e.target.value)} placeholder="Comma-separated values..." />
              ) : (
                <input
                  type={sensitive && !shown.has(k) ? 'password' : 'text'}
                  aria-label={k}
                  autoComplete="off"
                  className="input-field text-sm font-mono"
                  value={cur}
                  onChange={(e) => set(k, e.target.value)}
                  placeholder={sensitive ? 'Enter API key...' : ''}
                />
              )}
            </div>
          );
        })}
      </div>
      <div className="mt-4 flex items-center gap-3">
        <button
          type="button"
          className="btn-primary text-sm"
          disabled={!dirty || saveMut.isPending}
          onClick={() => saveMut.mutate()}
        >
          {saveMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
          Save changes
        </button>
        {dirty && (
          <button type="button" className="btn-secondary text-sm" onClick={() => setEdited({})}>
            Discard
          </button>
        )}
      </div>
    </div>
  );
}
