import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { aiProvidersApi, type AIProviderStatus, type AIProvidersResponse } from '../lib/api';
import { Sparkles, Loader2, Info, Check, Trash2, Save } from 'lucide-react';
import { PageHeader, Toast, type ToastType } from '../components/ui';
import { useDocumentTitle } from '../hooks/useDocumentTitle';

// DeepSeek is not its own backend provider type: its API is wire-compatible
// with OpenAI's, so it is the OpenAI provider with DeepSeek's base URL.
const NOTES: Record<string, string> = {
  deepseek: 'Uses the OpenAI-compatible provider with DeepSeek’s endpoint.',
  mock: 'No real model: returns canned responses, for testing without spending API credits.',
};

interface Draft { api_key: string; model: string; api_base: string }

function ProviderCard({
  provider, active, onChanged, notify,
}: {
  provider: AIProviderStatus;
  active: boolean;
  onChanged: (data: AIProvidersResponse) => void;
  notify: (type: ToastType, message: string) => void;
}) {
  const [draft, setDraft] = useState<Draft>({ api_key: '', model: provider.model, api_base: provider.api_base });
  const dirty = draft.api_key !== '' || draft.model !== provider.model || draft.api_base !== provider.api_base;
  const canActivate = !provider.needs_key || provider.key_set;

  const run = useMutation({
    mutationFn: (fn: () => Promise<AIProvidersResponse>) => fn(),
    onSuccess: (data) => { onChanged(data); },
    onError: () => notify('error', 'Could not save. Administrator access is required.'),
  });

  const save = () => run.mutate(async () => {
    const body: { api_key?: string; model: string; api_base: string } = { model: draft.model, api_base: draft.api_base };
    if (draft.api_key) body.api_key = draft.api_key;
    const data = await aiProvidersApi.update(provider.id, body);
    setDraft((d) => ({ ...d, api_key: '' }));
    notify('success', `${provider.label} saved`);
    return data;
  });

  return (
    <div className={`card animate-fade-in border ${active ? 'border-spider-500' : 'border-transparent'}`}>
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-foreground">{provider.label}</h3>
        <div className="flex items-center gap-2 text-[11px]">
          {provider.needs_key ? (
            <span className={provider.key_set ? 'text-green-400' : 'text-yellow-500'}>
              {provider.key_set ? 'Key stored' : 'No key'}
            </span>
          ) : (
            <span className="text-dark-400">No key needed</span>
          )}
          {active && <span className="px-2 py-0.5 rounded bg-spider-600/20 text-spider-300">Active</span>}
        </div>
      </div>
      {NOTES[provider.id] && (
        <p className="mb-3 flex items-start gap-1.5 text-xs text-dark-400">
          <Info className="h-3.5 w-3.5 flex-shrink-0 mt-0.5" />{NOTES[provider.id]}
        </p>
      )}
      <div className="space-y-3">
        {provider.needs_key && (
          <div>
            <label className="text-xs text-dark-300 font-medium">API key</label>
            <input
              type="password" autoComplete="off" className="input-field text-sm font-mono mt-1"
              value={draft.api_key} onChange={(e) => setDraft({ ...draft, api_key: e.target.value })}
              placeholder={provider.key_set ? 'Stored. Enter a new key to replace it' : 'Paste the API key'}
            />
          </div>
        )}
        {provider.id !== 'mock' && (
          <>
            <div>
              <label className="text-xs text-dark-300 font-medium">Model</label>
              <input
                className="input-field text-sm font-mono mt-1" value={draft.model}
                onChange={(e) => setDraft({ ...draft, model: e.target.value })}
                placeholder={provider.default_model}
              />
            </div>
            <div>
              <label className="text-xs text-dark-300 font-medium">API base URL</label>
              <input
                className="input-field text-sm font-mono mt-1" value={draft.api_base}
                onChange={(e) => setDraft({ ...draft, api_base: e.target.value })}
                placeholder={provider.default_api_base || 'Provider default'}
              />
            </div>
          </>
        )}
      </div>
      <div className="flex flex-wrap gap-2 mt-4">
        <button className="btn-primary" onClick={save} disabled={!dirty || run.isPending}>
          {run.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />} Save
        </button>
        {provider.needs_key && provider.key_set && (
          <button
            className="btn-secondary"
            onClick={() => run.mutate(async () => {
              const data = await aiProvidersApi.clearKey(provider.id);
              notify('success', `${provider.label} key removed`);
              return data;
            })}
            disabled={run.isPending}
          >
            <Trash2 className="h-4 w-4" /> Remove key
          </button>
        )}
        {!active && (
          <button
            className="btn-secondary" disabled={!canActivate || run.isPending}
            title={canActivate ? undefined : 'Save an API key first'}
            onClick={() => run.mutate(async () => {
              const data = await aiProvidersApi.setActive(provider.id);
              notify('success', `${provider.label} is now the active provider`);
              return data;
            })}
          >
            <Check className="h-4 w-4" /> Make active
          </button>
        )}
      </div>
    </div>
  );
}

export default function AIConnectionsPage() {
  useDocumentTitle('AI Connections');
  const queryClient = useQueryClient();
  const [toast, setToast] = useState<{ type: ToastType; message: string } | null>(null);
  const notify = (type: ToastType, message: string) => setToast({ type, message });

  const { data, isLoading, isError } = useQuery({
    queryKey: ['ai-providers'],
    queryFn: ({ signal }) => aiProvidersApi.list(signal),
  });
  const onChanged = (next: AIProvidersResponse) => queryClient.setQueryData(['ai-providers'], next);

  const activeProvider = data?.providers.find((p) => p.id === data.active);

  return (
    <div className="space-y-6">
      <PageHeader
        title="AI Connections"
        subtitle="The model behind AI reports and analysis. Keys are stored encrypted and never shown again. Settings here override the server environment."
      />

      {isLoading && (
        <div className="flex items-center gap-2 text-sm text-dark-400"><Loader2 className="h-4 w-4 animate-spin" /> Loading...</div>
      )}
      {isError && <p className="text-sm text-red-400">Could not load AI connections. Administrator access is required.</p>}

      {data && (
        <>
          <div className="card animate-fade-in">
            <h3 className="text-sm font-semibold text-foreground mb-2 flex items-center gap-2">
              <Sparkles className="h-4 w-4 text-spider-400" /> Active provider
            </h3>
            {activeProvider ? (
              <p className="text-sm text-dark-300">
                <strong>{activeProvider.label}</strong>, set here. Scan findings are sent to this provider only.
              </p>
            ) : (
              <p className="text-sm text-dark-300">
                None chosen here, so the server environment is used
                {data.environment.provider ? <> (<strong>{data.environment.provider}</strong>{data.environment.model ? `, ${data.environment.model}` : ''}; key {data.environment.key_set ? 'present' : 'missing'})</> : null}.
              </p>
            )}
            <p className="mt-2 flex items-start gap-1.5 text-xs text-dark-500">
              <Info className="h-3.5 w-3.5 flex-shrink-0 mt-0.5" />
              Only one provider is active at a time. Others can keep their saved settings. There is no automatic fallback
              between providers, so findings never go to a provider you did not choose.
            </p>
            {activeProvider && (
              <button className="btn-secondary mt-3" onClick={() => aiProvidersApi.setActive('').then(onChanged)}>
                Use the server environment instead
              </button>
            )}
          </div>

          <div className="card animate-fade-in">
            <h3 className="text-sm font-semibold text-foreground mb-2 flex items-center gap-2">
              <Info className="h-4 w-4 text-spider-400" /> How this works
            </h3>
            <ul className="space-y-1.5 text-xs text-dark-400 list-disc pl-4">
              <li><strong className="text-dark-300">One active provider.</strong> You can save settings for several providers, but all AI reports and analysis use the active one only. Switching takes effect within a few seconds, and requests already running finish on the old provider.</li>
              <li><strong className="text-dark-300">No automatic fallback.</strong> If the active provider fails, the request fails; it is never retried on a different provider. Scan findings (hosts, credentials, vulnerabilities) go only to the provider you chose.</li>
              <li><strong className="text-dark-300">These settings override the server environment.</strong> If no provider is active here, the server&apos;s <code>SF_LLM_*</code> / <code>ANTHROPIC_API_KEY</code> settings are used, so an environment-only setup keeps working. A blank key on the active Anthropic provider also falls back to the environment key.</li>
              <li><strong className="text-dark-300">Keys are write-only.</strong> They are stored encrypted in the database and never displayed again; to change one, enter a new key. Only administrators can view or change this page.</li>
              <li><strong className="text-dark-300">If the server&apos;s <code>SF_JWT_SECRET_KEY</code> is rotated</strong>, stored keys can no longer be decrypted and show as &quot;No key&quot;; enter them again.</li>
              <li><strong className="text-dark-300">One model per provider.</strong> Leave the model blank to use the provider&apos;s default.</li>
            </ul>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {data.providers.map((p) => (
              <ProviderCard key={p.id} provider={p} active={p.id === data.active} onChanged={onChanged} notify={notify} />
            ))}
          </div>
        </>
      )}

      {toast && <Toast type={toast.type} message={toast.message} onClose={() => setToast(null)} />}
    </div>
  );
}
