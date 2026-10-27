import { useMemo, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { configApi } from '../lib/api';
import {
  Sparkles, Eye, EyeOff, AlertTriangle, Save, Loader2, Info,
} from 'lucide-react';
import { PageHeader, Toast, type ToastType } from '../components/ui';
import { useDocumentTitle } from '../hooks/useDocumentTitle';

interface ProviderPreset {
  key: string;
  label: string;
  /** Value actually stored in _llm_provider — must match a provider the
   * backend's LLMProvider enum recognises (spiderfoot/ai/llm_client.py). */
  providerValue: string;
  apiBase: string;
  modelPlaceholder: string;
  needsKey: boolean;
  note?: string;
}

// DeepSeek isn't its own backend provider type — its API is wire-compatible
// with OpenAI's, so picking it just sets provider=openai with DeepSeek's
// base URL pre-filled. Anything genuinely OpenAI-compatible (self-hosted
// gateways, etc.) can be reached the same way via a custom API Base URL.
const PRESETS: ProviderPreset[] = [
  { key: 'anthropic', label: 'Anthropic', providerValue: 'anthropic', apiBase: '', modelPlaceholder: 'claude-sonnet-5-5', needsKey: true },
  { key: 'openai', label: 'OpenAI', providerValue: 'openai', apiBase: '', modelPlaceholder: 'gpt-4o-mini', needsKey: true },
  { key: 'ollama', label: 'Ollama', providerValue: 'ollama', apiBase: 'http://localhost:11434', modelPlaceholder: 'llama3', needsKey: false },
  { key: 'deepseek', label: 'DeepSeek', providerValue: 'openai', apiBase: 'https://api.deepseek.com/v1', modelPlaceholder: 'deepseek-chat', needsKey: true, note: 'Uses the OpenAI-compatible provider with DeepSeek’s endpoint — DeepSeek’s API speaks the same wire format.' },
  { key: 'mock', label: 'Mock', providerValue: 'mock', apiBase: '', modelPlaceholder: '(none)', needsKey: false, note: 'No real model — returns canned responses, useful for testing without burning API credits.' },
];

const FIELDS: { key: string; label: string; hint: string; sensitive?: boolean }[] = [
  { key: '_llm_provider', label: 'Provider', hint: "LLM provider: 'anthropic', 'openai', 'ollama', 'mock', or 'huggingface'." },
  { key: '_llm_model', label: 'Model', hint: "Model name, e.g. 'claude-sonnet-5-5', 'gpt-4o-mini', 'llama3'." },
  { key: '_llm_api_key', label: 'API Key', hint: 'API key for the selected provider (not needed for Ollama or mock).', sensitive: true },
  { key: '_llm_api_base', label: 'API Base URL', hint: 'Base URL for the provider API — set this for a self-hosted or OpenAI-compatible endpoint.' },
  { key: '_llm_temperature', label: 'Temperature', hint: 'Generation temperature (0.0 = deterministic).' },
  { key: '_llm_max_tokens', label: 'Max Tokens', hint: 'Maximum tokens per LLM response.' },
];

export default function AIConnectionsPage() {
  useDocumentTitle('AI Connections');
  const queryClient = useQueryClient();
  const [editedValues, setEditedValues] = useState<Record<string, string>>({});
  const [showKey, setShowKey] = useState(false);
  const [toast, setToast] = useState<{ type: ToastType; message: string } | null>(null);

  const { data: configData, isLoading } = useQuery({
    queryKey: ['config'],
    queryFn: ({ signal }) => configApi.get(signal),
  });
  const config = configData?.config ?? {};

  const currentValues = useMemo(() => {
    const out: Record<string, string> = {};
    for (const f of FIELDS) out[f.key] = editedValues[f.key] ?? String(config[f.key] ?? '');
    return out;
  }, [config, editedValues]);

  // More than one preset can share a providerValue (DeepSeek rides on the
  // "openai" provider type) — disambiguate by matching the exact API base
  // first, falling back to whichever candidate has no fixed base of its own
  // (the plain OpenAI preset) rather than just taking array order.
  const activePreset = useMemo(() => {
    const candidates = PRESETS.filter((p) => p.providerValue === currentValues._llm_provider);
    if (candidates.length <= 1) return candidates[0];
    return candidates.find((p) => p.apiBase && currentValues._llm_api_base === p.apiBase)
      ?? candidates.find((p) => !p.apiBase)
      ?? candidates[0];
  }, [currentValues]);

  const setField = (key: string, value: string) => {
    setEditedValues((prev) => ({ ...prev, [key]: value }));
  };

  const applyPreset = (preset: ProviderPreset) => {
    setEditedValues((prev) => ({
      ...prev,
      _llm_provider: preset.providerValue,
      _llm_api_base: preset.apiBase,
    }));
  };

  const saveMut = useMutation({
    mutationFn: async (edited: Record<string, string>) => configApi.update(edited),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['config'] });
      setEditedValues({});
      setToast({ type: 'success', message: 'AI connection saved' });
    },
    onError: () => setToast({ type: 'error', message: 'Failed to save AI connection' }),
  });

  const handleSave = () => {
    if (Object.keys(editedValues).length === 0) return;
    saveMut.mutate(editedValues);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="AI Connections"
        subtitle="The LLM used for AI scan reports and RAG analysis — one connection, shared by both."
      />

      <div className="card animate-fade-in">
        <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
          <Sparkles className="h-4 w-4 text-spider-400" /> Provider
        </h3>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
          {PRESETS.map((p) => (
            <button
              key={p.key}
              onClick={() => applyPreset(p)}
              className={`p-3 rounded-xl border text-center transition-all ${
                activePreset?.key === p.key
                  ? 'border-spider-500 bg-spider-600/10 ring-1 ring-spider-500/30'
                  : 'border-dark-700 hover:border-dark-600 hover:bg-dark-700/30'
              }`}
            >
              <p className="text-sm font-medium text-foreground">{p.label}</p>
            </button>
          ))}
        </div>
        {activePreset?.note && (
          <p className="mt-3 flex items-start gap-1.5 text-xs text-dark-400">
            <Info className="h-3.5 w-3.5 flex-shrink-0 mt-0.5" />
            {activePreset.note}
          </p>
        )}
        <p className="mt-3 flex items-start gap-1.5 text-xs text-dark-500">
          <AlertTriangle className="h-3.5 w-3.5 flex-shrink-0 mt-0.5 text-yellow-500" />
          GitHub Copilot isn&apos;t available as a preset — its API requires GitHub&apos;s own OAuth
          device-flow sign-in rather than a pasted API key, which this deployment doesn&apos;t support yet.
        </p>
      </div>

      <div className="card animate-fade-in">
        {isLoading ? (
          <div className="flex items-center gap-2 text-sm text-dark-400">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading...
          </div>
        ) : (
          <div className="space-y-5">
            {FIELDS.map((f) => {
              const val = currentValues[f.key];
              const isHidden = f.sensitive && !showKey;
              const isModified = editedValues[f.key] !== undefined;
              return (
                <div key={f.key}>
                  <div className="flex items-center gap-2 mb-1">
                    <label className="text-sm text-dark-300 font-medium">{f.label}</label>
                    {f.sensitive && (
                      <button onClick={() => setShowKey(!showKey)} className="text-dark-500 hover:text-dark-300 transition-colors">
                        {isHidden ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                      </button>
                    )}
                    {f.sensitive && !val && (
                      <span className="text-yellow-500 text-[10px] flex items-center gap-0.5">
                        <AlertTriangle className="h-3 w-3" /> Not set
                      </span>
                    )}
                    {isModified && <span className="text-spider-400 text-[10px]">Modified</span>}
                  </div>
                  <p className="text-xs text-dark-500 mb-1.5">{f.hint}</p>
                  <input
                    type={isHidden ? 'password' : 'text'}
                    className="input-field text-sm font-mono"
                    value={val}
                    onChange={(e) => setField(f.key, e.target.value)}
                    placeholder={f.key === '_llm_model' ? activePreset?.modelPlaceholder : undefined}
                  />
                </div>
              );
            })}
          </div>
        )}
      </div>

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
