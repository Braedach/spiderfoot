import { useState } from 'react';
import { Loader2, CheckCircle2, XCircle, PlugZap } from 'lucide-react';
import { webSearchApi, type WebSearchTestResult } from '../lib/api';

/**
 * Settings > Web Search: tries the SearXNG address typed above (or the saved one) and says what is wrong when it does not
 * answer. The usual problem is the json format being off in the server's settings.yml, and the message says so.
 */
export function WebSearchTest({ url }: { url: string }) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<WebSearchTestResult | null>(null);

  const run = async () => {
    setBusy(true);
    setResult(null);
    try {
      setResult(await webSearchApi.test(url.trim() || undefined));
    } catch {
      setResult({ ok: false, message: 'The test could not be run. Check that you are signed in and the API is reachable.' });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card animate-fade-in" data-testid="websearch-test">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-foreground">Test the connection</h3>
          <p className="text-xs text-dark-400 mt-1">
            Sends one test search to the address above (it does not need to be saved first) and reports whether your SearXNG answers in JSON.
          </p>
        </div>
        <button className="btn-secondary text-sm" onClick={run} disabled={busy}>
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <PlugZap className="h-4 w-4" />} Test connection
        </button>
      </div>
      {result && (
        <div
          role="status"
          data-testid="websearch-test-result"
          className={`mt-3 flex items-start gap-2 rounded-lg border p-3 text-sm ${
            result.ok ? 'border-green-500/40 bg-green-500/10' : 'border-red-500/40 bg-red-500/10'
          }`}
        >
          {result.ok ? <CheckCircle2 className="h-4 w-4 mt-0.5 text-green-400 shrink-0" /> : <XCircle className="h-4 w-4 mt-0.5 text-red-400 shrink-0" />}
          <span className="text-foreground">{result.message}</span>
        </div>
      )}
    </div>
  );
}
