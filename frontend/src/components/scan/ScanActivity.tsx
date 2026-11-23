import { Loader2 } from 'lucide-react';
import type { ScanProgressSnapshot } from '../../hooks/useScanProgress';

/** "sfp_tool_nikto" -> "nikto", "sfp_hudsonrock" -> "hudsonrock": what a person would call the module. */
export function friendlyModuleName(name: string): string {
  return name.replace(/^sfp_/, '').replace(/^tool_/, '');
}

export function formatQuiet(seconds: number): string {
  if (seconds < 90) return `${Math.round(seconds)} seconds`;
  const minutes = Math.round(seconds / 60);
  return minutes < 90 ? `${minutes} minutes` : `${(minutes / 60).toFixed(1)} hours`;
}

const QUIET_WARNING_S = 600;   // ten minutes without a new result is worth saying

/**
 * What a running scan is doing right now. The percentage bar only counts modules that have produced a result, so it sits near
 * its top for hours while slow tools and lookups finish; this says which ones, how far they are, and whether results are still
 * arriving.
 */
export function ScanActivity({ progress }: { progress: ScanProgressSnapshot }) {
  const running = progress.running ?? [];
  const quiet = progress.quiet_for_s ?? 0;
  const stalled = quiet >= QUIET_WARNING_S && running.length > 0;

  return (
    <div role="status" aria-live="polite" className="w-full max-w-xl rounded-lg border border-white/10 bg-white/5 px-4 py-3 text-sm space-y-2">
      <div className="text-xs opacity-70">
        The bar shows how many modules have produced results so far. It is not time remaining: slow tools and lookups keep
        working after it fills.
      </div>
      {running.length > 0 ? (
        <>
          <div className="font-medium">Working now ({running.length})</div>
          <ul className="space-y-1">
            {running.map((m) => (
              <li key={m.name} className="flex items-center gap-2">
                <Loader2 className="h-3.5 w-3.5 animate-spin shrink-0" />
                <span className="font-mono">{friendlyModuleName(m.name)}</span>
                {m.progress && <span className="opacity-70">: {m.progress}</span>}
              </li>
            ))}
          </ul>
        </>
      ) : (
        <div className="font-medium">No module is working: the scan is finishing up.</div>
      )}
      <div className="flex flex-wrap gap-x-6 gap-y-1 text-xs opacity-80">
        <span>{progress.queued_events.toLocaleString()} events waiting</span>
        <span>{progress.events_per_min > 0 ? `${progress.events_per_min.toLocaleString()} results a minute` : 'no new results in the last few minutes'}</span>
        <span>last result {formatQuiet(quiet)} ago</span>
      </div>
      {stalled && (
        <div className="text-xs text-amber-300">
          No new results for {formatQuiet(quiet)}. The modules above are still working; a long tail of account checks or slow
          tools is normal, but if it stays like this for hours check the scan log.
        </div>
      )}
    </div>
  );
}
