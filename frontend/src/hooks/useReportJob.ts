/**
 * useReportJob: follows an AI report that is written by a background job on the server.
 *
 * `begin(job)` starts following a job the page just started; a job id kept in storage is picked up again after a refresh. While the
 * job runs the hook asks for its status every 2 seconds. When the job is done it fetches the result and calls `onDone(result)`
 * BEFORE it marks the job done: marking it done first changes the state this hook reacts to, which cancelled the fetch that was
 * still in flight and threw the finished report away (the page said "No report generated" until the tab was left and reopened).
 */
import { useState, useEffect, useRef, useCallback } from 'react';
import { agentsApi, type ReportJob } from '../lib/api';
import { safeGetItem, safeSetItem, safeRemoveItem } from '../lib/safeStorage';

const POLL_MS = 2000;

interface Options {
  /** Where the job id is kept (one per scan). */
  storageKey: string;
  /** Called once with the finished report. */
  onDone: (result: unknown) => void;
}

export function useReportJob({ storageKey, onDone }: Options) {
  const [job, setJob] = useState<ReportJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const onDoneRef = useRef(onDone);
  onDoneRef.current = onDone;

  const begin = useCallback((started: ReportJob) => {
    setError(null);
    setJob(started);
    safeSetItem(storageKey, started.job_id);
  }, [storageKey]);

  const fail = useCallback((message: string) => setError(message), []);

  // pick up a job this browser started earlier (a refresh, or a return to the page)
  useEffect(() => {
    const saved = safeGetItem(storageKey);
    if (!saved) return;
    let cancelled = false;
    agentsApi.reportStatus(saved)
      .then((j) => {
        if (cancelled) return;
        if (j.status === 'running') setJob(j); else safeRemoveItem(storageKey);
      })
      .catch(() => { if (!cancelled) safeRemoveItem(storageKey); });
    return () => { cancelled = true; };
  }, [storageKey]);

  const jobId = job?.status === 'running' ? job.job_id : null;

  // depends on the job id only: the status changing to "done" must not cancel the fetch of the result
  useEffect(() => {
    if (!jobId) return;
    let cancelled = false;
    let busy = false;
    const timer = setInterval(async () => {
      if (busy) return;
      busy = true;
      try {
        const j = await agentsApi.reportStatus(jobId);
        if (cancelled) return;
        if (j.status === 'done') {
          clearInterval(timer);
          const data = await agentsApi.reportResult(jobId);
          if (cancelled) return;
          onDoneRef.current(data);
          safeRemoveItem(storageKey);
          setJob(j);
        } else if (j.status === 'error') {
          clearInterval(timer);
          setError(j.error || 'The report failed.');
          safeRemoveItem(storageKey);
          setJob(j);
        } else {
          setJob(j);
        }
      } catch (err) {
        if (cancelled) return;
        clearInterval(timer);
        const status = (err as { response?: { status?: number } })?.response?.status;
        setError(status === 404
          ? 'The report was lost because the AI service restarted. Generate it again.'
          : 'Lost contact with the AI service. The report may still finish: reload this page in a minute.');
        setJob(null);
        if (status === 404) safeRemoveItem(storageKey);
      } finally {
        busy = false;
      }
    }, POLL_MS);
    return () => { cancelled = true; clearInterval(timer); };
  }, [jobId, storageKey]);

  return { job, error, isGenerating: job?.status === 'running', begin, fail };
}
