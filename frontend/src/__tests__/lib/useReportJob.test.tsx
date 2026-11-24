import { renderHook, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const { reportStatus, reportResult } = vi.hoisted(() => ({ reportStatus: vi.fn(), reportResult: vi.fn() }));
vi.mock('../../lib/api', () => ({ agentsApi: { reportStatus, reportResult } }));

import { useReportJob } from '../../hooks/useReportJob';
import type { ReportJob } from '../../lib/api';

const KEY = 'sf_report_job_S1';
const running: ReportJob = { job_id: 'J1', status: 'running', phase: 'model', steps: [], elapsed_s: 5, phase_elapsed_s: 5 };
const done: ReportJob = { ...running, status: 'done' };

/** Let the poll timer fire and every promise it started settle. */
async function tick(ms = 2000) {
  await act(async () => { await vi.advanceTimersByTimeAsync(ms); });
}

beforeEach(() => {
  vi.useFakeTimers();
  localStorage.clear();
  reportStatus.mockReset();
  reportResult.mockReset();
});
afterEach(() => vi.useRealTimers());

describe('useReportJob', () => {
  it('hands over the finished report even though marking the job done changes the state it reacts to (the lost-report bug)', async () => {
    const onDone = vi.fn();
    reportStatus.mockResolvedValueOnce({ ...running }).mockResolvedValue({ ...done });
    reportResult.mockResolvedValue({ data: { report: '# R' } });
    const { result } = renderHook(() => useReportJob({ storageKey: KEY, onDone }));
    act(() => result.current.begin({ ...running }));
    expect(result.current.isGenerating).toBe(true);
    expect(localStorage.getItem(KEY)).toBe('J1');
    await tick();                                                     // still running
    expect(onDone).not.toHaveBeenCalled();
    await tick();                                                     // done: the result is fetched and used
    expect(reportResult).toHaveBeenCalledWith('J1');
    expect(onDone).toHaveBeenCalledTimes(1);
    expect(onDone).toHaveBeenCalledWith({ data: { report: '# R' } });
    expect(result.current.isGenerating).toBe(false);
    expect(result.current.job?.status).toBe('done');
    expect(localStorage.getItem(KEY)).toBeNull();
    await tick(10000);                                                // and nothing more is asked afterwards
    expect(reportStatus).toHaveBeenCalledTimes(2);
    expect(onDone).toHaveBeenCalledTimes(1);
  });

  it('reports a failed job with its message and does not call onDone', async () => {
    const onDone = vi.fn();
    reportStatus.mockResolvedValue({ ...running, status: 'error', error: 'model said no' });
    const { result } = renderHook(() => useReportJob({ storageKey: KEY, onDone }));
    act(() => result.current.begin({ ...running }));
    await tick();
    expect(result.current.error).toBe('model said no');
    expect(onDone).not.toHaveBeenCalled();
    expect(reportResult).not.toHaveBeenCalled();
    expect(localStorage.getItem(KEY)).toBeNull();
  });

  it('says the report was lost when the service no longer knows the job (404) and forgets the job id', async () => {
    reportStatus.mockRejectedValue({ response: { status: 404 } });
    const { result } = renderHook(() => useReportJob({ storageKey: KEY, onDone: vi.fn() }));
    act(() => result.current.begin({ ...running }));
    await tick();
    expect(result.current.error).toMatch(/lost because the AI service restarted/);
    expect(result.current.job).toBeNull();
    expect(localStorage.getItem(KEY)).toBeNull();
  });

  it('keeps the job id when contact is lost for another reason, so a reload can pick it up', async () => {
    reportStatus.mockRejectedValue(new Error('network'));
    const { result } = renderHook(() => useReportJob({ storageKey: KEY, onDone: vi.fn() }));
    act(() => result.current.begin({ ...running }));
    await tick();
    expect(result.current.error).toMatch(/Lost contact/);
    expect(localStorage.getItem(KEY)).toBe('J1');
  });

  it('picks a running job up again after a refresh, and drops a finished or unknown one', async () => {
    localStorage.setItem(KEY, 'J1');
    reportStatus.mockResolvedValueOnce({ ...running });
    const first = renderHook(() => useReportJob({ storageKey: KEY, onDone: vi.fn() }));
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(first.result.current.isGenerating).toBe(true);
    first.unmount();
    reportStatus.mockResolvedValueOnce({ ...done });
    const second = renderHook(() => useReportJob({ storageKey: KEY, onDone: vi.fn() }));
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(second.result.current.isGenerating).toBe(false);
    expect(localStorage.getItem(KEY)).toBeNull();
    localStorage.setItem(KEY, 'J2');
    reportStatus.mockRejectedValueOnce({ response: { status: 404 } });
    renderHook(() => useReportJob({ storageKey: KEY, onDone: vi.fn() }));
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(localStorage.getItem(KEY)).toBeNull();
  });

  it('stops asking when the page is left', async () => {
    reportStatus.mockResolvedValue({ ...running });
    const { result, unmount } = renderHook(() => useReportJob({ storageKey: KEY, onDone: vi.fn() }));
    act(() => result.current.begin({ ...running }));
    await tick();
    const asked = reportStatus.mock.calls.length;
    unmount();
    await tick(10000);
    expect(reportStatus).toHaveBeenCalledTimes(asked);
  });

  it('shows a failure to start as an error', () => {
    const { result } = renderHook(() => useReportJob({ storageKey: KEY, onDone: vi.fn() }));
    act(() => result.current.fail('could not start'));
    expect(result.current.error).toBe('could not start');
    expect(result.current.isGenerating).toBe(false);
  });
});
