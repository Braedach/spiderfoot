import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { ScanActivity, friendlyModuleName, formatQuiet, formatElapsed } from '../../components/scan/ScanActivity';
import type { ScanProgressSnapshot } from '../../hooks/useScanProgress';

const base: ScanProgressSnapshot = {
  scan_id: 'S1', status: 'RUNNING', overall_percent: 93, modules_total: 100, modules_finished: 93, modules_running: 2, modules: [],
  timestamp: 1, running: [], queued_events: 0, events_per_min: 0, quiet_for_s: 0,
};

describe('ScanActivity', () => {
  it('names the modules that are working and their own progress line', () => {
    render(<ScanActivity progress={{ ...base, running: [
      { name: 'sfp_tool_nikto', progress: '55 of 118 servers tested so far', running_for_s: 4320, results: 1235 }, { name: 'sfp_accounts', progress: '', running_for_s: 40, results: 9 }], queued_events: 1234, events_per_min: 17.5, quiet_for_s: 30 }} />);
    expect(screen.getByText('Working now (2)')).toBeTruthy();
    expect(screen.getByText('nikto')).toBeTruthy();
    expect(screen.getByText(/55 of 118 servers tested so far/)).toBeTruthy();
    expect(screen.getByText('accounts')).toBeTruthy();
    expect(screen.getByText('1,234 events waiting')).toBeTruthy();
    expect(screen.getByText('17.5 results a minute')).toBeTruthy();
    expect(screen.queryByText(/No new results for/)).toBeNull();
  });

  it('says plainly when the percentage is not time remaining', () => {
    render(<ScanActivity progress={base} />);
    expect(screen.getByText(/not time remaining/)).toBeTruthy();
    expect(screen.getByText(/finishing up/)).toBeTruthy();
  });

  it('warns after ten quiet minutes while modules are still running, and not when nothing is running', () => {
    const { rerender } = render(<ScanActivity progress={{ ...base, running: [{ name: 'sfp_hudsonrock', progress: '', running_for_s: 0, results: 0 }], quiet_for_s: 700 }} />);
    expect(screen.getByText(/No new results for 12 minutes/)).toBeTruthy();
    expect(screen.getByText('no new results in the last few minutes')).toBeTruthy();
    rerender(<ScanActivity progress={{ ...base, running: [], quiet_for_s: 700 }} />);
    expect(screen.queryByText(/No new results for/)).toBeNull();
  });

  it('shows how long each module has worked and how many results it has stored', () => {
    render(<ScanActivity progress={{ ...base, running: [
      { name: 'sfp_tool_nikto', progress: '', running_for_s: 4320, results: 1235 }, { name: 'sfp_accounts', progress: '', running_for_s: 40, results: 9 }] }} />);
    expect(screen.getByText('1h 12m · 1,235 results')).toBeTruthy();
    expect(screen.getByText('40s · 9 results')).toBeTruthy();
  });

  it('names a slow tail when most of the scan is done and only a few modules are left, and not early in a scan', () => {
    const few = [{ name: 'sfp_accounts', progress: '', running_for_s: 100, results: 5 }];
    const { rerender } = render(<ScanActivity progress={{ ...base, modules_total: 100, modules_finished: 93, running: few }} />);
    expect(screen.getByText(/Slow tail: only this module is still working/)).toBeTruthy();
    rerender(<ScanActivity progress={{ ...base, modules_total: 100, modules_finished: 20, running: few }} />);
    expect(screen.queryByText(/Slow tail/)).toBeNull();                                  // early: most modules have not started
    const many = Array.from({ length: 8 }, (_, i) => ({ name: `sfp_m${i}`, progress: '', running_for_s: 1, results: 0 }));
    rerender(<ScanActivity progress={{ ...base, modules_total: 100, modules_finished: 93, running: many }} />);
    expect(screen.queryByText(/Slow tail/)).toBeNull();                                  // too many still working to call it a tail
  });

  it('lists the most relevant modules first, leaves out the storage module, and counts the rest', () => {
    const many = Array.from({ length: 30 }, (_, i) => ({ name: `sfp_m${i}`, progress: '', running_for_s: i, results: 0 }));
    const running = [{ name: 'sfp__stor_db', progress: '', running_for_s: 9999, results: 0 },
      { name: 'sfp_tool_nikto', progress: '3 of 9 servers tested so far', running_for_s: 5, results: 1 }, ...many];
    render(<ScanActivity progress={{ ...base, running }} />);
    expect(screen.getByText('Working now (31)')).toBeTruthy();                           // the storage module is not counted
    expect(screen.queryByText('stor_db')).toBeNull();
    expect(screen.getByText('nikto')).toBeTruthy();                                      // has a progress line, so it is listed first
    expect(screen.getByText('m29')).toBeTruthy();                                        // then the longest running
    expect(screen.queryByText('m0')).toBeNull();
    expect(screen.getByText('and 23 more working')).toBeTruthy();                        // 31 working, 8 listed
  });

  it('formats names and quiet times for people', () => {
    expect(formatElapsed(40)).toBe('40s');
    expect(formatElapsed(600)).toBe('10m');
    expect(formatElapsed(4320)).toBe('1h 12m');
    expect(friendlyModuleName('sfp_tool_nikto')).toBe('nikto');
    expect(friendlyModuleName('sfp_hudsonrock')).toBe('hudsonrock');
    expect(formatQuiet(30)).toBe('30 seconds');
    expect(formatQuiet(600)).toBe('10 minutes');
    expect(formatQuiet(7200)).toBe('2.0 hours');
  });
});
