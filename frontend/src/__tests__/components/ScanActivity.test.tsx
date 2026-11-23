import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { ScanActivity, friendlyModuleName, formatQuiet } from '../../components/scan/ScanActivity';
import type { ScanProgressSnapshot } from '../../hooks/useScanProgress';

const base: ScanProgressSnapshot = {
  scan_id: 'S1', status: 'RUNNING', overall_percent: 93, modules_total: 100, modules_finished: 93, modules_running: 2, modules: [],
  timestamp: 1, running: [], queued_events: 0, events_per_min: 0, quiet_for_s: 0,
};

describe('ScanActivity', () => {
  it('names the modules that are working and their own progress line', () => {
    render(<ScanActivity progress={{ ...base, running: [
      { name: 'sfp_tool_nikto', progress: '55 of 118 servers tested so far' }, { name: 'sfp_accounts', progress: '' }], queued_events: 1234, events_per_min: 17.5, quiet_for_s: 30 }} />);
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
    const { rerender } = render(<ScanActivity progress={{ ...base, running: [{ name: 'sfp_hudsonrock', progress: '' }], quiet_for_s: 700 }} />);
    expect(screen.getByText(/No new results for 12 minutes/)).toBeTruthy();
    expect(screen.getByText('no new results in the last few minutes')).toBeTruthy();
    rerender(<ScanActivity progress={{ ...base, running: [], quiet_for_s: 700 }} />);
    expect(screen.queryByText(/No new results for/)).toBeNull();
  });

  it('formats names and quiet times for people', () => {
    expect(friendlyModuleName('sfp_tool_nikto')).toBe('nikto');
    expect(friendlyModuleName('sfp_hudsonrock')).toBe('hudsonrock');
    expect(formatQuiet(30)).toBe('30 seconds');
    expect(formatQuiet(600)).toBe('10 minutes');
    expect(formatQuiet(7200)).toBe('2.0 hours');
  });
});
