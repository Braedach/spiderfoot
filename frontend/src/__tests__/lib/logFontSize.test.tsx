import { render, screen, act } from '@testing-library/react';
import { describe, it, expect, beforeEach } from 'vitest';
import { safeGetItem, safeSetItem } from '../../lib/safeStorage';
import { DEFAULT_LOG_FONT_SIZE, LOG_FONT_SIZES, setLogFontSize, useLogFontSize } from '../../lib/logFontSize';

function Probe() {
  const size = useLogFontSize();
  return <span data-testid="px">{LOG_FONT_SIZES[size].px}</span>;
}

describe('log font size preference', () => {
  beforeEach(() => localStorage.clear());

  it('defaults to small, two steps below the old 12px', () => {
    expect(DEFAULT_LOG_FONT_SIZE).toBe('small');
    render(<Probe />);
    expect(screen.getByTestId('px').textContent).toBe('10px');
  });

  it('updates live and persists when changed', () => {
    render(<Probe />);
    act(() => setLogFontSize('large'));
    expect(screen.getByTestId('px').textContent).toBe('12px');
    expect(safeGetItem('sf-log-font-size')).toBe('large');
  });

  it('ignores an invalid stored value', () => {
    safeSetItem('sf-log-font-size', 'huge');
    render(<Probe />);
    expect(screen.getByTestId('px').textContent).toBe('10px');
  });
});
