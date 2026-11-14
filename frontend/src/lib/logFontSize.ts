import { useSyncExternalStore } from 'react';
import { safeGetItem, safeSetItem } from './safeStorage';

export type LogFontSize = 'small' | 'medium' | 'large';

export const LOG_FONT_SIZES: Record<LogFontSize, { label: string; px: string }> = {
  small: { label: 'Small (10px)', px: '10px' },
  medium: { label: 'Medium (11px)', px: '11px' },
  large: { label: 'Large (12px)', px: '12px' },
};

export const DEFAULT_LOG_FONT_SIZE: LogFontSize = 'small';

const KEY = 'sf-log-font-size';
const EVENT = 'sf-log-font-size-change';

function read(): LogFontSize {
  const v = safeGetItem(KEY);
  return v === 'small' || v === 'medium' || v === 'large' ? v : DEFAULT_LOG_FONT_SIZE;
}

function subscribe(cb: () => void): () => void {
  window.addEventListener(EVENT, cb);
  window.addEventListener('storage', cb);
  return () => {
    window.removeEventListener(EVENT, cb);
    window.removeEventListener('storage', cb);
  };
}

export function setLogFontSize(size: LogFontSize): void {
  safeSetItem(KEY, size);
  window.dispatchEvent(new Event(EVENT));
}

/** Log text size, kept per browser and shared live between the Settings page and the log views. */
export function useLogFontSize(): LogFontSize {
  return useSyncExternalStore(subscribe, read, () => DEFAULT_LOG_FONT_SIZE);
}
