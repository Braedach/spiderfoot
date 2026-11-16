import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';

const { test, state } = vi.hoisted(() => ({ test: vi.fn(), state: { failRequest: false } }));

vi.mock('../lib/api', async (orig) => {
  const actual = await orig<typeof import('../lib/api')>();
  return { ...actual, webSearchApi: { test: (...a: unknown[]) => (state.failRequest ? Promise.reject(new Error('network')) : test(...a)) } };
});

import { WebSearchTest } from '../components/WebSearchTest';

beforeEach(() => { test.mockReset(); state.failRequest = false; });

describe('WebSearchTest', () => {
  it('tests the typed address and shows a success message', async () => {
    test.mockResolvedValue({ ok: true, message: 'Connected. A test search returned 12 results from 3 engine(s).' });
    render(<WebSearchTest url="  https://search.example.org  " />);
    fireEvent.click(screen.getByText('Test connection'));
    const result = await screen.findByTestId('websearch-test-result');
    expect(result.textContent).toContain('Connected');
    expect(test.mock.calls[0][0]).toBe('https://search.example.org');             // trimmed
  });

  it('shows what is wrong when the server does not answer properly', async () => {
    test.mockResolvedValue({ ok: false, message: "The server refused the search. The json format is probably not enabled: add 'json' under search.formats in the server's settings.yml." });
    render(<WebSearchTest url="https://search.example.org" />);
    fireEvent.click(screen.getByText('Test connection'));
    expect((await screen.findByTestId('websearch-test-result')).textContent).toContain('settings.yml');
  });

  it('with no address typed it asks the server to test the saved one', async () => {
    test.mockResolvedValue({ ok: false, message: 'No address entered.' });
    render(<WebSearchTest url="   " />);
    fireEvent.click(screen.getByText('Test connection'));
    await waitFor(() => expect(test).toHaveBeenCalledTimes(1));
    expect(test.mock.calls[0][0]).toBeUndefined();
  });

  it('reports a failed test request instead of failing silently, and shows nothing before it is used', async () => {
    state.failRequest = true;   // the request itself fails (network down, API unreachable)
    render(<WebSearchTest url="https://search.example.org" />);
    expect(screen.queryByTestId('websearch-test-result')).toBeNull();
    fireEvent.click(screen.getByText('Test connection'));
    expect((await screen.findByTestId('websearch-test-result')).textContent).toContain('could not be run');
  });

  it('disables the button while a test is running', async () => {
    let finish: (v: unknown) => void = () => {};
    test.mockReturnValue(new Promise((r) => { finish = r; }));
    render(<WebSearchTest url="https://search.example.org" />);
    fireEvent.click(screen.getByText('Test connection'));
    await waitFor(() => expect((screen.getByText('Test connection').closest('button') as HTMLButtonElement).disabled).toBe(true));
    finish({ ok: true, message: 'Connected.' });
    await waitFor(() => expect((screen.getByText('Test connection').closest('button') as HTMLButtonElement).disabled).toBe(false));
  });
});
