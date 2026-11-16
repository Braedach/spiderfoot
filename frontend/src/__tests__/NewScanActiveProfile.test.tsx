/**
 * New Scan > By Profile: a profile that tests the target actively (web-app-test) cannot be launched until the person
 * confirms they are authorised to test the target, and the request says so.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

const { create, profile } = vi.hoisted(() => ({
  create: vi.fn().mockResolvedValue({ id: 'ABC123' }),
  profile: (name: string, display: string, requires: boolean) => ({
    name, display_name: display, description: `${display} description.`, category: 'vulnerability', module_count: 10,
    modules: [], tags: [], max_threads: 0, timeout_minutes: 0, requires_authorisation: requires,
  }),
}));

vi.mock('../lib/api', async (orig) => {
  const actual = await orig<typeof import('../lib/api')>();
  return {
    ...actual,
    dataApi: { ...actual.dataApi, modules: vi.fn().mockResolvedValue({ modules: [], total: 0 }), entityTypes: vi.fn().mockResolvedValue([]) },
    scanApi: {
      ...actual.scanApi,
      profiles: vi.fn().mockResolvedValue({ profiles: [profile('quick-recon', 'Quick Reconnaissance', false), profile('web-app-test', 'Web Application Test', true)], total: 2 }),
      searchTypes: vi.fn().mockResolvedValue({ search_types: [], total: 0 }),
      create: (...args: unknown[]) => create(...args),
    },
  };
});

import NewScanPage from '../pages/NewScan';

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter><NewScanPage /></MemoryRouter></QueryClientProvider>);
}

const targetInput = () => screen.getByPlaceholderText(/Enter domain, IP, email, phone, name, or ASN/i) as HTMLInputElement;
const launch = () => screen.getByText('Launch Scan').closest('button') as HTMLButtonElement;

async function openProfile(name: string) {
  renderPage();
  fireEvent.click(screen.getByText('By Profile'));
  fireEvent.click(await screen.findByText(name));
  fireEvent.change(targetInput(), { target: { value: 'example.com' } });
}

beforeEach(() => create.mockClear());

describe('active-testing profile', () => {
  it('shows no confirmation for an ordinary profile and launches it', async () => {
    await openProfile('Quick Reconnaissance');
    expect(screen.queryByTestId('authorised-to-test')).toBeNull();
    expect(launch().disabled).toBe(false);
    fireEvent.click(launch());
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    expect(create.mock.calls[0][0].profile).toBe('quick-recon');
    expect(create.mock.calls[0][0].authorised_to_test).toBeUndefined();
  });

  it('asks for the confirmation and blocks the launch until it is ticked', async () => {
    await openProfile('Web Application Test');
    expect(screen.getByTestId('authorised-to-test')).toBeTruthy();
    expect(launch().disabled).toBe(true);
    fireEvent.click(launch());
    expect(create).not.toHaveBeenCalled();
  });

  it('sends authorised_to_test once the box is ticked', async () => {
    await openProfile('Web Application Test');
    fireEvent.click(screen.getByRole('checkbox'));
    await waitFor(() => expect(launch().disabled).toBe(false));
    fireEvent.click(launch());
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    expect(create.mock.calls[0][0]).toMatchObject({ profile: 'web-app-test', authorised_to_test: true });
  });

  it('forgets the confirmation when another profile is chosen and back', async () => {
    await openProfile('Web Application Test');
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByText('Quick Reconnaissance'));
    fireEvent.click(screen.getByText('Web Application Test'));
    expect((screen.getByRole('checkbox') as HTMLInputElement).checked).toBe(false);
    expect(launch().disabled).toBe(true);
  });
});
