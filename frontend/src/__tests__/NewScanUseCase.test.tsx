/**
 * New Scan > By Use Case: the six searches (domain, IP address, email, phone, person name, ASN) plus All Modules. The
 * page picks the search that matches the typed target, warns when the chosen one does not fit, and launches the profile
 * built for the search.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

const { create, SEARCH_TYPES } = vi.hoisted(() => {
  const create = vi.fn().mockResolvedValue({ id: 'ABC123' });

  const profile = (name: string, display: string, count: number, inactive: string[] = []) => ({
    name, display_name: display, description: `${display} description. Second sentence.`, category: 'reconnaissance',
    module_count: count, modules: Array.from({ length: count }, (_, i) => `sfp_${name}_${i}`), tags: [],
    max_threads: 0, timeout_minutes: 0, optional_total: inactive.length, optional_active: [], optional_inactive: inactive,
  });

  const SEARCH_TYPES = [
    { key: 'domain', label: 'Domain', profile: 'full-footprint', example: 'example.com', target_types: ['INTERNET_NAME'], profile_info: profile('full-footprint', 'Full Footprint', 175) },
    { key: 'ip', label: 'IP address', profile: 'ip-address', example: '203.0.113.10', target_types: ['IP_ADDRESS'], profile_info: profile('ip-address', 'IP Address Intelligence', 53, ['sfp_shodan', 'sfp_greynoise']) },
    { key: 'email', label: 'Email address', profile: 'email-address', example: 'name@example.com', target_types: ['EMAILADDR'], profile_info: profile('email-address', 'Email Address Intelligence', 20) },
    { key: 'phone', label: 'Phone number', profile: 'phone-number', example: '+61400000000', target_types: ['PHONE_NUMBER'], profile_info: profile('phone-number', 'Phone Number Intelligence', 4) },
    { key: 'name', label: 'Person name', profile: 'person-name', example: 'Pat Example', target_types: ['HUMAN_NAME'], profile_info: profile('person-name', 'Person Name Intelligence', 14) },
    { key: 'asn', label: 'ASN', profile: 'asn', example: 'AS64496', target_types: ['BGP_AS_OWNER'], profile_info: profile('asn', 'ASN Intelligence', 7) },
  ];
  return { create, SEARCH_TYPES };
});

vi.mock('../lib/api', async (orig) => {
  const actual = await orig<typeof import('../lib/api')>();
  return {
    ...actual,
    dataApi: {
      ...actual.dataApi,
      modules: vi.fn().mockResolvedValue({ modules: [], total: 0 }),
      entityTypes: vi.fn().mockResolvedValue([]),
    },
    scanApi: {
      ...actual.scanApi,
      profiles: vi.fn().mockResolvedValue({ profiles: [], total: 0 }),
      searchTypes: vi.fn().mockResolvedValue({ search_types: SEARCH_TYPES, total: 6 }),
      create: (...args: unknown[]) => create(...args),
    },
  };
});

import NewScanPage from '../pages/NewScan';

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter><NewScanPage /></MemoryRouter>
    </QueryClientProvider>,
  );
}

const targetInput = () => screen.getByPlaceholderText(/Enter domain, IP, email, phone, name, or ASN/i) as HTMLInputElement;
const isSelected = (testId: string) => screen.getByTestId(testId).className.includes('border-spider-500');

beforeEach(() => { create.mockClear(); });

describe('New Scan > By Use Case', () => {
  it('offers the six searches and All Modules, and no longer the generic use cases', async () => {
    renderPage();
    for (const key of ['domain', 'ip', 'email', 'phone', 'name', 'asn', 'all']) {
      expect(await screen.findByTestId(`usecase-${key}`)).toBeTruthy();
    }
    for (const gone of ['Quick Scan', 'Footprint', 'Investigate', 'Passive Only']) {
      expect(screen.queryByText(gone, { selector: 'p' })).toBeNull();
    }
  });

  it('shows what each search runs: its module count, the keyed modules still needing a key, and an example', async () => {
    renderPage();
    const ip = await screen.findByTestId('usecase-ip');
    expect(ip.textContent).toContain('53 modules');
    expect(ip.textContent).toContain('2 more need an API key');
    expect(ip.textContent).toContain('203.0.113.10');
    expect(ip.textContent).toContain('IP Address Intelligence description.');
    expect(ip.textContent).not.toContain('Second sentence');
  });

  it.each([
    ['example.com', 'usecase-domain'],
    ['203.0.113.10', 'usecase-ip'],
    ['name@example.com', 'usecase-email'],
    ['+61400000000', 'usecase-phone'],
    ['"Pat Example"', 'usecase-name'],
    ['AS64496', 'usecase-asn'],
  ])('typing %s selects the matching search', async (typed, testId) => {
    renderPage();
    await screen.findByTestId(testId);
    fireEvent.change(targetInput(), { target: { value: typed } });
    await waitFor(() => expect(isSelected(testId)).toBe(true));
    expect(screen.queryByTestId('usecase-mismatch')).toBeNull();
  });

  it('warns when the chosen search does not fit the target, and offers the one that does', async () => {
    renderPage();
    await screen.findByTestId('usecase-domain');
    fireEvent.change(targetInput(), { target: { value: 'example.com' } });
    await waitFor(() => expect(isSelected('usecase-domain')).toBe(true));
    fireEvent.click(screen.getByTestId('usecase-phone'));
    const warning = await screen.findByTestId('usecase-mismatch');
    expect(warning.textContent).toContain('looks like a Domain');
    expect(warning.textContent).toContain('Phone number');
    fireEvent.click(screen.getByText('Use Domain instead'));
    await waitFor(() => expect(isSelected('usecase-domain')).toBe(true));
    expect(screen.queryByTestId('usecase-mismatch')).toBeNull();
  });

  it('does not override a search the user picked, even when they keep typing', async () => {
    renderPage();
    await screen.findByTestId('usecase-email');
    fireEvent.click(screen.getByTestId('usecase-email'));
    fireEvent.change(targetInput(), { target: { value: 'example.com' } });
    expect(isSelected('usecase-email')).toBe(true);
    expect(await screen.findByTestId('usecase-mismatch')).toBeTruthy();
  });

  it('All Modules never warns about a mismatch', async () => {
    renderPage();
    await screen.findByTestId('usecase-all');
    fireEvent.click(screen.getByTestId('usecase-all'));
    fireEvent.change(targetInput(), { target: { value: '203.0.113.10' } });
    expect(screen.queryByTestId('usecase-mismatch')).toBeNull();
  });

  it('launches the profile built for the search', async () => {
    renderPage();
    await screen.findByTestId('usecase-ip');
    fireEvent.change(targetInput(), { target: { value: '203.0.113.10' } });
    await waitFor(() => expect(isSelected('usecase-ip')).toBe(true));
    fireEvent.click(screen.getByText('Launch Scan'));
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    const payload = create.mock.calls[0][0];
    expect(payload.target).toBe('203.0.113.10');
    expect(payload.profile).toBe('ip-address');
    expect(payload.modules).toBeUndefined();
  });

  it('All Modules sends no profile and no module list, so the server runs every reliable module', async () => {
    renderPage();
    await screen.findByTestId('usecase-all');
    fireEvent.click(screen.getByTestId('usecase-all'));
    fireEvent.change(targetInput(), { target: { value: 'example.com' } });
    fireEvent.click(screen.getByText('Launch Scan'));
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    const payload = create.mock.calls[0][0];
    expect(payload.profile).toBeUndefined();
    expect(payload.modules).toBeUndefined();
  });

  it('summarises the chosen search under the form', async () => {
    renderPage();
    await screen.findByTestId('usecase-phone');
    fireEvent.change(targetInput(), { target: { value: '+61400000000' } });
    await waitFor(() => expect(screen.getByText(/Phone number search: Phone Number Intelligence \(4 modules\)/)).toBeTruthy());
  });

  it('offers the optional subject context only for person searches, pre-filled from the target, and sends it', async () => {
    renderPage();
    await screen.findByTestId('usecase-phone');
    expect(screen.queryByTestId('subject-context')).toBeNull();                 // nothing selected yet
    fireEvent.change(targetInput(), { target: { value: '+61400000000' } });
    await waitFor(() => expect(isSelected('usecase-phone')).toBe(true));
    const country = await screen.findByLabelText('Subject country') as HTMLInputElement;
    expect(country.value).toBe('Australia');                                    // from the calling code only
    fireEvent.change(screen.getByLabelText('Subject city or state'), { target: { value: 'Perth' } });
    fireEvent.click(screen.getByText('Launch Scan'));
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    const payload = create.mock.calls[0][0];
    expect(payload.subject_country).toBe('Australia');
    expect(payload.subject_region).toBe('Perth');
  });

  it('never guesses a country from a name, and does not offer the context for a domain or an IP address', async () => {
    renderPage();
    await screen.findByTestId('usecase-name');
    fireEvent.change(targetInput(), { target: { value: 'Pat Example' } });
    const country = await screen.findByLabelText('Subject country') as HTMLInputElement;
    expect(country.value).toBe('');
    fireEvent.change(targetInput(), { target: { value: 'example.com' } });
    await waitFor(() => expect(screen.queryByTestId('subject-context')).toBeNull());
    fireEvent.change(targetInput(), { target: { value: '203.0.113.10' } });
    await waitFor(() => expect(screen.queryByTestId('subject-context')).toBeNull());
  });

  it('keeps what the user typed over the pre-filled country, and sends nothing when the fields are empty', async () => {
    renderPage();
    await screen.findByTestId('usecase-email');
    fireEvent.change(targetInput(), { target: { value: 'pat@example.com' } });
    const country = await screen.findByLabelText('Subject country') as HTMLInputElement;
    fireEvent.change(country, { target: { value: 'New Zealand' } });
    fireEvent.change(targetInput(), { target: { value: 'pat@example.com.au' } });
    expect((screen.getByLabelText('Subject country') as HTMLInputElement).value).toBe('New Zealand');
    fireEvent.change(screen.getByLabelText('Subject country'), { target: { value: '' } });
    fireEvent.click(screen.getByText('Launch Scan'));
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    expect(create.mock.calls[0][0].subject_country).toBeUndefined();
    expect(create.mock.calls[0][0].subject_region).toBeUndefined();
  });

  it('sends the subject label when one is typed, and nothing otherwise', async () => {
    renderPage();
    await screen.findByTestId('usecase-name');
    fireEvent.change(targetInput(), { target: { value: 'Pat Example' } });
    fireEvent.change(await screen.findByLabelText('Subject label'), { target: { value: '  pat  ' } });
    fireEvent.click(screen.getByText('Launch Scan'));
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    expect(create.mock.calls[0][0].subject_label).toBe('pat');
  });

  it('does not send a subject label when the box is empty', async () => {
    renderPage();
    await screen.findByTestId('usecase-name');
    fireEvent.change(targetInput(), { target: { value: 'Pat Example' } });
    await screen.findByLabelText('Subject label');
    fireEvent.click(screen.getByText('Launch Scan'));
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    expect(create.mock.calls[0][0].subject_label).toBeUndefined();
  });
});
