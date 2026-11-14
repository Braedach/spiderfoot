import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import ModuleOptionsEditor from '../../components/ModuleOptionsEditor';
import { configApi, type Module } from '../../lib/api';

vi.mock('../../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../../lib/api')>('../../lib/api');
  return { ...actual, configApi: { ...actual.configApi, updateModuleOptions: vi.fn().mockResolvedValue({}) } };
});

const mod = {
  name: 'sfp_example',
  opts: { api_key: 'secret-value', max_results: 25, verify: true, note: 'hello' },
  optdescs: { api_key: 'Your API key', max_results: 'How many results' },
} as unknown as Module;

function renderEditor(onResult = vi.fn()) {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <ModuleOptionsEditor module={mod} onResult={onResult} />
    </QueryClientProvider>,
  );
  return onResult;
}

describe('ModuleOptionsEditor', () => {
  beforeEach(() => vi.clearAllMocks());

  it('masks API keys until revealed and lists them first', () => {
    renderEditor();
    const key = screen.getByLabelText('api_key') as HTMLInputElement;
    expect(key.type).toBe('password');
    fireEvent.click(screen.getByLabelText('Show api_key'));
    expect(key.type).toBe('text');
    const labels = screen.getAllByText(/^(api_key|max_results|note|verify)$/).map((e) => e.textContent);
    expect(labels[0]).toBe('api_key');
  });

  it('saves only the edited options, including an API key', async () => {
    const onResult = renderEditor();
    const save = screen.getByText('Save changes').closest('button') as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText('api_key'), { target: { value: 'new-key' } });
    fireEvent.change(screen.getByLabelText('max_results'), { target: { value: '50' } });
    expect(save.disabled).toBe(false);
    fireEvent.click(save);
    await waitFor(() => expect(configApi.updateModuleOptions).toHaveBeenCalledWith('sfp_example', { api_key: 'new-key', max_results: '50' }));
    await waitFor(() => expect(onResult).toHaveBeenCalledWith('success', 'sfp_example saved'));
  });

  it('can toggle a boolean option', async () => {
    renderEditor();
    fireEvent.click(screen.getByRole('switch', { name: 'verify' }));
    fireEvent.click(screen.getByText('Save changes').closest('button') as HTMLButtonElement);
    await waitFor(() => expect(configApi.updateModuleOptions).toHaveBeenCalledWith('sfp_example', { verify: 'false' }));
  });
});
