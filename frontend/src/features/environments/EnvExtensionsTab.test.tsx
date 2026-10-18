import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { EnvExtensionsTab } from './EnvExtensionsTab';
import type { EnvExtensions, ExtensionSummary } from '$/api/types';

const api = vi.hoisted(() => ({
  getEnvExtensions: vi.fn(),
  assignEnvExtension: vi.fn(),
  unassignEnvExtension: vi.fn(),
}));

vi.mock('$/api/extensions', () => ({
  getEnvExtensions: api.getEnvExtensions,
  assignEnvExtension: api.assignEnvExtension,
  unassignEnvExtension: api.unassignEnvExtension,
}));

function ext(o: Partial<ExtensionSummary> = {}): ExtensionSummary {
  return {
    id: 1,
    name: 'osq-ext',
    description: '',
    version: '1.0.0',
    command_execution: false,
    platforms: ['darwin', 'linux'],
    ...o,
  };
}

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(
    <QueryClientProvider client={qc}>
      <EnvExtensionsTab env="prod" />
    </QueryClientProvider>,
  );
  return { qc, ...view };
}

describe('EnvExtensionsTab', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.getEnvExtensions.mockResolvedValue({
      assigned: [ext()],
      available: [ext({ id: 2, name: 'other-ext', version: '2.0.0', platforms: ['windows'] })],
    } satisfies EnvExtensions);
  });

  it('lists assigned extensions with version and platforms, and the sync note', async () => {
    renderTab();
    const row = (await screen.findByText('osq-ext')).closest('li') as HTMLElement;
    expect(within(row).getByText('1.0.0')).toBeInTheDocument();
    expect(within(row).getByText('darwin, linux')).toBeInTheDocument();
    expect(api.getEnvExtensions).toHaveBeenCalledWith('prod');
    expect(
      screen.getByText('Hosts get these extensions from osctrld on its next sync (up to an hour).'),
    ).toBeInTheDocument();
  });

  it('assigns the picked extension and shows the refreshed view', async () => {
    api.assignEnvExtension.mockResolvedValue({
      assigned: [ext(), ext({ id: 2, name: 'other-ext' })],
      available: [],
    });
    const user = userEvent.setup();
    const { qc } = renderTab();
    await screen.findByText('osq-ext');
    const add = screen.getByRole('button', { name: 'Add extension' });
    expect(add).toBeDisabled();
    const picker = screen.getByLabelText('Extension to add');
    // Only the library's non-command-execution extensions the API offers are listed.
    expect(within(picker).getAllByRole('option').map((o) => o.textContent)).toEqual(['Select an extension…', 'other-ext 2.0.0']);
    await user.selectOptions(picker, 'other-ext 2.0.0');
    await user.click(add);
    await waitFor(() => expect(api.assignEnvExtension).toHaveBeenCalledWith('prod', 2));
    expect(await screen.findByText('other-ext')).toBeInTheDocument();
    expect(qc.getQueryData(['env-extensions', 'prod'])).toEqual({
      assigned: [ext(), ext({ id: 2, name: 'other-ext' })],
      available: [],
    });
    expect(screen.queryByLabelText('Extension to add')).not.toBeInTheDocument();
  });

  it('removes an assigned extension', async () => {
    api.unassignEnvExtension.mockResolvedValue({ assigned: [], available: [ext()] });
    const user = userEvent.setup();
    renderTab();
    await user.click(await screen.findByRole('button', { name: 'Remove osq-ext' }));
    await waitFor(() => expect(api.unassignEnvExtension).toHaveBeenCalledWith('prod', 1));
    expect(await screen.findByText('No extensions assigned to this environment.')).toBeInTheDocument();
  });

  it('shows the server error inline', async () => {
    api.assignEnvExtension.mockRejectedValue(new Error('extension is not assignable'));
    const user = userEvent.setup();
    renderTab();
    await screen.findByText('osq-ext');
    await user.selectOptions(screen.getByLabelText('Extension to add'), 'other-ext 2.0.0');
    await user.click(screen.getByRole('button', { name: 'Add extension' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('extension is not assignable');
  });
});
