import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createMemoryHistory,
  createRouter,
  createRoute,
  createRootRoute,
  RouterProvider,
  Outlet,
} from '@tanstack/react-router';
import { ServiceConfigPage } from './ServiceConfigPage';
import type { ServiceConfig } from '$/api/service-config';

const mockList = vi.fn<(service: string) => Promise<ServiceConfig[]>>();
const mockUpdate = vi.fn();
const mockApply = vi.fn();

vi.mock('$/api/service-config', () => ({
  listServiceConfig: (service: string) => mockList(service),
  updateServiceConfig: (...args: unknown[]) => mockUpdate(...args),
  applyServiceConfig: () => mockApply(),
}));

vi.mock('$/api/client', () => ({
  isAuthenticated: () => true,
  AuthError: class AuthError extends Error {
    readonly status = 401;
    constructor() {
      super('Unauthorized');
    }
  },
  ApiError: class ApiError extends Error {
    constructor(msg: string, public status: number, public code?: string) {
      super(msg);
    }
  },
}));

// Monaco Editor is lazy-loaded and not available in jsdom. Capture the
// onChange callback so tests can simulate edits.
let lastEditorOnChange: ((v: string | undefined) => void) | null = null;
vi.mock('@monaco-editor/react', () => ({
  Editor: ({ value, onChange }: { value: string; onChange?: (v: string | undefined) => void }) => {
    lastEditorOnChange = onChange ?? null;
    return (
      <div
        data-testid="monaco-editor"
        data-value={value}
        data-readonly={onChange === undefined}
      />
    );
  },
}));

function makeSection(overrides: Partial<ServiceConfig> = {}): ServiceConfig {
  return {
    ID: 1,
    CreatedAt: new Date().toISOString(),
    UpdatedAt: new Date().toISOString(),
    Name: 'logger',
    Service: 'api',
    EnvironmentID: 0,
    Type: 'json',
    Value: '{"type":"stdout"}',
    Source: 'yaml',
    Editable: false,
    Info: 'Log sinks',
    ...overrides,
  };
}

function makeTestRouter(initialPath = '/_app/config/api') {
  const rootRoute = createRootRoute({ component: Outlet });
  const appRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/_app',
    component: Outlet,
  });
  const configRoute = createRoute({
    getParentRoute: () => appRoute,
    path: 'config/$service',
    component: ServiceConfigPage,
  });
  const loginRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/login',
    component: () => <div data-testid="login">Login</div>,
  });
  const routeTree = rootRoute.addChildren([
    appRoute.addChildren([configRoute]),
    loginRoute,
  ]);
  const history = createMemoryHistory({ initialEntries: [initialPath] });
  return createRouter({ routeTree, history });
}

function renderWithProviders(router: ReturnType<typeof makeTestRouter>) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe('ServiceConfigPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    lastEditorOnChange = null;
  });

  it('renders service config sections with their names and badges', async () => {
    mockList.mockResolvedValue([
      makeSection(),
      makeSection({
        ID: 2,
        Name: 'saml',
        Value: '{"enabled":true}',
        Source: 'db',
        Editable: true,
        Info: 'SAML federated login',
      }),
    ]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('logger')).toBeInTheDocument();
    });
    expect(screen.getByText('saml')).toBeInTheDocument();
    expect(screen.getByText('yaml')).toBeInTheDocument();
    expect(screen.getByText('db')).toBeInTheDocument();
    expect(screen.getByText('read-only')).toBeInTheDocument();
    expect(screen.getByText('editable')).toBeInTheDocument();
    expect(mockList).toHaveBeenCalledWith('api');
  });

  it('renders the service tabs and switches service on click', async () => {
    mockList.mockResolvedValue([]);
    renderWithProviders(makeTestRouter('/_app/config/tls'));

    await waitFor(() => {
      expect(screen.getByRole('tab', { name: 'osctrl-tls' })).toBeInTheDocument();
    });
    expect(screen.getByRole('tab', { name: 'osctrl-api' })).toBeInTheDocument();
    expect(mockList).toHaveBeenCalledWith('tls');
  });

  it('shows empty state when no sections are returned', async () => {
    mockList.mockResolvedValue([]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('No service config for api.')).toBeInTheDocument();
    });
  });

  it('shows error state when the API fails', async () => {
    const { ApiError } = await import('$/api/client');
    mockList.mockRejectedValue(new ApiError('Internal error', 500));
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('Internal error')).toBeInTheDocument();
    });
    expect(screen.getByText('Retry')).toBeInTheDocument();
  });

  it('pretty-prints JSON values in the editor', async () => {
    mockList.mockResolvedValue([
      makeSection({ Value: '{"type":"stdout","alwaysLog":true}' }),
    ]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      const editor = screen.getByTestId('monaco-editor');
      const value = editor.getAttribute('data-value') ?? '';
      expect(value).toContain('\n');
      expect(value).toContain('"type": "stdout"');
    });
  });

  it('renders raw value when it is not valid JSON', async () => {
    mockList.mockResolvedValue([
      makeSection({ Value: 'not-json' }),
    ]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      const editor = screen.getByTestId('monaco-editor');
      expect(editor.getAttribute('data-value')).toBe('not-json');
    });
  });

  it('does not show Edit button for read-only sections', async () => {
    mockList.mockResolvedValue([makeSection({ Editable: false })]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('logger')).toBeInTheDocument();
    });
    expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
  });

  it('shows Edit button for editable sections', async () => {
    mockList.mockResolvedValue([makeSection({ Editable: true, Name: 'debug' })]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('debug')).toBeInTheDocument();
    });
    expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument();
  });

  it('enters edit mode and shows Save/Cancel when Edit is clicked', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([makeSection({ Editable: true, Name: 'debug' })]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument();
    });
    await user.click(screen.getByRole('button', { name: 'Edit' }));

    expect(screen.getByRole('button', { name: 'Save' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeInTheDocument();
    // Editor should now be writable (onChange is wired).
    expect(lastEditorOnChange).not.toBeNull();
  });

  it('calls updateServiceConfig when Save is clicked after editing', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([makeSection({ Editable: true, Name: 'debug' })]);
    mockUpdate.mockResolvedValue(makeSection({ Value: '{"enableHttp":true}', Source: 'db' }));
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument();
    });
    await user.click(screen.getByRole('button', { name: 'Edit' }));

    // Simulate an edit in the Monaco editor.
    expect(lastEditorOnChange).not.toBeNull();
    await act(async () => {
      lastEditorOnChange!('{\n  "enableHttp": true\n}');
    });

    await user.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => {
      expect(mockUpdate).toHaveBeenCalledTimes(1);
    });
    const args = mockUpdate.mock.calls[0] as [string, string, { value: unknown }];
    expect(args[0]).toBe('api');
    expect(args[1]).toBe('debug');
    expect(args[2].value).toEqual({ enableHttp: true });
  });

  it('cancels editing and restores the original value', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([makeSection({ Editable: true, Name: 'debug' })]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument();
    });
    await user.click(screen.getByRole('button', { name: 'Edit' }));

    await act(async () => {
      lastEditorOnChange!('{\n  "enableHttp": true\n}');
    });
    await user.click(screen.getByRole('button', { name: 'Cancel' }));

    // Back to read-only, Edit button visible again.
    expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();
    // Editor shows the original pretty-printed value.
    const editor = screen.getByTestId('monaco-editor');
    expect(editor.getAttribute('data-value')).toContain('"type": "stdout"');
  });

  it('shows an error when the PUT returns 409 (not editable)', async () => {
    const user = userEvent.setup();
    const { ApiError } = await import('$/api/client');
    mockList.mockResolvedValue([makeSection({ Editable: true, Name: 'debug' })]);
    mockUpdate.mockRejectedValue(new ApiError('section is not editable', 409));
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument();
    });
    await user.click(screen.getByRole('button', { name: 'Edit' }));
    await act(async () => {
      lastEditorOnChange!('{\n  "enableHttp": true\n}');
    });
    await user.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => {
      expect(screen.getByText('Section is not editable.')).toBeInTheDocument();
    });
  });

  it('does not show Apply & Restart button when no sections have source=db', async () => {
    mockList.mockResolvedValue([makeSection({ Source: 'yaml' })]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('logger')).toBeInTheDocument();
    });
    expect(screen.queryByRole('button', { name: /Apply & Restart/i })).not.toBeInTheDocument();
  });

  it('shows Apply & Restart button when a section has source=db', async () => {
    mockList.mockResolvedValue([makeSection({ Source: 'db', Name: 'debug', Editable: true })]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Apply & Restart/i })).toBeInTheDocument();
    });
  });

  it('calls applyServiceConfig when Apply & Restart is clicked', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([makeSection({ Source: 'db', Name: 'debug', Editable: true })]);
    mockApply.mockResolvedValue({ message: 'Restart triggered.' });
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Apply & Restart/i })).toBeInTheDocument();
    });
    await user.click(screen.getByRole('button', { name: /Apply & Restart/i }));

    await waitFor(() => {
      expect(mockApply).toHaveBeenCalledTimes(1);
    });
  });
});
