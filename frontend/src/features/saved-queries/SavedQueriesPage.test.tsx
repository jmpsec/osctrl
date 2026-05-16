import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
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
import { SavedQueriesPage } from './SavedQueriesPage';
import { savedQueriesSearchSchema } from '$/routes/_app/env/$env/saved-queries';
import type { SavedQuery, SavedQueriesPagedResponse } from '$/api/types';

// ---------------------------------------------------------------------------
// Mock the saved-queries API module
// ---------------------------------------------------------------------------
const mockList = vi.fn<() => Promise<SavedQueriesPagedResponse>>();
const mockCreate = vi.fn<(...args: unknown[]) => Promise<SavedQuery>>();
const mockUpdate = vi.fn<(...args: unknown[]) => Promise<SavedQuery>>();
const mockDelete = vi.fn<(...args: unknown[]) => Promise<{ message: string }>>();

vi.mock('$/api/saved-queries', () => ({
  listSavedQueries: (...args: unknown[]) => mockList(...(args as [])),
  createSavedQuery: (...args: unknown[]) => mockCreate(...args),
  updateSavedQuery: (...args: unknown[]) => mockUpdate(...args),
  deleteSavedQuery: (...args: unknown[]) => mockDelete(...args),
}));

vi.mock('$/api/client', () => ({
  isAuthenticated: () => true,
  getCsrfToken: () => 'test-csrf',
  setCsrfToken: vi.fn(),
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

// Monaco editor pulls in a heavy worker — stub it for tests.
vi.mock('$/components/forms/CodeEditor', () => ({
  CodeEditor: ({
    value,
    onChange,
    'aria-labelledby': labelledBy,
  }: {
    value: string;
    onChange?: (v: string) => void;
    'aria-labelledby'?: string;
  }) => (
    <textarea
      aria-labelledby={labelledBy}
      value={value}
      onChange={(e) => onChange?.(e.target.value)}
      data-testid="stub-code-editor"
    />
  ),
}));

// ---------------------------------------------------------------------------
// Stub response factory
// ---------------------------------------------------------------------------
function makeSaved(overrides: Partial<SavedQuery> = {}): SavedQuery {
  return {
    id: 42,
    created_at: new Date(Date.now() - 3600_000).toISOString(),
    updated_at: new Date().toISOString(),
    name: 'top_listening',
    creator: 'alice',
    query: 'SELECT pid, name, port FROM listening_ports;',
    environment_id: 1,
    extra_data: '',
    ...overrides,
  };
}

function makeResponse(
  overrides: Partial<SavedQueriesPagedResponse> = {},
): SavedQueriesPagedResponse {
  return {
    items: [makeSaved()],
    page: 1,
    page_size: 50,
    total_items: 1,
    total_pages: 1,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Router factory
// ---------------------------------------------------------------------------
function makeTestRouter(initialPath = '/_app/env/test-env/saved-queries') {
  const rootRoute = createRootRoute({ component: Outlet });

  const appRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/_app',
    component: Outlet,
  });

  const envRoute = createRoute({
    getParentRoute: () => appRoute,
    path: 'env/$env',
    component: Outlet,
  });

  const savedRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'saved-queries',
    validateSearch: savedQueriesSearchSchema,
    component: SavedQueriesPage,
  });

  const loginRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/login',
    component: () => <div data-testid="login">Login</div>,
  });

  const routeTree = rootRoute.addChildren([
    appRoute.addChildren([envRoute.addChildren([savedRoute])]),
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe('SavedQueriesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders saved-query rows after loading', async () => {
    mockList.mockResolvedValue(makeResponse());
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('top_listening')).toBeInTheDocument();
    });
    expect(screen.getByText('alice')).toBeInTheDocument();
  });

  it('shows empty state with "Save your first query" CTA when none exist', async () => {
    mockList.mockResolvedValue(
      makeResponse({ items: [], total_items: 0, total_pages: 0 }),
    );
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('No saved queries yet.')).toBeInTheDocument();
    });
    expect(
      screen.getByRole('button', { name: /save your first query/i }),
    ).toBeInTheDocument();
  });

  it('opens the create modal and calls createSavedQuery on submit', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue(makeResponse());
    mockCreate.mockResolvedValue(makeSaved({ name: 'new_q' }));

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('top_listening')).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: /new saved query/i }));

    const dialog = await screen.findByRole('dialog');
    expect(dialog).toBeInTheDocument();

    const nameInput = screen.getByLabelText(/^name$/i);
    await user.type(nameInput, 'new_q');

    const editor = screen.getByTestId('stub-code-editor');
    await user.clear(editor);
    await user.type(editor, 'SELECT 1');

    await user.click(screen.getByRole('button', { name: /^save query$/i }));

    await waitFor(() => {
      expect(mockCreate).toHaveBeenCalledTimes(1);
      const args = mockCreate.mock.calls[0] as [string, { name: string; query: string }];
      expect(args[0]).toBe('test-env');
      expect(args[1].name).toBe('new_q');
      expect(args[1].query).toBe('SELECT 1');
    });
  });

  it('clicking Delete row action opens confirm and calls deleteSavedQuery', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue(makeResponse());
    mockDelete.mockResolvedValue({ message: 'ok' });

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('top_listening')).toBeInTheDocument();
    });

    // The visible "Delete" row action button (not "Cancel"/"Delete" in modal).
    const deleteButtons = screen.getAllByRole('button', { name: /^delete$/i });
    await user.click(deleteButtons[0]);

    expect(await screen.findByRole('dialog')).toBeInTheDocument();
    // Confirm button inside the dialog
    const confirm = screen.getAllByRole('button', { name: /^delete$/i }).at(-1)!;
    await user.click(confirm);

    await waitFor(() => {
      expect(mockDelete).toHaveBeenCalledTimes(1);
      const args = mockDelete.mock.calls[0] as [string, string];
      expect(args[0]).toBe('test-env');
      expect(args[1]).toBe('top_listening');
    });
  });
});
