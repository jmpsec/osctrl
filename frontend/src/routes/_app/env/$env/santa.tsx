import { createRoute } from '@tanstack/react-router';
import { envRoute } from './route';
import { SantaPage, SANTA_TABS, type SantaTab } from '$/features/santa/SantaPage';

const SHA256 = /^[0-9a-f]{64}$/i;

export interface SantaSearch {
  tab?: SantaTab;
  /** SHA-256 of the file whose binary details are open. */
  binary?: string;
}

export const envSantaRoute = createRoute({
  getParentRoute: () => envRoute,
  path: 'santa',
  validateSearch: (s: Record<string, unknown>): SantaSearch => ({
    tab: SANTA_TABS.find((t) => t === s.tab),
    binary: typeof s.binary === 'string' && SHA256.test(s.binary) ? s.binary.toLowerCase() : undefined,
  }),
  component: SantaPage,
});
