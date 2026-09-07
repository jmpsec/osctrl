import { cn } from '$/lib/cn';
import { useTranslation } from 'react-i18next';
import { DropdownMenu } from '$/components/primitives/DropdownMenu';
import { logout } from '$/api/client';

interface UserMenuProps {
  username?: string;
}

function getInitials(name: string): string {
  return name
    .split(/\s+/)
    .map((w) => w[0]?.toUpperCase() ?? '')
    .slice(0, 2)
    .join('');
}

export function UserMenu({ username = 'admin' }: UserMenuProps) {
  const { t } = useTranslation();
  const initials = getInitials(username);

  function handleLogout() {
    // logout() owns the navigation. It POSTs to /api/v1/logout
    // (clears server-side cookies + revokes APIToken), then
    // either redirects to the IdP's end-session endpoint (which
    // in turn bounces to /login) OR straight to /login when no
    // IdP is configured. We do NOT chain a router.navigate here:
    // logout() may set window.location.href to a cross-origin
    // URL (Keycloak), and racing with TanStack Router would
    // either no-op or cause a tab flash.
    void logout();
  }

  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button
          aria-label={t('topbar.userMenu', { name: username })}
          className={cn(
            'w-8 h-8 rounded-md flex items-center justify-center',
            'text-xs font-semibold',
            'bg-[color:var(--bg-3)] border border-[color:var(--border)]',
            'transition-colors duration-[100ms]',
            'hover:border-[color:var(--border-strong)] hover:bg-[color:var(--bg-2)]',
            'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1',
            'focus-visible:outline-[color:var(--accent)]',
            'text-[color:var(--text-1)]'
          )}
        >
          {initials}
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Content align="end" sideOffset={8}>
        <DropdownMenu.Label className="tabular-nums">{username}</DropdownMenu.Label>
        <DropdownMenu.Separator />
        <DropdownMenu.Item
          onClick={handleLogout}
          className="text-[color:var(--danger)] hover:text-[color:var(--danger)] focus:text-[color:var(--danger)] hover:bg-[color:var(--danger)]/10 focus:bg-[color:var(--danger)]/10"
        >
          <svg
            className="w-4 h-4"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
          >
            <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4" />
            <polyline points="16 17 21 12 16 7" />
            <line x1="21" y1="12" x2="9" y2="12" />
          </svg>
          {t('common.signOut')}
        </DropdownMenu.Item>
      </DropdownMenu.Content>
    </DropdownMenu.Root>
  );
}
