import { useRouter } from '@tanstack/react-router';
import { cn } from '$/lib/cn';
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
  const router = useRouter();
  const initials = getInitials(username);

  function handleLogout() {
    logout();
    void router.navigate({ to: '/login' });
  }

  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button
          aria-label={`User menu for ${username}`}
          className={cn(
            'w-9 h-9 rounded-full flex items-center justify-center',
            'font-mono-tabular text-[11px] font-semibold',
            'bg-[color:var(--bg-2)] border border-[color:var(--border)]',
            'shadow-[0_0_0_2px_rgba(var(--halo-r),var(--halo-g),var(--halo-b),0.18)]',
            'transition-all duration-[120ms]',
            'hover:border-[color:var(--border-strong)] hover:shadow-[0_0_0_2px_rgba(var(--halo-r),var(--halo-g),var(--halo-b),0.32)]',
            'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1',
            'focus-visible:outline-[color:var(--signal)]',
            'text-[color:var(--text-1)]'
          )}
        >
          {initials}
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Content align="end" sideOffset={8}>
        <DropdownMenu.Label className="font-mono-tabular">{username}</DropdownMenu.Label>
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
          Sign out
        </DropdownMenu.Item>
      </DropdownMenu.Content>
    </DropdownMenu.Root>
  );
}
