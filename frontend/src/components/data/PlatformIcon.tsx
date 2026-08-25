import { Monitor } from 'lucide-react';
import type { IconType } from 'react-icons';
import { FaApple, FaFreebsd, FaLinux, FaWindows } from 'react-icons/fa';
import { cn } from '$/lib/cn';

export const PLATFORM_OPTIONS = [
  { id: 'linux', label: 'Linux' },
  { id: 'darwin', label: 'macOS' },
  { id: 'windows', label: 'Windows' },
  { id: 'freebsd', label: 'FreeBSD' },
  { id: 'all', label: 'All' },
] as const;

export type PlatformId = (typeof PLATFORM_OPTIONS)[number]['id'];

const PLATFORM_BRAND_ICONS: Record<Exclude<PlatformId, 'all'>, IconType> = {
  linux: FaLinux,
  darwin: FaApple,
  windows: FaWindows,
  freebsd: FaFreebsd,
};

const PLATFORM_COLORS: Record<PlatformId, string> = {
  linux: 'var(--plat-linux, var(--warning))',
  darwin: 'var(--plat-mac, var(--text-2))',
  windows: 'var(--plat-windows, var(--info))',
  freebsd: 'var(--danger)',
  all: 'var(--signal)',
};

export function PlatformIcon({
  platform,
  className,
}: {
  platform: PlatformId;
  className?: string;
}) {
  const iconClassName = cn('size-3.5 shrink-0', className);

  if (platform === 'all') {
    return (
      <Monitor
        aria-hidden
        className={iconClassName}
        color={PLATFORM_COLORS.all}
        strokeWidth={1.8}
      />
    );
  }

  const Icon = PLATFORM_BRAND_ICONS[platform];

  return (
    <Icon
      aria-hidden
      className={iconClassName}
      color={PLATFORM_COLORS[platform]}
    />
  );
}
