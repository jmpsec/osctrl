import { cn } from '$/lib/cn';

interface LogoProps {
  size?: number;
  className?: string;
  decorative?: boolean;
}

export function Logo({ size = 32, className, decorative = false }: LogoProps) {
  return (
    <svg
      viewBox="0 0 64 64"
      width={size}
      height={size}
      className={cn('text-[color:var(--signal)]', className)}
      role={decorative ? undefined : 'img'}
      aria-hidden={decorative ? true : undefined}
      aria-label={decorative ? undefined : 'osctrl logo'}
    >
      <path d="M14 22 Q32 4 50 22" stroke="currentColor" strokeWidth="3" strokeLinecap="round" fill="none" />
      <path d="M20 28 Q32 18 44 28" stroke="currentColor" strokeWidth="3" strokeLinecap="round" fill="none" />
      <circle cx="32" cy="32" r="2" fill="currentColor" />
      <path d="M20 38 L44 38 L40 46 L24 46 Z" fill="currentColor" />
      <rect x="29.5" y="46" width="5" height="10" fill="currentColor" rx="1" />
      <rect x="22" y="56" width="20" height="3" fill="currentColor" rx="1" />
    </svg>
  );
}
