import { cn } from '$/lib/cn';

interface LogoProps {
  size?: number;
  className?: string;
  decorative?: boolean;
}

/**
 * Original osctrl tower mark from cmd/admin/static/img/logo.png — the
 * artwork legacy operators already recognise. Two PNG variants exist:
 *
 *   /img/osctrl-logo.png      — original (dark outline, light-blue
 *                                cabin windows). Used in light theme.
 *   /img/osctrl-logo-dark.png — manually recolored (light outline,
 *                                brand-info blue cabin windows). Used
 *                                in dark theme.
 *
 * The .osctrl-logo CSS rule in base.css shows one or the other based
 * on data-theme, no JS state needed. This replaces the previous
 * filter:invert() hack which Tailwind's minifier kept breaking.
 */
export function Logo({ size = 32, className, decorative = false }: LogoProps) {
  return (
    <span
      className={cn('osctrl-logo', className)}
      role={decorative ? undefined : 'img'}
      aria-label={decorative ? undefined : 'osctrl logo'}
      aria-hidden={decorative ? true : undefined}
      style={{ display: 'inline-block', width: size, height: size }}
    >
      <img
        src="/img/osctrl-logo.png"
        width={size}
        height={size}
        alt=""
        className="osctrl-logo-light"
        style={{ display: 'block', width: '100%', height: '100%' }}
      />
      <img
        src="/img/osctrl-logo-dark.png"
        width={size}
        height={size}
        alt=""
        className="osctrl-logo-dark"
        style={{ display: 'block', width: '100%', height: '100%' }}
      />
    </span>
  );
}
