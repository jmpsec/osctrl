import { cn } from '$/lib/cn';

interface LogoProps {
  size?: number;
  className?: string;
  decorative?: boolean;
}

/**
 * Original osctrl tower mark from cmd/admin/static/img/logo.png — the
 * artwork legacy operators already recognise. Rendered as a plain
 * <img> because the PNG carries the brand asset (tower + arcs + cabin
 * windows). Inverted via a Tailwind `invert` utility in dark mode so
 * the near-black outline reads against the dark chrome; left as-is in
 * light mode where the outline already pops. The `decorative` flag
 * controls aria semantics, matching the previous SVG component's API
 * so this swap doesn't require any caller changes.
 */
export function Logo({ size = 32, className, decorative = false }: LogoProps) {
  return (
    <img
      src="/img/osctrl-logo.png"
      width={size}
      height={size}
      alt={decorative ? '' : 'osctrl logo'}
      aria-hidden={decorative ? true : undefined}
      className={cn('osctrl-logo', className)}
    />
  );
}
