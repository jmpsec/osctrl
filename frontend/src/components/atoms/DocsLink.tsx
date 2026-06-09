import { cn } from '$/lib/cn';

/**
 * DocsLink — small "docs" affordance that opens an external documentation
 * URL in a new tab. Designed to live in section headers next to a title.
 *
 * Visual: a "?" glyph + the word "docs" in dim mono-tabular text, both
 * tucked into a low-contrast pill that brightens on hover. The link goes
 * through `rel="noopener noreferrer"` since the target is third-party
 * (typically osquery's read-the-docs site) and we don't want the docs
 * tab to be able to navigate the SPA back via window.opener.
 */
export function DocsLink({
  href,
  label = 'docs',
  className,
}: {
  href: string;
  label?: string;
  className?: string;
}) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      aria-label={`Open documentation: ${label}`}
      className={cn(
        'inline-flex items-center gap-1 px-1.5 py-0.5 rounded',
        'text-[10px] font-mono-tabular text-[color:var(--text-3)]',
        'hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)]',
        'transition-colors',
        'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
        className,
      )}
    >
      <svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
        <circle cx="12" cy="12" r="10" />
        <path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3" />
        <line x1="12" y1="17" x2="12.01" y2="17" />
      </svg>
      <span>{label}</span>
    </a>
  );
}
