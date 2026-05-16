/**
 * CodeEditor — Monaco wrapper, lazy-loaded so the Monaco chunk (~3 MB) only
 * loads on pages that use it. The initial bundle stays small.
 *
 * Props:
 *   value       - current editor content
 *   onChange    - called on every edit
 *   language    - Monaco language id (default: 'sql')
 *   height      - CSS height string (default: '240px')
 *   readOnly    - if true the editor is not editable
 */
import { lazy, Suspense } from 'react';
import { cn } from '$/lib/cn';

// Lazy-load the Monaco wrapper so the 3 MB chunk is never included in the
// initial bundle. Vite automatically code-splits at the dynamic import boundary.
const MonacoEditor = lazy(() =>
  import('@monaco-editor/react').then((m) => ({ default: m.Editor })),
);

interface CodeEditorProps {
  value: string;
  onChange?: (value: string) => void;
  language?: string;
  height?: string;
  readOnly?: boolean;
  className?: string;
  /** ID of an external <label> describing the editor for assistive tech. */
  'aria-labelledby'?: string;
  /** Direct accessibility label, used when no external label exists. */
  'aria-label'?: string;
}

export function CodeEditor({
  value,
  onChange,
  language = 'sql',
  height = '240px',
  readOnly = false,
  className,
  'aria-labelledby': ariaLabelledBy,
  'aria-label': ariaLabel,
}: CodeEditorProps) {
  // Detect current theme by reading the data-theme attribute on <html>.
  const isDark =
    typeof document !== 'undefined'
      ? document.documentElement.getAttribute('data-theme') !== 'light'
      : true;

  return (
    <div
      role="group"
      aria-labelledby={ariaLabelledBy}
      aria-label={ariaLabelledBy ? undefined : ariaLabel}
      className={cn(
        'rounded-md overflow-hidden border border-[color:var(--border)]',
        className,
      )}
      style={{ height }}
    >
      <Suspense
        fallback={
          <div
            className="flex items-center justify-center h-full bg-[color:var(--bg-2)] text-[color:var(--text-3)] text-xs"
            aria-label="Loading editor"
          >
            Loading editor…
          </div>
        }
      >
        <MonacoEditor
          height={height}
          language={language}
          value={value}
          theme={isDark ? 'vs-dark' : 'light'}
          options={{
            readOnly,
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            fontSize: 13,
            fontFamily: 'IBM Plex Mono, Menlo, Monaco, Consolas, monospace',
            lineNumbers: 'on',
            wordWrap: 'on',
            tabSize: 2,
            automaticLayout: true,
          }}
          onChange={(v) => {
            if (onChange && v !== undefined) onChange(v);
          }}
        />
      </Suspense>
    </div>
  );
}
