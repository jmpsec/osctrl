/**
 * DiffView — minimal side-by-side line-level diff.
 *
 * Built in-tree (no `diff` npm dep) using a longest-common-subsequence walk
 * over arrays of lines. Output is two columns:
 *   left  — the BEFORE document, with deleted lines highlighted danger.
 *   right — the AFTER document, with added lines highlighted success.
 *
 * For the per-section Monaco patches in EnvConfigPage this is enough — the
 * config sections are small (tens to a few hundred lines) so the O(n*m) LCS
 * table is cheap. We do not aim for word-level diffs.
 */
import { useMemo } from 'react';
import { cn } from '$/lib/cn';

type Op = 'eq' | 'add' | 'del';

interface DiffOp {
  op: Op;
  left?: string;
  right?: string;
}

function diffLines(before: string, after: string): DiffOp[] {
  const a = before === '' ? [] : before.split('\n');
  const b = after === '' ? [] : after.split('\n');
  const m = a.length;
  const n = b.length;

  // LCS table (rows = before lines, cols = after lines).
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0));
  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      if (a[i] === b[j]) {
        dp[i][j] = dp[i + 1][j + 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
  }

  const out: DiffOp[] = [];
  let i = 0;
  let j = 0;
  while (i < m && j < n) {
    if (a[i] === b[j]) {
      out.push({ op: 'eq', left: a[i], right: b[j] });
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      out.push({ op: 'del', left: a[i] });
      i++;
    } else {
      out.push({ op: 'add', right: b[j] });
      j++;
    }
  }
  while (i < m) {
    out.push({ op: 'del', left: a[i] });
    i++;
  }
  while (j < n) {
    out.push({ op: 'add', right: b[j] });
    j++;
  }
  return out;
}

export interface DiffViewProps {
  before: string;
  after: string;
  /** Optional class on the outer wrapper. */
  className?: string;
  /** Pretty-print labels in the column headers. */
  leftLabel?: string;
  rightLabel?: string;
}

export function DiffView({
  before,
  after,
  className,
  leftLabel = 'Saved',
  rightLabel = 'Pending',
}: DiffViewProps) {
  const ops = useMemo(() => diffLines(before, after), [before, after]);

  const summary = useMemo(() => {
    let adds = 0;
    let dels = 0;
    for (const op of ops) {
      if (op.op === 'add') adds++;
      else if (op.op === 'del') dels++;
    }
    return { adds, dels };
  }, [ops]);

  if (summary.adds === 0 && summary.dels === 0) {
    return (
      <div
        className={cn(
          'text-xs text-[color:var(--text-3)] px-3 py-2 border border-[color:var(--border)] rounded-md bg-[color:var(--bg-2)]',
          className,
        )}
      >
        No changes.
      </div>
    );
  }

  return (
    <div
      className={cn(
        'border border-[color:var(--border)] rounded-md overflow-hidden bg-[color:var(--bg-2)]',
        className,
      )}
    >
      <div className="flex items-center justify-between px-3 py-1.5 text-[10px] font-mono-tabular uppercase tracking-wider bg-[color:var(--bg-0)] border-b border-[color:var(--border)] text-[color:var(--text-3)]">
        <span>
          {leftLabel} → {rightLabel}
        </span>
        <span>
          <span className="text-[color:var(--success)]">+{summary.adds}</span>{' '}
          <span className="text-[color:var(--danger)]">−{summary.dels}</span>
        </span>
      </div>
      <div className="overflow-x-auto max-h-[280px] overflow-y-auto">
        <table className="w-full text-xs font-mono-tabular border-collapse">
          <tbody>
            {ops.map((op, idx) => (
              <tr key={idx} className="align-top">
                <td
                  className={cn(
                    'w-1/2 px-3 py-0.5 whitespace-pre-wrap break-all border-r border-[color:var(--border)]',
                    op.op === 'del' &&
                      'bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.10)] text-[color:var(--danger)]',
                  )}
                >
                  {op.op === 'add' ? ' ' : (op.left ?? '')}
                </td>
                <td
                  className={cn(
                    'w-1/2 px-3 py-0.5 whitespace-pre-wrap break-all',
                    op.op === 'add' &&
                      'bg-[rgba(var(--success-r),var(--success-g),var(--success-b),0.10)] text-[color:var(--success)]',
                  )}
                >
                  {op.op === 'del' ? ' ' : (op.right ?? '')}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default DiffView;
