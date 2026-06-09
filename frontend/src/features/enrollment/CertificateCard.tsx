import { useRef, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getEnrollData, uploadCertificate } from '$/api/enrollment';
import { ApiError } from '$/api/client';
import { Button } from '$/components/atoms/Button';
import { Skeleton } from '$/components/data/Skeleton';
import { cn } from '$/lib/cn';

/**
 * CertificateCard — view, copy, download, and replace the env's enrollment
 * certificate. Slots into the EnrollPage right rail beside the two
 * LifecycleCards. The card always displays a short fingerprint preview
 * (first + last PEM lines) so operators can sanity-check at a glance
 * without copy/pasting the whole thing.
 *
 * Upload path: paste full PEM into the textarea, click Upload. The API
 * does the PEM + x509 validation server-side — we surface its rejection
 * verbatim under the textarea on 400, and re-fetch the cert on 200.
 *
 * Notes on layout: matches the LifecycleCard chrome exactly (rounded-xl,
 * border, p-4, h2 heading) so the rail stays visually coherent.
 */
export function CertificateCard({ env }: { env: string }) {
  const qc = useQueryClient();
  const [paste, setPaste] = useState('');
  const [feedback, setFeedback] = useState<{ kind: 'success' | 'error'; msg: string } | null>(
    null,
  );
  const [copied, setCopied] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const certQuery = useQuery({
    queryKey: ['enrollment', env, 'cert'],
    queryFn: () => getEnrollData(env, 'cert'),
    staleTime: 60_000,
  });

  const uploadMut = useMutation({
    mutationFn: (pem: string) => uploadCertificate(env, pem),
    onSuccess: (res) => {
      setFeedback({ kind: 'success', msg: res.message });
      setPaste('');
      void qc.invalidateQueries({ queryKey: ['enrollment', env, 'cert'] });
    },
    onError: (err) =>
      setFeedback({
        kind: 'error',
        msg: err instanceof ApiError ? err.message : 'Upload failed',
      }),
  });

  function handleUpload() {
    const trimmed = paste.trim();
    if (!trimmed) {
      setFeedback({ kind: 'error', msg: 'Empty certificate' });
      return;
    }
    setFeedback(null);
    uploadMut.mutate(trimmed);
  }

  async function handleFile(file: File) {
    try {
      const text = await file.text();
      setPaste(text);
      setFeedback(null);
    } catch {
      setFeedback({ kind: 'error', msg: 'Could not read file' });
    }
  }

  async function handleCopy() {
    if (!certQuery.data?.data) return;
    try {
      await navigator.clipboard.writeText(certQuery.data.data);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setFeedback({ kind: 'error', msg: 'Clipboard blocked by browser' });
    }
  }

  function handleDownload() {
    if (!certQuery.data?.data) return;
    const blob = new Blob([certQuery.data.data], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `osctrl-${env}.crt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // Build a one-glance preview: first PEM line + last 60 chars of body.
  const preview = (() => {
    const pem = certQuery.data?.data ?? '';
    if (!pem) return null;
    const lines = pem.trim().split('\n');
    if (lines.length < 3) return pem;
    const body = lines.slice(1, -1).join('');
    const tail = body.slice(-60);
    return `${lines[0]}\n…${tail}\n${lines[lines.length - 1]}`;
  })();

  return (
    <section
      className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] p-4"
      aria-label="Enrollment certificate"
    >
      <div className="mb-3 flex items-center justify-between gap-2">
        <h2 className="text-[12px] font-display font-semibold text-[color:var(--text-1)]">
          Certificate
        </h2>
        <span
          className="text-[10px] text-[color:var(--text-3)] cursor-help"
          title="The PEM-encoded TLS certificate agents pin to when they enroll. Replace this when rotating CAs or after a compromise."
        >
          ⓘ
        </span>
      </div>

      {/* Preview */}
      <pre
        className={cn(
          'text-[10px] font-mono-tabular',
          'bg-[color:var(--bg-2)] border border-[color:var(--border)] rounded-md',
          'p-2 min-h-[60px] overflow-hidden whitespace-pre-wrap break-all',
          'text-[color:var(--text-2)]',
        )}
      >
        {certQuery.isLoading ? (
          <Skeleton className="h-4 w-full" />
        ) : certQuery.isError ? (
          <span className="text-[color:var(--danger)]">
            {(certQuery.error as Error | undefined)?.message ?? 'Failed to load'}
          </span>
        ) : (
          preview ?? <span className="text-[color:var(--text-3)]">No certificate set</span>
        )}
      </pre>

      <div className="mt-2 flex items-center gap-1.5">
        <Button
          variant="ghost"
          size="sm"
          onClick={handleCopy}
          disabled={!certQuery.data?.data}
        >
          {copied ? 'Copied ✓' : 'Copy'}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          onClick={handleDownload}
          disabled={!certQuery.data?.data}
        >
          Download
        </Button>
      </div>

      {/* Replace */}
      <div className="mt-4 pt-3 border-t border-[color:var(--border)]">
        <div className="mb-2 flex items-center justify-between">
          <span className="text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)]">
            Replace certificate
          </span>
          <input
            ref={fileInputRef}
            type="file"
            accept=".crt,.pem,.cer,application/x-pem-file"
            className="hidden"
            onChange={(ev) => {
              const f = ev.target.files?.[0];
              if (f) void handleFile(f);
              ev.target.value = '';
            }}
          />
          <Button
            variant="ghost"
            size="sm"
            onClick={() => fileInputRef.current?.click()}
          >
            Pick file…
          </Button>
        </div>
        <textarea
          value={paste}
          onChange={(ev) => {
            setPaste(ev.target.value);
            setFeedback(null);
          }}
          placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
          className={cn(
            'w-full px-2.5 py-2 rounded-md text-[10px] font-mono-tabular',
            'bg-[color:var(--bg-2)] border border-[color:var(--border)]',
            'text-[color:var(--text-1)] placeholder:text-[color:var(--text-3)]',
            'focus:outline-none focus:ring-2 focus:ring-[color:var(--signal)] focus:border-transparent',
            'min-h-[80px] resize-y',
          )}
          spellCheck={false}
        />
        {feedback && (
          <p
            className={cn(
              'mt-1.5 text-[10px]',
              feedback.kind === 'success'
                ? 'text-[color:var(--success)]'
                : 'text-[color:var(--danger)]',
            )}
          >
            {feedback.msg}
          </p>
        )}
        <div className="mt-2 flex justify-end">
          <Button
            variant="primary"
            size="sm"
            onClick={handleUpload}
            disabled={uploadMut.isPending || !paste.trim()}
          >
            {uploadMut.isPending ? 'Uploading…' : 'Upload'}
          </Button>
        </div>
      </div>
    </section>
  );
}
