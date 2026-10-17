import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Copy, Pencil, Plus, Trash2, Upload } from 'lucide-react';
import {
  createExtension,
  deleteExtension,
  deleteExtensionFile,
  extensionsQueryKey,
  listExtensions,
  updateExtension,
  uploadExtensionFile,
} from '$/api/extensions';
import type { Extension } from '$/api/types';
import { usePageTitle } from '$/lib/usePageTitle';
import { formatBytes } from '$/lib/time';
import { buttonClasses } from '$/components/atoms/Button';
import { ModalShell } from '$/components/feedback/ModalShell';
import { EmptyState } from '$/components/data/EmptyState';
import { MetadataBadge } from '$/components/data/MetadataBadge';
import { SkeletonRow } from '$/components/data/Skeleton';

const MAX_FILE_BYTES = 64 * 1024 * 1024;
const ASSIGNED_TIP = 'Remove it from all environments and hosts first';

// Platform/arch pairs the server accepts for extension binaries.
const SLOTS: ReadonlyArray<[platform: string, arch: string]> = [
  ['darwin', 'amd64'],
  ['darwin', 'arm64'],
  ['darwin', 'universal'],
  ['linux', 'amd64'],
  ['linux', 'arm64'],
  ['windows', 'amd64'],
];

const inputClass =
  'w-full h-8 px-2.5 text-sm rounded-md bg-[color:var(--bg-1)] text-[color:var(--text-1)] ' +
  'border border-[color:var(--border-strong)] outline-none focus:border-[color:var(--accent)]';

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export function ExtensionsPage() {
  const { t } = useTranslation();
  usePageTitle(t('pageTitle.extensions'));
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const [uploading, setUploading] = useState<string | null>(null);
  const [editor, setEditor] = useState<{ ext?: Extension } | null>(null);

  const { data, isLoading, error: loadError } = useQuery({
    queryKey: extensionsQueryKey,
    queryFn: listExtensions,
  });

  const refresh = () => qc.invalidateQueries({ queryKey: extensionsQueryKey });
  const onError = (e: unknown) => setError(errMsg(e));

  const removeExt = useMutation({
    mutationFn: (id: number) => deleteExtension(id),
    onSuccess: () => {
      setError(null);
      void refresh();
    },
    onError,
  });
  const removeFile = useMutation({
    mutationFn: (v: { id: number; platform: string; arch: string }) =>
      deleteExtensionFile(v.id, v.platform, v.arch),
    onSuccess: () => {
      setError(null);
      void refresh();
    },
    onError,
  });
  const upload = useMutation({
    mutationFn: (v: { id: number; platform: string; arch: string; file: File }) =>
      uploadExtensionFile(v.id, v.platform, v.arch, v.file),
    onSuccess: () => {
      setError(null);
      void refresh();
    },
    onError,
    onSettled: () => setUploading(null),
  });

  function pickFile(ext: Extension, platform: string, arch: string, file: File | undefined) {
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) {
      setError('Files can be at most 64 MB.');
      return;
    }
    setError(null);
    setUploading(`${ext.id}/${platform}/${arch}`);
    upload.mutate({ id: ext.id, platform, arch, file });
  }

  const rows = data ?? [];

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)] mr-2">
          {t('pageTitle.extensions')}
        </h1>
        <p className="text-xs text-[color:var(--text-3)] flex-1">
          osquery extension library. Upload one binary per platform, then assign it to environments
          or hosts.
        </p>
        <button
          type="button"
          className={buttonClasses({ size: 'md' })}
          onClick={() => setEditor({})}
        >
          <Plus size={14} /> New extension
        </button>
      </div>

      {(error || loadError) && (
        <div
          role="alert"
          className="mx-4 mt-3 px-3 py-2 text-sm rounded-md border border-[color:var(--danger)]/30 bg-[color:var(--danger)]/10 text-[color:var(--danger)]"
        >
          {error ?? errMsg(loadError)}
        </div>
      )}

      <div className="flex-1 overflow-auto min-h-0">
        {isLoading ? (
          <table className="w-full">
            <tbody>
              <SkeletonRow cells={5} />
              <SkeletonRow cells={5} />
            </tbody>
          </table>
        ) : rows.length === 0 && !loadError ? (
          <EmptyState title="No extensions yet." description="Create one to start uploading binaries." />
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-[color:var(--text-3)] border-b border-[color:var(--border)]">
                <th className="px-4 py-2 font-medium">Name</th>
                <th className="px-4 py-2 font-medium">Version</th>
                <th className="px-4 py-2 font-medium">Files</th>
                <th className="px-4 py-2 font-medium">Assigned to</th>
                <th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody>
              {rows.map((ext) => {
                const assigned = ext.environments > 0 || ext.nodes > 0;
                return (
                  <tr key={ext.id} className="align-top border-b border-[color:var(--border)]">
                    <td className="px-4 py-3">
                      <div className="font-semibold text-[color:var(--text-1)]">{ext.name}</div>
                      {ext.description && (
                        <div className="text-xs text-[color:var(--text-3)]">{ext.description}</div>
                      )}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className="tabular-nums">{ext.version}</span>{' '}
                      {ext.command_execution && <MetadataBadge>Command execution</MetadataBadge>}
                    </td>
                    <td className="px-4 py-3">
                      <ul className="space-y-1">
                        {SLOTS.map(([platform, arch]) => {
                          const f = ext.files?.find((x) => x.platform === platform && x.arch === arch);
                          const key = `${ext.id}/${platform}/${arch}`;
                          const slot = `${platform}/${arch}`;
                          return (
                            <li key={slot} className="flex items-center gap-2 text-xs">
                              <span className="w-32 text-[color:var(--text-2)]">{slot}</span>
                              {f ? (
                                <>
                                  <span className="tabular-nums">{formatBytes(f.size)}</span>
                                  <code className="text-[color:var(--text-3)]" title={f.sha256}>
                                    {f.sha256.slice(0, 8)}
                                  </code>
                                  <button
                                    type="button"
                                    aria-label={`Copy SHA-256 of ${slot} for ${ext.name}`}
                                    title="Copy SHA-256"
                                    className="text-[color:var(--text-3)] hover:text-[color:var(--text-1)]"
                                    onClick={() => void navigator.clipboard?.writeText(f.sha256)}
                                  >
                                    <Copy size={12} />
                                  </button>
                                </>
                              ) : (
                                <span className="text-[color:var(--text-3)]">no file</span>
                              )}
                              {uploading === key ? (
                                <span className="text-[color:var(--text-3)]">Uploading…</span>
                              ) : (
                                <label
                                  className={buttonClasses({ variant: 'ghost', size: 'sm', className: 'cursor-pointer' })}
                                >
                                  <Upload size={12} /> {f ? 'Replace' : 'Upload'}
                                  <input
                                    type="file"
                                    className="sr-only"
                                    aria-label={`Upload ${slot} for ${ext.name}`}
                                    onChange={(e) => {
                                      pickFile(ext, platform, arch, e.target.files?.[0]);
                                      e.target.value = '';
                                    }}
                                  />
                                </label>
                              )}
                              {f && (
                                <button
                                  type="button"
                                  aria-label={`Delete ${slot} file of ${ext.name}`}
                                  className={buttonClasses({ variant: 'danger', size: 'sm' })}
                                  onClick={() => {
                                    if (window.confirm(`Delete the ${slot} file of ${ext.name}?`)) {
                                      removeFile.mutate({ id: ext.id, platform, arch });
                                    }
                                  }}
                                >
                                  <Trash2 size={12} />
                                </button>
                              )}
                            </li>
                          );
                        })}
                      </ul>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-[color:var(--text-2)]">
                      {ext.environments} {ext.environments === 1 ? 'environment' : 'environments'}
                      {', '}
                      {ext.nodes} {ext.nodes === 1 ? 'host' : 'hosts'}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-right">
                      <div className="inline-flex gap-2">
                        <button
                          type="button"
                          aria-label={`Edit ${ext.name}`}
                          className={buttonClasses({ variant: 'ghost', size: 'sm' })}
                          onClick={() => setEditor({ ext })}
                        >
                          <Pencil size={12} />
                        </button>
                        {/* A disabled button swallows hover, so the tooltip lives on the wrapper. */}
                        <span title={assigned ? ASSIGNED_TIP : undefined}>
                          <button
                            type="button"
                            aria-label={`Delete ${ext.name}`}
                            disabled={assigned}
                            className={buttonClasses({ variant: 'danger', size: 'sm' })}
                            onClick={() => {
                              if (window.confirm(`Delete extension ${ext.name}?`)) {
                                removeExt.mutate(ext.id);
                              }
                            }}
                          >
                            <Trash2 size={12} />
                          </button>
                        </span>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {editor && (
        <ExtensionDialog
          ext={editor.ext}
          onClose={() => setEditor(null)}
          onSaved={() => {
            setEditor(null);
            void refresh();
          }}
        />
      )}
    </div>
  );
}

function ExtensionDialog({
  ext,
  onClose,
  onSaved,
}: {
  ext?: Extension;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState(ext?.name ?? '');
  const [description, setDescription] = useState(ext?.description ?? '');
  const [version, setVersion] = useState(ext?.version ?? '');
  const [exec, setExec] = useState(ext?.command_execution ?? false);
  const [error, setError] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: () =>
      ext
        ? updateExtension(ext.id, { description, version, command_execution: exec })
        : createExtension({ name, description, version, command_execution: exec }),
    onSuccess: onSaved,
    onError: (e) => setError(errMsg(e)),
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    save.mutate();
  }

  const label = 'block text-xs font-semibold text-[color:var(--text-2)] mb-1';
  return (
    <ModalShell
      title={ext ? `Edit ${ext.name}` : 'New extension'}
      titleId="extension-editor-title"
      onClose={onClose}
      panelClassName="max-w-lg"
    >
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label htmlFor="ext-name" className={label}>Name</label>
          <input
            id="ext-name"
            className={inputClass}
            value={name}
            disabled={!!ext}
            required
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <div>
          <label htmlFor="ext-desc" className={label}>Description</label>
          <input id="ext-desc" className={inputClass} value={description} onChange={(e) => setDescription(e.target.value)} />
        </div>
        <div>
          <label htmlFor="ext-version" className={label}>Version</label>
          <input id="ext-version" className={inputClass} value={version} onChange={(e) => setVersion(e.target.value)} />
        </div>
        <label className="flex items-center gap-2 text-sm text-[color:var(--text-1)]">
          <input
            type="checkbox"
            checked={exec}
            onChange={(e) => setExec(e.target.checked)}
            className="accent-[color:var(--signal)]"
          />
          Can execute commands
        </label>
        {error && (
          <p role="alert" className="text-sm text-[color:var(--danger)]">
            {error}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" className={buttonClasses({ variant: 'ghost' })} onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className={buttonClasses()} disabled={save.isPending}>
            {ext ? 'Save' : 'Create'}
          </button>
        </div>
      </form>
    </ModalShell>
  );
}
