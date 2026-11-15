import { useTranslation } from 'react-i18next';
import { useMutation, useQuery } from '@tanstack/react-query';
import { ApiError } from '$/api/client';
import { decideSantaRequestByLink, getSantaRequest, type SantaDecision } from '$/api/santa';
import { DecisionForm } from './RequestsTab';
import { MONO, errorText } from './table';

/**
 * Where an approve or deny link from a notification lands. Opening the link
 * decides nothing: the approver, signed in, confirms here.
 */
export function DecideLinkPage({ env, requestId, approve, token }: { env: string; requestId: number; approve: boolean; token: string }) {
  const { t } = useTranslation();
  const complete = requestId > 0 && token !== '';
  const request = useQuery({
    queryKey: ['santa', env, 'requests', 'one', requestId],
    queryFn: () => getSantaRequest(env, requestId),
    enabled: complete,
    retry: false,
  });
  const decide = useMutation({ mutationFn: (body: SantaDecision) => decideSantaRequestByLink(env, token, body) });
  const r = decide.data ?? request.data;
  const gone = decide.error instanceof ApiError && decide.error.status === 410;
  const sub = 'text-xs text-[color:var(--text-3)] [overflow-wrap:anywhere]';

  return (
    <main className="mx-auto min-h-screen max-w-2xl space-y-4 bg-[color:var(--bg-0)] p-4 sm:p-8">
      <h1 className="text-lg font-semibold text-[color:var(--text-1)]">{t(approve ? 'santa.link.approveTitle' : 'santa.link.denyTitle')}</h1>
      {!complete || gone ? (
        <p role="alert" className="text-sm text-[color:var(--danger)]">{t('santa.link.invalid')}</p>
      ) : request.isError ? (
        <p role="alert" className="text-sm text-[color:var(--danger)]">{errorText(request.error)}</p>
      ) : (
        r && (
          <section className="space-y-3 rounded-lg border border-[color:var(--border)] bg-[color:var(--bg-1)] p-4">
            {/* File names, paths and the justification come from clients and users: React text only. */}
            <div className="text-sm">
              <div className="text-[color:var(--text-1)] [overflow-wrap:anywhere]">{r.file_name || r.file_sha256}</div>
              {r.file_path && <div className={sub}>{r.file_path}</div>}
              <div className={`${MONO} ${sub}`}>{r.file_sha256}</div>
              <div className={`${MONO} ${sub}`}>{r.machine_id}</div>
            </div>
            <div className="text-sm">
              <div className="text-[color:var(--text-1)]">{r.requester}</div>
              <div className={sub}>{r.justification}</div>
            </div>
            {r.status === 'pending' ? (
              <DecisionForm approve={approve} pending={decide.isPending} error={errorText(decide.error)} onSubmit={decide.mutate} />
            ) : (
              <p role="status" className="text-sm text-[color:var(--text-1)]">
                {t('santa.request.status')}: {t(`santa.request.statuses.${r.status}`)}
                {r.decided_by && ` (${r.decided_by})`}
              </p>
            )}
          </section>
        )
      )}
    </main>
  );
}
