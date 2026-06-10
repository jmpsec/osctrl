import { useState, useEffect, type ReactNode } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useQuery, useMutation } from '@tanstack/react-query';
import {
  getMe,
  patchMe,
  changeMyPassword,
  refreshUserToken,
  deleteUserToken,
} from '$/api/users';
import { AuthError, ApiError, primeCsrfFromCookie } from '$/api/client';
import { cn } from '$/lib/cn';
import { formatRelative } from '$/lib/time';
import { toggleTheme, getInitialTheme } from '$/lib/theme';
import type { Theme } from '$/lib/design-tokens';
import { Button } from '$/components/atoms/Button';
import { Input } from '$/components/atoms/Input';
import { Label } from '$/components/atoms/Label';
import { Skeleton } from '$/components/data/Skeleton';

export function ProfilePage() {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [fullname, setFullname] = useState('');
  const [profileErr, setProfileErr] = useState<string | null>(null);
  const [profileOK, setProfileOK] = useState<string | null>(null);

  const [currentPwd, setCurrentPwd] = useState('');
  const [newPwd, setNewPwd] = useState('');
  const [confirmPwd, setConfirmPwd] = useState('');
  const [pwdErr, setPwdErr] = useState<string | null>(null);
  const [pwdOK, setPwdOK] = useState<string | null>(null);

  const [tokenMsg, setTokenMsg] = useState<string | null>(null);
  const [tokenErr, setTokenErr] = useState<string | null>(null);

  const [theme, setTheme] = useState<Theme>(() => {
    const fromDom = document.documentElement.getAttribute('data-theme') as Theme | null;
    return fromDom === 'light' || fromDom === 'dark' ? fromDom : getInitialTheme();
  });

  function handleThemeSwitch(t: Theme) {
    if (t === theme) return;
    toggleTheme();
    setTheme(t);
  }

  const { data: me, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['me'],
    queryFn: () => getMe(),
    staleTime: 60_000,
  });

  // Hydrate the form when the profile loads.
  useEffect(() => {
    if (me) {
      setEmail(me.email);
      setFullname(me.fullname);
    }
  }, [me]);

  if (isError && error instanceof AuthError) {
    void navigate({ to: '/login' });
    return null;
  }

  const profileMutation = useMutation({
    mutationFn: () => patchMe({ email: email.trim(), fullname: fullname.trim() }),
    onSuccess: () => {
      setProfileErr(null);
      setProfileOK('Profile updated.');
      void refetch();
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      setProfileOK(null);
      setProfileErr(e instanceof Error ? e.message : 'Update failed');
    },
  });

  const passwordMutation = useMutation({
    mutationFn: () => {
      if (newPwd !== confirmPwd) throw new Error('New passwords do not match.');
      if (newPwd.length < 8) throw new Error('New password must be at least 8 characters.');
      return changeMyPassword({ current_password: currentPwd, new_password: newPwd });
    },
    onSuccess: () => {
      setPwdErr(null);
      setPwdOK('Password changed. Use the new password on next login.');
      setCurrentPwd('');
      setNewPwd('');
      setConfirmPwd('');
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      if (e instanceof ApiError && e.status === 403) {
        setPwdErr('Current password is incorrect.');
        return;
      }
      setPwdOK(null);
      setPwdErr(e instanceof Error ? e.message : 'Password change failed');
    },
  });

  const rotateMutation = useMutation({
    mutationFn: () => {
      if (!me) throw new Error('Profile not loaded yet.');
      return refreshUserToken(me.username);
    },
    onSuccess: () => {
      // Self-rotate: the API just re-issued osctrl_token + osctrl_csrf
      // cookies with the freshly minted JWT. Re-prime the in-memory
      // CSRF from the new cookie so subsequent X-CSRF-Token headers
      // carry the rotated value — otherwise the next mutation
      // (e.g. revoke or password change) sends a stale CSRF and the
      // server rejects it.
      primeCsrfFromCookie();
      setTokenErr(null);
      setTokenMsg('Token rotated. Store it now — it will not be shown again.');
      void refetch();
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      setTokenMsg(null);
      setTokenErr(e instanceof Error ? e.message : 'Rotation failed');
    },
  });

  const revokeMutation = useMutation({
    mutationFn: () => {
      if (!me) throw new Error('Profile not loaded yet.');
      return deleteUserToken(me.username);
    },
    onSuccess: () => {
      setTokenErr(null);
      setTokenMsg('Token revoked. A new one will be issued on next login.');
      void refetch();
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      setTokenMsg(null);
      setTokenErr(e instanceof Error ? e.message : 'Revoke failed');
    },
  });

  // Derived display bits for the hero strip.
  const initials = me ? deriveInitials(me.fullname || me.username) : '';

  return (
    <div className="flex flex-col h-full min-h-0 overflow-auto">
      {/* ── Page header ──
          Slim two-line: kicker + h1. The previous subtitle restated
          what the four cards below already say (account · password ·
          token · theme) so it's redundant; the kicker plus the cards'
          own titles carry the same information without the noise. */}
      <div className="px-6 py-4 border-b border-[color:var(--border)]">
        <div className="text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)] mb-0.5 select-none">
          account · profile
        </div>
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)]">
          Your profile
        </h1>
      </div>

      {/* ── Hero strip ──────────────────────────────────────────────────── */}
      <div className="px-6 pt-6">
        {isLoading || !me ? (
          <div
            className={cn(
              'flex items-center gap-4 flex-wrap p-4',
              'rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)]',
            )}
          >
            <Skeleton className="h-10 w-10 rounded-full" />
            <Skeleton className="h-4 w-40" />
            <Skeleton className="h-4 w-24" />
            <Skeleton className="h-4 w-32" />
          </div>
        ) : (
          <div
            className={cn(
              'flex items-center gap-4 flex-wrap p-4',
              'rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)]',
            )}
          >
            {/* Avatar glyph */}
            <div
              aria-hidden
              className={cn(
                'flex-shrink-0 flex items-center justify-center',
                'w-10 h-10 rounded-full',
                'bg-[rgba(var(--signal-r),var(--signal-g),var(--signal-b),0.14)]',
                'text-[color:var(--signal)] font-display font-semibold text-sm tracking-wide',
              )}
            >
              {initials}
            </div>

            {/* Identity */}
            <div className="flex items-center gap-2 flex-wrap min-w-0">
              <span className="font-mono-tabular text-sm font-medium text-[color:var(--text-1)] truncate">
                {me.username}
              </span>
              {me.fullname && (
                <>
                  <span className="text-[color:var(--text-3)]">—</span>
                  <span className="text-sm text-[color:var(--text-2)] truncate">
                    {me.fullname}
                  </span>
                </>
              )}
              <RoleBadge admin={me.admin} service={me.service} />
            </div>

            {/* Spacer */}
            <div className="flex-1 min-w-0" />

            {/* Last access — Token expires used to live here too but it's
                already shown inside the API token card below; duplicating
                it in the hero was visual noise. */}
            <div className="flex items-center gap-6 flex-wrap">
              <div>
                <div className="text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)] mb-0.5">
                  Last access
                </div>
                <div
                  className="text-xs tnum text-[color:var(--text-1)]"
                  title={me.last_access}
                >
                  {formatRelative(me.last_access)}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── Body ──
          Four focused cards in a responsive 2-col grid. The previous
          single "Security" mega-card stacked password / token / theme
          / role under one heading, which forced operators to mentally
          parse hairlines as section dividers. One card per job balances
          the page and matches the brand kit's "cards differentiate by
          border + faint bg shift" guidance. Role used to be tacked at
          the bottom of Security too — the hero badge already shows it,
          so it's gone from here. */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 p-6">
        {/* ─ Account ─ */}
        {isLoading || !me ? (
          <Panel id="profile-section-title" title="Account">
            <div className="space-y-4">
              <Skeleton className="h-9 w-full" />
              <Skeleton className="h-9 w-full" />
              <Skeleton className="h-8 w-32" />
            </div>
          </Panel>
        ) : (
          <Panel id="profile-section-title" title="Account">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                profileMutation.mutate();
              }}
              className="space-y-4"
              aria-labelledby="profile-section-title"
            >
              <div>
                <FieldLabel htmlFor="profile-email">Email</FieldLabel>
                <Input
                  id="profile-email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  autoComplete="email"
                />
              </div>
              <div>
                <FieldLabel htmlFor="profile-fullname">Full name</FieldLabel>
                <Input
                  id="profile-fullname"
                  type="text"
                  value={fullname}
                  onChange={(e) => setFullname(e.target.value)}
                  autoComplete="name"
                />
              </div>

              {profileErr && <Feedback kind="error" message={profileErr} />}
              {profileOK && <Feedback kind="success" message={profileOK} />}

              <div className="pt-1">
                <Button
                  type="submit"
                  variant="primary"
                  size="sm"
                  disabled={profileMutation.isPending}
                >
                  {profileMutation.isPending ? 'Saving…' : 'Save changes'}
                </Button>
              </div>
            </form>
          </Panel>
        )}

        {/* ─ Password ─ */}
        {isLoading || !me ? (
          <Panel title="Password">
            <div className="space-y-4">
              <Skeleton className="h-9 w-full" />
              <Skeleton className="h-9 w-full" />
              <Skeleton className="h-9 w-full" />
              <Skeleton className="h-8 w-32" />
            </div>
          </Panel>
        ) : (
          <Panel title="Password">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                passwordMutation.mutate();
              }}
              className="space-y-4"
              aria-label="Change password"
            >
              <div>
                <FieldLabel htmlFor="pwd-current">Current password</FieldLabel>
                <Input
                  id="pwd-current"
                  type="password"
                  value={currentPwd}
                  onChange={(e) => setCurrentPwd(e.target.value)}
                  autoComplete="current-password"
                />
              </div>
              <div>
                <FieldLabel htmlFor="pwd-new">New password</FieldLabel>
                <Input
                  id="pwd-new"
                  type="password"
                  value={newPwd}
                  onChange={(e) => setNewPwd(e.target.value)}
                  autoComplete="new-password"
                  minLength={8}
                />
                <p className="mt-1 text-[10px] text-[color:var(--text-3)]">
                  Minimum 8 characters.
                </p>
              </div>
              <div>
                <FieldLabel htmlFor="pwd-confirm">Confirm new password</FieldLabel>
                <Input
                  id="pwd-confirm"
                  type="password"
                  value={confirmPwd}
                  onChange={(e) => setConfirmPwd(e.target.value)}
                  autoComplete="new-password"
                  minLength={8}
                />
              </div>

              {pwdErr && <Feedback kind="error" message={pwdErr} />}
              {pwdOK && <Feedback kind="success" message={pwdOK} />}

              <div className="pt-1">
                <Button
                  type="submit"
                  variant="primary"
                  size="sm"
                  disabled={passwordMutation.isPending}
                >
                  {passwordMutation.isPending ? 'Changing…' : 'Change password'}
                </Button>
              </div>
            </form>
          </Panel>
        )}

        {/* ─ API token ─ */}
        {isLoading || !me ? (
          <Panel title="API token">
            <div className="space-y-3">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-8 w-40" />
            </div>
          </Panel>
        ) : (
          <Panel title="API token">
            <div className="space-y-3">
              <div
                className={cn(
                  'flex items-center justify-between gap-3 px-3 py-2',
                  'rounded-md border border-[color:var(--border)] bg-[color:var(--bg-2)]',
                )}
              >
                <span
                  className="font-mono-tabular text-xs text-[color:var(--text-2)] tracking-wider truncate"
                  aria-label="Token (masked)"
                >
                  ········••••
                </span>
                <span
                  className="text-[10px] font-mono-tabular text-[color:var(--text-3)] tnum whitespace-nowrap"
                  title={me.token_expire}
                >
                  expires {formatRelative(me.token_expire)}
                </span>
              </div>

              <p className="text-[10px] text-[color:var(--text-3)] leading-relaxed">
                The raw token is never displayed after issuance. Rotate to mint a
                new one — the previous token will stop working immediately.
              </p>

              {tokenErr && <Feedback kind="error" message={tokenErr} />}
              {tokenMsg && <Feedback kind="success" message={tokenMsg} />}

              <div className="flex items-center gap-2 flex-wrap">
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  disabled={rotateMutation.isPending || revokeMutation.isPending}
                  onClick={() => rotateMutation.mutate()}
                >
                  {rotateMutation.isPending ? 'Rotating…' : 'Rotate token'}
                </Button>
                <Button
                  type="button"
                  variant="danger"
                  size="sm"
                  disabled={revokeMutation.isPending || rotateMutation.isPending}
                  onClick={() => revokeMutation.mutate()}
                >
                  {revokeMutation.isPending ? 'Revoking…' : 'Revoke'}
                </Button>
              </div>
            </div>
          </Panel>
        )}

        {/* ─ Preferences ─ */}
        {isLoading || !me ? (
          <Panel title="Preferences">
            <Skeleton className="h-10 w-full" />
          </Panel>
        ) : (
          <Panel title="Preferences">
            <div className="flex items-center justify-between gap-3">
              <div>
                <div className="text-xs text-[color:var(--text-1)] font-medium">
                  Color theme
                </div>
                <div className="text-[10px] text-[color:var(--text-3)]">
                  Persists across reloads.
                </div>
              </div>

              <div
                role="group"
                aria-label="Toggle color theme"
                className={cn(
                  'flex items-center gap-0.5 p-1 rounded-full',
                  'bg-[color:var(--bg-2)] border border-[color:var(--border)]',
                )}
              >
                {(['dark', 'light'] as const).map((t) => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => handleThemeSwitch(t)}
                    aria-pressed={theme === t}
                    className={cn(
                      'px-2.5 py-1 rounded-full text-[11px] font-medium font-mono-tabular uppercase tracking-[0.04em]',
                      'transition-colors duration-[120ms] ease-out',
                      'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[color:var(--signal)]',
                      theme === t
                        ? 'bg-[color:var(--bg-3)] text-[color:var(--text-1)]'
                        : 'text-[color:var(--text-2)] hover:text-[color:var(--text-1)]',
                    )}
                  >
                    {t.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>
          </Panel>
        )}
      </div>
    </div>
  );
}

export default ProfilePage;

// ---------------------------------------------------------------------------
// Inline sub-components
// ---------------------------------------------------------------------------

function FieldLabel({
  htmlFor,
  children,
}: {
  htmlFor: string;
  children: ReactNode;
}) {
  return (
    <Label
      htmlFor={htmlFor}
      className="text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)] mb-1.5"
    >
      {children}
    </Label>
  );
}

function Feedback({
  kind,
  message,
}: {
  kind: 'error' | 'success';
  message: string;
}) {
  if (kind === 'error') {
    return (
      <p
        role="alert"
        className={cn(
          'text-xs text-[color:var(--danger)] px-3 py-2 rounded-md',
          'bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.08)]',
          'border border-[color:var(--danger)]/20',
        )}
      >
        {message}
      </p>
    );
  }
  return (
    <p
      role="status"
      className={cn(
        'text-xs text-[color:var(--success)] px-3 py-2 rounded-md',
        'bg-[rgba(var(--success-r),var(--success-g),var(--success-b),0.08)]',
        'border border-[color:var(--success)]/20',
      )}
    >
      {message}
    </p>
  );
}

function Panel({
  id,
  title,
  children,
}: {
  id?: string;
  title: string;
  children: ReactNode;
}) {
  return (
    <section
      className={cn(
        'rounded-lg border border-[color:var(--border)] bg-[color:var(--bg-1)] overflow-hidden',
      )}
      aria-labelledby={id}
    >
      <header
        className={cn(
          'px-4 py-3 border-b border-[color:var(--border)]',
          'bg-[color:var(--bg-2)]',
        )}
      >
        <h2
          id={id}
          className="font-display text-[13px] font-semibold text-[color:var(--text-1)]"
        >
          {title}
        </h2>
      </header>
      <div className="p-4">{children}</div>
    </section>
  );
}

function RoleBadge({ admin, service }: { admin: boolean; service: boolean }) {
  if (admin) {
    return (
      <span
        className={cn(
          'px-2 py-0.5 rounded-full text-[10px] font-medium font-mono-tabular uppercase tracking-[0.06em]',
          'bg-[rgba(var(--signal-r),var(--signal-g),var(--signal-b),0.12)] text-[color:var(--signal)]',
          'border border-[color:var(--signal)]/30',
        )}
      >
        super-admin
      </span>
    );
  }
  if (service) {
    return (
      <span
        className={cn(
          'px-2 py-0.5 rounded-full text-[10px] font-medium font-mono-tabular uppercase tracking-[0.06em]',
          'bg-[rgba(var(--info-r),var(--info-g),var(--info-b),0.12)] text-[color:var(--info)]',
          'border border-[color:var(--info)]/30',
        )}
      >
        service
      </span>
    );
  }
  return (
    <span
      className={cn(
        'px-2 py-0.5 rounded-full text-[10px] font-medium font-mono-tabular uppercase tracking-[0.06em]',
        'bg-[color:var(--bg-3)] text-[color:var(--text-2)]',
        'border border-[color:var(--border)]',
      )}
    >
      operator
    </span>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function deriveInitials(source: string): string {
  const trimmed = source.trim();
  if (!trimmed) return '?';
  const parts = trimmed.split(/\s+/).filter(Boolean);
  if (parts.length === 1) {
    const p = parts[0]!;
    return p.length >= 2 ? p.slice(0, 2).toUpperCase() : p[0]!.toUpperCase();
  }
  return (parts[0]![0]! + parts[parts.length - 1]![0]!).toUpperCase();
}
