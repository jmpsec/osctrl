import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { cn } from '$/lib/cn';
import { Button } from '$/components/atoms/Button';
import { Input } from '$/components/atoms/Input';
import { Label } from '$/components/atoms/Label';
import { Skeleton } from '$/components/data/Skeleton';
import { formatRelative } from '$/lib/time';
import {
  getMFAStatus,
  beginTOTP,
  verifyTOTP,
  disableTOTP,
  regenerateRecoveryCodes,
  registerSecurityKey,
  deleteCredential,
  isWebAuthnAvailable,
  type MFATOTPSetup,
} from '$/api/mfa';

// A destructive change is confirmed by re-entering the account password, so a
// stolen session cannot quietly strip a factor. `action` names what the
// password will be spent on once submitted.
type Confirm =
  | { action: 'disable-totp' }
  | { action: 'regenerate' }
  | { action: 'delete-credential'; id: string; name: string };

export function MFAPanel() {
  const qc = useQueryClient();
  const [setup, setSetup] = useState<MFATOTPSetup | null>(null);
  const [code, setCode] = useState('');
  const [keyName, setKeyName] = useState('');
  const [registering, setRegistering] = useState(false);
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  const [password, setPassword] = useState('');
  // Recovery codes exist in plaintext exactly once, right after they are
  // generated. Keep them on screen until the user dismisses them.
  const [codes, setCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const { data: status, isLoading } = useQuery({
    queryKey: ['mfa-status'],
    queryFn: () => getMFAStatus(),
    staleTime: 30_000,
  });

  function refresh() {
    void qc.invalidateQueries({ queryKey: ['mfa-status'] });
  }

  function fail(err: unknown, fallback: string) {
    setError(err instanceof Error ? err.message : fallback);
  }

  const beginMutation = useMutation({
    mutationFn: () => beginTOTP(),
    onSuccess: (data) => {
      setError(null);
      setSetup(data);
    },
    onError: (err) => fail(err, 'Could not start enrollment'),
  });

  const verifyMutation = useMutation({
    mutationFn: () => verifyTOTP(code),
    onSuccess: (data) => {
      setError(null);
      setSetup(null);
      setCode('');
      setCodes(data.recovery_codes);
      refresh();
    },
    onError: (err) => fail(err, 'That code did not match'),
  });

  const confirmMutation = useMutation({
    mutationFn: async () => {
      if (!confirm) return null;
      if (confirm.action === 'disable-totp') {
        await disableTOTP(password);
        return null;
      }
      if (confirm.action === 'delete-credential') {
        await deleteCredential(confirm.id, password);
        return null;
      }
      const { recovery_codes } = await regenerateRecoveryCodes(password);
      return recovery_codes;
    },
    onSuccess: (newCodes) => {
      setError(null);
      setConfirm(null);
      setPassword('');
      if (newCodes) setCodes(newCodes);
      refresh();
    },
    onError: (err) => fail(err, 'Could not apply the change'),
  });

  async function onRegisterKey() {
    setError(null);
    setRegistering(true);
    try {
      await registerSecurityKey(keyName.trim() || 'Security key');
      setKeyName('');
      refresh();
    } catch (err) {
      fail(err, 'Could not register this authenticator');
    } finally {
      setRegistering(false);
    }
  }

  if (isLoading || !status) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-8 w-full" />
        <Skeleton className="h-8 w-2/3" />
      </div>
    );
  }

  const onlyFactor =
    status.required &&
    ((status.totp_enabled && status.credentials.length === 0) ||
      (!status.totp_enabled && status.credentials.length === 1));

  return (
    <div className="space-y-5">
      {error && (
        <p className="rounded-md border border-[color:var(--danger)]/30 bg-[color:var(--danger)]/10 px-3 py-2 text-xs text-[color:var(--danger)]">
          {error}
        </p>
      )}

      {status.required && (
        <p className="text-xs text-[color:var(--text-3)]">
          This deployment requires a second factor, so the last one on your account cannot be removed.
        </p>
      )}

      {/* ── Authenticator app ── */}
      <div className="space-y-2">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h3 className="text-xs font-semibold text-[color:var(--text-1)]">Authenticator app</h3>
            <p className="text-xs text-[color:var(--text-3)]">
              {status.totp_enabled ? 'Enabled' : 'Not set up — codes from Google Authenticator, 1Password, Aegis…'}
            </p>
          </div>
          {status.totp_enabled ? (
            <Button
              type="button"
              variant="danger"
              size="sm"
              disabled={onlyFactor}
              title={onlyFactor ? 'Register a security key before removing this factor' : undefined}
              onClick={() => {
                setConfirm({ action: 'disable-totp' });
                setError(null);
              }}
            >
              Remove
            </Button>
          ) : (
            <Button
              type="button"
              variant="primary"
              size="sm"
              disabled={beginMutation.isPending || !!setup}
              onClick={() => beginMutation.mutate()}
            >
              Set up
            </Button>
          )}
        </div>

        {setup && (
          <form
            className="space-y-3 rounded-md border border-[color:var(--border)] bg-[color:var(--bg-3)] p-3"
            onSubmit={(e) => {
              e.preventDefault();
              verifyMutation.mutate();
            }}
          >
            {setup.qr && (
              <img
                src={setup.qr}
                alt="Authenticator enrollment QR code"
                width={160}
                height={160}
                className="mx-auto"
              />
            )}
            <p className="text-xs text-[color:var(--text-3)] text-center">
              Scan it, or enter this key by hand:
            </p>
            <code className="block font-mono-tabular text-xs text-center break-all text-[color:var(--text-1)]">
              {setup.secret}
            </code>
            <div>
              <Label htmlFor="mfa-setup-code">Code from the app</Label>
              <Input
                id="mfa-setup-code"
                name="mfa-setup-code"
                inputMode="numeric"
                autoComplete="one-time-code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
            </div>
            <div className="flex items-center gap-2">
              <Button type="submit" variant="primary" size="sm" disabled={verifyMutation.isPending}>
                {verifyMutation.isPending ? 'Verifying…' : 'Confirm'}
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => {
                  setSetup(null);
                  setCode('');
                  setError(null);
                }}
              >
                Cancel
              </Button>
            </div>
          </form>
        )}
      </div>

      {/* ── Security keys and passkeys ── */}
      <div className="space-y-2">
        <div>
          <h3 className="text-xs font-semibold text-[color:var(--text-1)]">Security keys and passkeys</h3>
          <p className="text-xs text-[color:var(--text-3)]">
            {status.webauthn_available
              ? 'Hardware keys (YubiKey), Touch ID, Windows Hello or a passkey in your password manager.'
              : 'Unavailable — the server has no WebAuthn relying party configured.'}
          </p>
        </div>

        {status.credentials.length > 0 && (
          <ul className="divide-y divide-[color:var(--border)] rounded-md border border-[color:var(--border)]">
            {status.credentials.map((cred) => (
              <li key={cred.id} className="flex items-center justify-between gap-3 px-3 py-2">
                <div className="min-w-0">
                  <p className="truncate text-xs text-[color:var(--text-1)]">{cred.name}</p>
                  <p className="text-xs text-[color:var(--text-3)] font-mono-tabular">
                    added {formatRelative(cred.created_at)}
                    {cred.last_used_at ? ` · last used ${formatRelative(cred.last_used_at)}` : ' · never used'}
                  </p>
                </div>
                <Button
                  type="button"
                  variant="danger"
                  size="sm"
                  disabled={onlyFactor && status.credentials.length === 1}
                  onClick={() => {
                    setConfirm({ action: 'delete-credential', id: cred.id, name: cred.name });
                    setError(null);
                  }}
                >
                  Remove
                </Button>
              </li>
            ))}
          </ul>
        )}

        {status.webauthn_available && isWebAuthnAvailable() && (
          <div className="flex items-end gap-2">
            <div className="flex-1">
              <Label htmlFor="mfa-key-name">Name</Label>
              <Input
                id="mfa-key-name"
                name="mfa-key-name"
                placeholder="YubiKey 5C"
                value={keyName}
                onChange={(e) => setKeyName(e.target.value)}
              />
            </div>
            <Button
              type="button"
              variant="primary"
              size="sm"
              disabled={registering}
              onClick={() => void onRegisterKey()}
            >
              {registering ? 'Waiting for the key…' : 'Register'}
            </Button>
          </div>
        )}
      </div>

      {/* ── Recovery codes ── */}
      <div className="flex items-center justify-between gap-3">
        <div>
          <h3 className="text-xs font-semibold text-[color:var(--text-1)]">Recovery codes</h3>
          <p className="text-xs text-[color:var(--text-3)]">
            {status.recovery_codes_left > 0
              ? `${status.recovery_codes_left} unused`
              : 'None — generate a set so a lost device does not lock you out.'}
          </p>
        </div>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          disabled={!status.totp_enabled && status.credentials.length === 0}
          onClick={() => {
            setConfirm({ action: 'regenerate' });
            setError(null);
          }}
        >
          Regenerate
        </Button>
      </div>

      {/* ── Password confirmation ── */}
      {confirm && (
        <form
          className="space-y-3 rounded-md border border-[color:var(--border)] bg-[color:var(--bg-3)] p-3"
          onSubmit={(e) => {
            e.preventDefault();
            confirmMutation.mutate();
          }}
        >
          <p className="text-xs text-[color:var(--text-2)]">
            {confirm.action === 'disable-totp' && 'Removing the authenticator app.'}
            {confirm.action === 'regenerate' &&
              'Generating new recovery codes invalidates the ones you have now.'}
            {confirm.action === 'delete-credential' && `Removing "${confirm.name}".`}{' '}
            Confirm with your password.
          </p>
          <div>
            <Label htmlFor="mfa-confirm-password">Password</Label>
            <Input
              id="mfa-confirm-password"
              name="mfa-confirm-password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <div className="flex items-center gap-2">
            <Button type="submit" variant="danger" size="sm" disabled={confirmMutation.isPending}>
              {confirmMutation.isPending ? 'Working…' : 'Confirm'}
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => {
                setConfirm(null);
                setPassword('');
                setError(null);
              }}
            >
              Cancel
            </Button>
          </div>
        </form>
      )}

      {/* ── Freshly generated codes ── */}
      {codes && (
        <div className={cn('space-y-2 rounded-md border p-3', 'border-[color:var(--signal)]/40 bg-[color:var(--bg-3)]')}>
          <p className="text-xs text-[color:var(--text-1)] font-semibold">
            Save these recovery codes — they are shown only once
          </p>
          <ul className="grid grid-cols-2 gap-1">
            {codes.map((c) => (
              <li key={c} className="font-mono-tabular text-xs text-[color:var(--text-1)]">
                {c}
              </li>
            ))}
          </ul>
          <Button type="button" variant="ghost" size="sm" onClick={() => setCodes(null)}>
            Done
          </Button>
        </div>
      )}
    </div>
  );
}
