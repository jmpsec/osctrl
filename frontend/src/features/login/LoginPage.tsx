import { useState } from 'react';
import { usePageTitle } from '$/lib/usePageTitle';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useRouter } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { cn } from '$/lib/cn';
import { CircleAlert, Eye, EyeOff, KeyRound, LockKeyhole, Network, ScanSearch, ShieldCheck } from 'lucide-react';
import { Button } from '$/components/atoms/Button';
import { Input } from '$/components/atoms/Input';
import { Label } from '$/components/atoms/Label';
import { Logo } from '$/components/atoms/Logo';
import { ThemeToggle } from '$/components/chrome/ThemeToggle';
import { login, listAuthMethods } from '$/api/client';
import {
  submitMFACode,
  beginMFAEnrollment,
  finishMFAEnrollment,
  loginWithSecurityKey,
  isWebAuthnAvailable,
  type MFATOTPSetup,
} from '$/api/mfa';

const loginSchema = z.object({
  username: z.string().min(1, 'Username is required'),
  password: z.string().min(1, 'Password is required'),
});

type LoginFormValues = z.infer<typeof loginSchema>;

/** The second step of a login, once the password has been accepted. */
interface MFAState {
  challenge: string;
  methods: string[];
  enrollment: boolean;
  setup?: MFATOTPSetup;
}

function AuthIntro({ title, description }: { title: string; description: string }) {
  return (
    <div className="flex flex-col gap-2">
      <h1 className="text-balance font-display text-2xl font-semibold tracking-tight text-[color:var(--text-1)]">
        {title}
      </h1>
      <p className="max-w-[40ch] text-pretty text-base text-[color:var(--text-2)] sm:text-sm">{description}</p>
    </div>
  );
}

function InlineError({ children }: { children: React.ReactNode }) {
  return (
    <div
      role="alert"
      className="flex items-start gap-2 rounded-lg bg-[color:var(--danger)]/8 p-3 text-base text-[color:var(--danger)] ring-1 ring-inset ring-[color:var(--danger)]/20 sm:text-sm"
    >
      <CircleAlert size={16} strokeWidth={1.8} aria-hidden className="mt-0.5 shrink-0" />
      <p className="min-w-0 text-pretty">{children}</p>
    </div>
  );
}

function ProductContextPanel() {
  const capabilities = [
    {
      icon: Network,
      title: 'Work in context',
      description: 'Enter the right fleet environment from the moment you sign in.',
    },
    {
      icon: ScanSearch,
      title: 'Investigate in one place',
      description: 'Move from endpoint visibility to query results without losing context.',
    },
    {
      icon: ShieldCheck,
      title: 'Act with confidence',
      description: 'Keep sensitive operator actions visible and reviewable.',
    },
  ];

  return (
    <aside className="hidden min-w-0 p-3 pr-0 lg:order-1 lg:flex" aria-label="About the osctrl workspace">
      <div className="flex min-w-0 flex-1 flex-col justify-between overflow-hidden">
        <div className="flex items-center gap-2 p-8 text-sm font-medium text-[color:var(--text-2)]">
          <ShieldCheck size={16} strokeWidth={1.8} aria-hidden className="shrink-0" />
          Operator workspace
        </div>

        <div className="flex max-w-xl flex-col gap-5 p-10 xl:p-14">
          <p className="text-sm font-medium text-[color:var(--text-link)]">osquery fleet operations</p>
          <h2 className="text-balance font-display text-3xl font-semibold tracking-tight text-[color:var(--text-1)] xl:text-4xl">
            Secure fleet operations, without the noise.
          </h2>
          <p className="max-w-[52ch] text-pretty text-base text-[color:var(--text-2)]">
            Move from endpoint visibility to investigation and response in one calm, environment-aware control plane.
          </p>
        </div>

        <div className="grid grid-cols-3 gap-5 px-10 py-8 xl:gap-8 xl:px-14">
          {capabilities.map(({ icon: Icon, title, description }) => (
            <div key={title} className="flex min-w-0 flex-col gap-3">
              <div className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-[color:var(--bg-1)] text-[color:var(--text-link)] ring-1 ring-inset ring-[color:var(--border)]">
                <Icon size={16} strokeWidth={1.8} aria-hidden className="shrink-0" />
              </div>
              <div className="min-w-0">
                <p className="text-sm font-semibold text-[color:var(--text-1)]">{title}</p>
                <p className="mt-1 text-sm leading-5 text-[color:var(--text-2)]">{description}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </aside>
  );
}

export function LoginPage() {
  usePageTitle('Login');
  const [serverError, setServerError] = useState<string | null>(null);
  const [mfa, setMfa] = useState<MFAState | null>(null);
  const [mfaCode, setMfaCode] = useState('');
  const [useRecoveryCode, setUseRecoveryCode] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [mfaBusy, setMfaBusy] = useState(false);
  // Shown once, after a forced enrollment: the only time these exist.
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const router = useRouter();

  const { data: authMethods } = useQuery({
    queryKey: ['auth-methods'],
    queryFn: () => listAuthMethods(),
    staleTime: 5 * 60_000,
    retry: 1,
  });
  const oidcMethod = authMethods?.find((m) => m.type === 'oidc');
  const samlMethod = authMethods?.find((m) => m.type === 'saml');
  const hasSSO = oidcMethod || samlMethod;

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
  });

  async function onSubmit(values: LoginFormValues) {
    setServerError(null);
    try {
      const result = await login({
        username: values.username,
        password: values.password,
      });
      if (result.kind === 'mfa') {
        const state: MFAState = {
          challenge: result.challenge,
          methods: result.methods,
          enrollment: result.enrollment,
        };
        // A user who must enroll gets the secret straight away, so the
        // step renders as "scan this, then confirm" in one screen.
        if (result.enrollment) {
          state.setup = await beginMFAEnrollment(result.challenge);
        }
        setMfa(state);
        return;
      }
      void router.navigate({ to: '/_app' });
    } catch (err) {
      setServerError(err instanceof Error ? err.message : 'Login failed');
    }
  }

  async function onSubmitMFA(e: React.FormEvent) {
    e.preventDefault();
    if (!mfa) return;
    setServerError(null);
    setMfaBusy(true);
    try {
      if (mfa.enrollment) {
        const session = await finishMFAEnrollment(mfa.challenge, mfaCode);
        // Hold the user here until they have written the codes down;
        // they are unrecoverable afterwards.
        setRecoveryCodes(session.recovery_codes ?? []);
        return;
      }
      await submitMFACode(mfa.challenge, useRecoveryCode ? 'recovery' : 'totp', mfaCode);
      void router.navigate({ to: '/_app' });
    } catch (err) {
      setServerError(err instanceof Error ? err.message : 'Verification failed');
      setMfaCode('');
    } finally {
      setMfaBusy(false);
    }
  }

  async function onSecurityKey() {
    if (!mfa) return;
    setServerError(null);
    setMfaBusy(true);
    try {
      await loginWithSecurityKey(mfa.challenge);
      void router.navigate({ to: '/_app' });
    } catch (err) {
      setServerError(err instanceof Error ? err.message : 'Security key verification failed');
    } finally {
      setMfaBusy(false);
    }
  }

  function restart() {
    setMfa(null);
    setMfaCode('');
    setUseRecoveryCode(false);
    setServerError(null);
  }

  return (
    <div className="isolate min-h-dvh bg-[color:var(--bg-2)] text-[color:var(--text-1)]">
      <header className="absolute inset-x-0 top-0 z-10 flex items-center justify-between p-5 sm:p-6">
        <div className="flex items-center gap-2.5">
          <Logo size={28} decorative />
          <div className="font-wordmark text-lg font-semibold text-[color:var(--text-1)]">osctrl</div>
        </div>
        <div className="rounded-lg bg-[color:var(--bg-1)] ring-1 ring-inset ring-[color:var(--border)]">
          <ThemeToggle />
        </div>
      </header>

      <main className="grid min-h-dvh lg:grid-cols-[7fr_5fr]">
        <section className="min-w-0 p-3 lg:order-2 lg:pl-0" aria-label="Sign in">
          <div className="flex min-h-[calc(100dvh-1.5rem)] w-full items-center rounded-xl bg-[color:var(--bg-1)] px-6 pb-12 pt-28 ring-1 ring-inset ring-[color:var(--border)] sm:px-10 lg:px-16">
            <div className="mx-auto flex w-full max-w-sm flex-col gap-8">
              {recoveryCodes ? (
                <AuthIntro
                  title="Save your recovery codes"
                  description="Each code signs you in once if you lose your authenticator. They are shown only now."
                />
              ) : mfa ? (
                <AuthIntro
                  title={mfa.enrollment ? 'Set up two-factor authentication' : 'Verify your identity'}
                  description={
                    mfa.enrollment
                      ? 'Scan the code with an authenticator app, then enter the verification code it shows.'
                      : useRecoveryCode
                        ? 'Enter one of the recovery codes you saved when you enrolled.'
                        : 'Enter the current code from your authenticator app.'
                  }
                />
              ) : (
                <AuthIntro title="Welcome back" description="Sign in to continue to your osquery control workspace." />
              )}

              {recoveryCodes ? (
                /* Forced enrollment just completed. The codes exist nowhere else,
                 so the session waits behind an explicit acknowledgement. */
                <div className="flex flex-col gap-5">
                  <ul
                    role="list"
                    className="grid grid-cols-2 gap-2 rounded-lg bg-[color:var(--bg-2)] p-4 ring-1 ring-inset ring-[color:var(--border)]"
                  >
                    {recoveryCodes.map((code) => (
                      <li key={code} className="font-mono-tabular text-sm text-[color:var(--text-1)]">
                        {code}
                      </li>
                    ))}
                  </ul>
                  <Button
                    type="button"
                    variant="primary"
                    size="lg"
                    className="h-11 w-full sm:h-10"
                    onClick={() => void router.navigate({ to: '/_app' })}
                  >
                    I have saved them — continue
                  </Button>
                </div>
              ) : mfa ? (
                <form onSubmit={onSubmitMFA} noValidate className="flex flex-col gap-5">
                  {mfa.enrollment && mfa.setup && (
                    <div className="flex flex-col items-center gap-3 rounded-lg bg-[color:var(--bg-2)] p-4 ring-1 ring-inset ring-[color:var(--border)]">
                      {mfa.setup.qr && (
                        <div className="rounded-lg bg-white p-2 ring-1 ring-black/5">
                          <img src={mfa.setup.qr} alt="Authenticator enrollment QR code" width={176} height={176} />
                        </div>
                      )}
                      <p className="text-center text-base text-[color:var(--text-2)] sm:text-sm">
                        Can&apos;t scan? Enter this key manually.
                      </p>
                      <code className="break-all text-center font-mono-tabular text-sm text-[color:var(--text-1)]">
                        {mfa.setup.secret}
                      </code>
                    </div>
                  )}

                  <div className="flex flex-col gap-1.5">
                    <Label htmlFor="mfa-code" className="mb-0 text-base sm:text-sm">
                      {useRecoveryCode ? 'Recovery code' : 'Authentication code'}
                    </Label>
                    <Input
                      id="mfa-code"
                      name="mfa-code"
                      type="text"
                      inputMode={useRecoveryCode ? 'text' : 'numeric'}
                      autoComplete="one-time-code"
                      autoFocus
                      value={mfaCode}
                      onChange={(event) => setMfaCode(event.target.value)}
                      className={cn(
                        'h-11 rounded-lg px-3 text-base sm:h-10 sm:text-sm',
                        !useRecoveryCode && 'text-center tracking-[0.18em] tabular-nums',
                      )}
                    />
                  </div>

                  {serverError && <InlineError>{serverError}</InlineError>}

                  <Button type="submit" variant="primary" size="lg" disabled={mfaBusy} className="h-11 w-full sm:h-10">
                    {mfaBusy ? 'Verifying…' : mfa.enrollment ? 'Confirm and sign in' : 'Verify'}
                  </Button>

                  {!mfa.enrollment && mfa.methods.includes('webauthn') && isWebAuthnAvailable() && (
                    <Button
                      type="button"
                      variant="ghost"
                      size="lg"
                      disabled={mfaBusy}
                      className="h-11 w-full sm:h-10"
                      onClick={() => void onSecurityKey()}
                    >
                      <KeyRound size={16} strokeWidth={1.8} aria-hidden className="shrink-0" />
                      Use a security key or passkey
                    </Button>
                  )}

                  <div className="flex items-center justify-between gap-3 text-base sm:text-sm">
                    {!mfa.enrollment && mfa.methods.includes('recovery') ? (
                      <button
                        type="button"
                        className="rounded text-left font-medium text-[color:var(--text-link)] hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[color:var(--signal)]"
                        onClick={() => {
                          setUseRecoveryCode((value) => !value);
                          setMfaCode('');
                          setServerError(null);
                        }}
                      >
                        {useRecoveryCode ? 'Use authenticator code' : 'Use a recovery code'}
                      </button>
                    ) : (
                      <div aria-hidden />
                    )}
                    <button
                      type="button"
                      className="shrink-0 rounded font-medium text-[color:var(--text-2)] hover:text-[color:var(--text-1)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[color:var(--signal)]"
                      onClick={restart}
                    >
                      Back to sign in
                    </button>
                  </div>
                </form>
              ) : (
                <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-5">
                  <div className="flex flex-col gap-4">
                    <div className="flex flex-col gap-1.5">
                      <Label htmlFor="username" className="mb-0 text-base sm:text-sm">
                        Username
                      </Label>
                      <Input
                        id="username"
                        type="text"
                        autoComplete="username"
                        autoCapitalize="none"
                        spellCheck={false}
                        autoFocus
                        {...register('username')}
                        error={errors.username?.message}
                        className="h-11 rounded-lg px-3 text-base sm:h-10 sm:text-sm"
                      />
                      {errors.username && (
                        <p className="flex items-start gap-1.5 text-base text-[color:var(--danger)] sm:text-sm">
                          <CircleAlert size={16} strokeWidth={1.8} aria-hidden className="mt-0.5 shrink-0" />
                          {errors.username.message}
                        </p>
                      )}
                    </div>

                    <div className="flex flex-col gap-1.5">
                      <Label htmlFor="password" className="mb-0 text-base sm:text-sm">
                        Password
                      </Label>
                      <div className="relative">
                        <Input
                          id="password"
                          type={showPassword ? 'text' : 'password'}
                          autoComplete="current-password"
                          {...register('password')}
                          error={errors.password?.message}
                          className="h-11 rounded-lg py-2 pr-11 pl-3 text-base sm:h-10 sm:text-sm"
                        />
                        <button
                          type="button"
                          onClick={() => setShowPassword((visible) => !visible)}
                          className="absolute inset-y-0 right-0 flex w-11 items-center justify-center rounded-r-lg text-[color:var(--text-3)] hover:text-[color:var(--text-1)] focus-visible:outline focus-visible:outline-2 -outline-offset-2 focus-visible:outline-[color:var(--signal)]"
                          aria-label={showPassword ? 'Hide password' : 'Show password'}
                        >
                          {showPassword ? (
                            <EyeOff size={16} strokeWidth={1.8} aria-hidden className="shrink-0" />
                          ) : (
                            <Eye size={16} strokeWidth={1.8} aria-hidden className="shrink-0" />
                          )}
                          <span
                            className="pointer-events-none absolute left-1/2 top-1/2 size-[max(100%,3rem)] -translate-x-1/2 -translate-y-1/2 pointer-fine:hidden"
                            aria-hidden
                          />
                        </button>
                      </div>
                      {errors.password && (
                        <p className="flex items-start gap-1.5 text-base text-[color:var(--danger)] sm:text-sm">
                          <CircleAlert size={16} strokeWidth={1.8} aria-hidden className="mt-0.5 shrink-0" />
                          {errors.password.message}
                        </p>
                      )}
                    </div>
                  </div>

                  {serverError && <InlineError>{serverError}</InlineError>}

                  <Button
                    type="submit"
                    variant="primary"
                    size="lg"
                    disabled={isSubmitting}
                    className="h-11 w-full sm:h-10"
                  >
                    {isSubmitting ? 'Signing in…' : 'Sign in'}
                  </Button>

                  {hasSSO && (
                    <div className="flex items-center gap-3">
                      <div className="h-px grow bg-[color:var(--border)]" />
                      <p className="shrink-0 text-base text-[color:var(--text-2)] sm:text-sm">or continue with</p>
                      <div className="h-px grow bg-[color:var(--border)]" />
                    </div>
                  )}
                  {oidcMethod && (
                    <a
                      href={oidcMethod.loginUrl}
                      className={cn(
                        'inline-flex h-11 w-full items-center justify-center gap-2 rounded-lg px-3 text-base font-medium sm:h-10 sm:text-sm',
                        'bg-[color:var(--bg-1)] text-[color:var(--text-1)] ring-1 ring-inset ring-[color:var(--border)]',
                        'hover:bg-[color:var(--bg-3)] hover:ring-[color:var(--border-strong)]',
                        'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[color:var(--signal)]',
                      )}
                    >
                      <LockKeyhole aria-hidden size={16} strokeWidth={1.8} className="shrink-0" />
                      Continue with OIDC
                    </a>
                  )}
                  {samlMethod && (
                    <a
                      href={samlMethod.loginUrl}
                      className={cn(
                        'inline-flex h-11 w-full items-center justify-center gap-2 rounded-lg px-3 text-base font-medium sm:h-10 sm:text-sm',
                        'bg-[color:var(--bg-1)] text-[color:var(--text-1)] ring-1 ring-inset ring-[color:var(--border)]',
                        'hover:bg-[color:var(--bg-3)] hover:ring-[color:var(--border-strong)]',
                        'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[color:var(--signal)]',
                      )}
                    >
                      <LockKeyhole aria-hidden size={16} strokeWidth={1.8} className="shrink-0" />
                      Continue with SAML
                    </a>
                  )}
                </form>
              )}

              <div className="flex items-start gap-2 border-t border-[color:var(--border)] pt-5 text-base text-[color:var(--text-2)] sm:text-sm">
                <ShieldCheck size={16} strokeWidth={1.8} aria-hidden className="mt-0.5 shrink-0" />
                <p className="text-pretty">Protected by your deployment&apos;s authentication policy.</p>
              </div>
            </div>
          </div>
        </section>

        <ProductContextPanel />
      </main>
    </div>
  );
}
