import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useRouter } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { cn } from '$/lib/cn';
import { Logo } from '$/components/atoms/Logo';
import { Button } from '$/components/atoms/Button';
import { Input } from '$/components/atoms/Input';
import { Label } from '$/components/atoms/Label';
import { login, listAuthMethods } from '$/api/client';

const loginSchema = z.object({
  username: z.string().min(1, 'Username is required'),
  password: z.string().min(1, 'Password is required'),
});

type LoginFormValues = z.infer<typeof loginSchema>;

export function LoginPage() {
  const [serverError, setServerError] = useState<string | null>(null);
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
      await login({
        username: values.username,
        password: values.password,
      });
      void router.navigate({ to: '/_app' });
    } catch (err) {
      setServerError(err instanceof Error ? err.message : 'Login failed');
    }
  }

  return (
    <div
      className="min-h-screen flex items-center justify-center px-4"
      style={{
        background:
          'radial-gradient(900px 600px at 50% 30%, rgba(var(--halo-r), var(--halo-g), var(--halo-b), 0.07) 0%, transparent 60%), var(--bg-0)',
      }}
    >
      <div
        className={cn(
          'w-full max-w-sm',
          'bg-[color:var(--bg-1)] border border-[color:var(--border)]',
          'rounded-2xl p-8',
          'shadow-[0_10px_28px_rgba(0,0,0,0.32)]'
        )}
      >
        {/* Wordmark */}
        <div className="flex flex-col items-center mb-8">
          <Logo size={48} />
          <div className="mt-3 font-display text-2xl font-bold tracking-tight text-[color:var(--text-1)]">
            osctrl
          </div>
          <p className="mt-1 text-xs text-[color:var(--text-3)] font-mono-tabular uppercase tracking-[0.1em]">
            Osquery Control
          </p>
        </div>

        <form onSubmit={handleSubmit(onSubmit)} noValidate className="space-y-4">
          {/* Username */}
          <div>
            <Label htmlFor="username">Username</Label>
            <Input
              id="username"
              type="text"
              autoComplete="username"
              autoFocus
              {...register('username')}
              error={errors.username?.message}
            />
            {errors.username && (
              <p className="mt-1 text-xs text-[color:var(--danger)] flex items-center gap-1">
                <svg aria-hidden="true" className="w-3.5 h-3.5 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" y1="8" x2="12" y2="12" />
                  <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
                {errors.username.message}
              </p>
            )}
          </div>

          {/* Password */}
          <div>
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              type="password"
              autoComplete="current-password"
              {...register('password')}
              error={errors.password?.message}
            />
            {errors.password && (
              <p className="mt-1 text-xs text-[color:var(--danger)] flex items-center gap-1">
                <svg aria-hidden="true" className="w-3.5 h-3.5 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" y1="8" x2="12" y2="12" />
                  <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
                {errors.password.message}
              </p>
            )}
          </div>

          {/* Server error */}
          {serverError && (
            <div className="rounded-lg border border-[color:var(--danger)]/30 bg-[color:var(--danger)]/10 px-3 py-2.5 text-sm text-[color:var(--danger)] flex items-start gap-2">
              <svg aria-hidden="true" className="w-4 h-4 flex-shrink-0 mt-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10" />
                <line x1="15" y1="9" x2="9" y2="15" />
                <line x1="9" y1="9" x2="15" y2="15" />
              </svg>
              {serverError}
            </div>
          )}

          <Button
            type="submit"
            variant="primary"
            size="lg"
            disabled={isSubmitting}
            className="w-full mt-2"
          >
            {isSubmitting ? 'Signing in…' : 'Sign in'}
          </Button>

          {hasSSO && (
            <div className="relative my-4 flex items-center">
              <div className="flex-grow border-t border-[color:var(--border)]" />
              <span className="mx-3 text-[0.65rem] uppercase tracking-[0.15em] font-mono-tabular text-[color:var(--text-3)]">
                or
              </span>
              <div className="flex-grow border-t border-[color:var(--border)]" />
            </div>
          )}
          {oidcMethod && (
            <a
              href={oidcMethod.loginUrl}
              className={cn(
                'inline-flex w-full items-center justify-center gap-2',
                'px-4 py-2.5 rounded-md text-sm font-medium',
                'bg-[color:var(--bg-2)] border border-[color:var(--border)]',
                'text-[color:var(--text-1)]',
                'hover:bg-[color:var(--bg-1)] hover:border-[color:var(--signal)]',
                'focus:outline-none focus:ring-2 focus:ring-[color:var(--signal)] focus:ring-offset-2 focus:ring-offset-[color:var(--bg-1)]',
                'transition-colors duration-150',
              )}
            >
              <svg aria-hidden="true" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
              Continue with OIDC
            </a>
          )}
          {samlMethod && (
            <a
              href={samlMethod.loginUrl}
              className={cn(
                'inline-flex w-full items-center justify-center gap-2',
                'px-4 py-2.5 rounded-md text-sm font-medium',
                'bg-[color:var(--bg-2)] border border-[color:var(--border)]',
                'text-[color:var(--text-1)]',
                'hover:bg-[color:var(--bg-1)] hover:border-[color:var(--signal)]',
                'focus:outline-none focus:ring-2 focus:ring-[color:var(--signal)] focus:ring-offset-2 focus:ring-offset-[color:var(--bg-1)]',
                'transition-colors duration-150',
                oidcMethod && 'mt-2',
              )}
            >
              <svg aria-hidden="true" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
              Continue with SAML
            </a>
          )}
        </form>
      </div>
    </div>
  );
}
