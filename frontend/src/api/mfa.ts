import { apiFetch, setCsrfToken } from './client';

// ---------------------------------------------------------------------------
// Multi-factor authentication.
//
// Two surfaces live here:
//   - the pre-auth half of a login (challenge → second factor → session),
//     which bypasses apiFetch for the same reason login() does: those calls
//     are unauthenticated and must not trigger the 401 → /login redirect;
//   - the authenticated enrollment endpoints used by the profile page.
// ---------------------------------------------------------------------------

export interface MFAChallenge {
  challenge: string;
  /** What this user can answer with: "totp", "webauthn", "recovery". */
  methods: string[];
  /** True when the deployment requires MFA and the user has none yet. */
  enrollment: boolean;
}

export interface MFASession {
  token: string;
  csrf_token: string;
  /** Present only when a forced enrollment just handed out fresh codes. */
  recovery_codes?: string[];
}

export interface MFAStatus {
  required: boolean;
  webauthn_available: boolean;
  totp_enabled: boolean;
  recovery_codes_left: number;
  credentials: MFACredential[];
}

export interface MFACredential {
  id: string;
  name: string;
  created_at: string;
  last_used_at?: string;
}

export interface MFATOTPSetup {
  secret: string;
  uri: string;
  /** PNG data URI for the enrollment QR code; may be absent. */
  qr?: string;
}

interface ApiError {
  error?: string;
}

/** POST to a pre-auth MFA endpoint, throwing the server's message on failure. */
async function postPreAuth<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = (await res.json().catch(() => ({}))) as ApiError;
    throw new Error(err.error || 'Verification failed. Please try again.');
  }
  return (await res.json()) as T;
}

/** Finishing a login through any MFA path lands here: store the CSRF token. */
function adoptSession(session: MFASession): MFASession {
  setCsrfToken(session.csrf_token);
  return session;
}

// --- login: second factor -------------------------------------------------

export async function submitMFACode(
  challenge: string,
  method: 'totp' | 'recovery',
  code: string,
): Promise<MFASession> {
  return adoptSession(
    await postPreAuth<MFASession>('/api/v1/login/mfa', { challenge, method, code }),
  );
}

export async function beginMFAEnrollment(challenge: string): Promise<MFATOTPSetup> {
  return postPreAuth<MFATOTPSetup>('/api/v1/login/mfa/enroll/begin', { challenge });
}

export async function finishMFAEnrollment(challenge: string, code: string): Promise<MFASession> {
  return adoptSession(
    await postPreAuth<MFASession>('/api/v1/login/mfa/enroll/finish', { challenge, code }),
  );
}

/**
 * Runs the WebAuthn assertion ceremony for a login challenge: fetch the
 * options, hand them to the authenticator, post the result back.
 */
export async function loginWithSecurityKey(challenge: string): Promise<MFASession> {
  const options = await postPreAuth<{ publicKey: PublicKeyCredentialRequestOptionsJSON }>(
    '/api/v1/login/mfa/webauthn/begin',
    { challenge },
  );
  const assertion = await getAssertion(options.publicKey);
  return adoptSession(
    await postPreAuth<MFASession>('/api/v1/login/mfa/webauthn/finish', {
      challenge,
      credential: assertion,
    }),
  );
}

// --- profile: enrollment --------------------------------------------------

export function getMFAStatus(): Promise<MFAStatus> {
  return apiFetch<MFAStatus>('/api/v1/mfa');
}

export function beginTOTP(): Promise<MFATOTPSetup> {
  return apiFetch<MFATOTPSetup>('/api/v1/mfa/totp', { method: 'POST' });
}

export function verifyTOTP(code: string): Promise<{ recovery_codes: string[] }> {
  return apiFetch<{ recovery_codes: string[] }>('/api/v1/mfa/totp/verify', {
    method: 'POST',
    body: JSON.stringify({ code }),
  });
}

export function disableTOTP(password: string): Promise<{ message: string }> {
  return apiFetch<{ message: string }>('/api/v1/mfa/totp', {
    method: 'DELETE',
    body: JSON.stringify({ password }),
  });
}

export function regenerateRecoveryCodes(password: string): Promise<{ recovery_codes: string[] }> {
  return apiFetch<{ recovery_codes: string[] }>('/api/v1/mfa/recovery', {
    method: 'POST',
    body: JSON.stringify({ password }),
  });
}

export function deleteCredential(id: string, password: string): Promise<{ message: string }> {
  return apiFetch<{ message: string }>(`/api/v1/mfa/webauthn/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    body: JSON.stringify({ password }),
  });
}

/** Registers a passkey or security key against the signed-in account. */
export async function registerSecurityKey(name: string): Promise<{ message: string }> {
  const begin = await apiFetch<{
    challenge_id: string;
    options: { publicKey: PublicKeyCredentialCreationOptionsJSON };
  }>('/api/v1/mfa/webauthn', { method: 'POST' });
  const credential = await createCredential(begin.options.publicKey);
  return apiFetch<{ message: string }>('/api/v1/mfa/webauthn/verify', {
    method: 'POST',
    body: JSON.stringify({ challenge: begin.challenge_id, name, credential }),
  });
}

// --- WebAuthn plumbing ----------------------------------------------------
//
// The server speaks the WebAuthn JSON encoding (base64url strings) while the
// browser API wants ArrayBuffers, so every binary field is converted on the
// way in and back on the way out. Written by hand rather than pulling in
// @simplewebauthn/browser: it is two conversions and a pair of calls.

export function isWebAuthnAvailable(): boolean {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential;
}

interface PublicKeyCredentialRequestOptionsJSON {
  challenge: string;
  timeout?: number;
  rpId?: string;
  userVerification?: UserVerificationRequirement;
  allowCredentials?: { id: string; type: string; transports?: string[] }[];
}

interface PublicKeyCredentialCreationOptionsJSON {
  challenge: string;
  rp: { id?: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: { type: string; alg: number }[];
  timeout?: number;
  attestation?: AttestationConveyancePreference;
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  excludeCredentials?: { id: string; type: string; transports?: string[] }[];
}

function fromBase64Url(value: string): ArrayBuffer {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes.buffer;
}

function toBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let raw = '';
  for (const b of bytes) raw += String.fromCharCode(b);
  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function descriptors(list?: { id: string; type: string; transports?: string[] }[]) {
  return list?.map((c) => ({
    id: fromBase64Url(c.id),
    type: c.type as PublicKeyCredentialType,
    transports: c.transports as AuthenticatorTransport[] | undefined,
  }));
}

async function getAssertion(options: PublicKeyCredentialRequestOptionsJSON) {
  const credential = (await navigator.credentials.get({
    publicKey: {
      ...options,
      challenge: fromBase64Url(options.challenge),
      allowCredentials: descriptors(options.allowCredentials),
    },
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error('No security key was used.');
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: toBase64Url(response.clientDataJSON),
      authenticatorData: toBase64Url(response.authenticatorData),
      signature: toBase64Url(response.signature),
      userHandle: response.userHandle ? toBase64Url(response.userHandle) : undefined,
    },
  };
}

async function createCredential(options: PublicKeyCredentialCreationOptionsJSON) {
  const credential = (await navigator.credentials.create({
    publicKey: {
      ...options,
      challenge: fromBase64Url(options.challenge),
      user: { ...options.user, id: fromBase64Url(options.user.id) },
      pubKeyCredParams: options.pubKeyCredParams as PublicKeyCredentialParameters[],
      excludeCredentials: descriptors(options.excludeCredentials),
    },
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error('Registration was cancelled.');
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    transports: response.getTransports?.() ?? [],
    response: {
      clientDataJSON: toBase64Url(response.clientDataJSON),
      attestationObject: toBase64Url(response.attestationObject),
    },
  };
}
