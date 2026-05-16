/**
 * Enrollment API client.
 *
 * Wraps the four /api/v1/environments/{env}/{enroll|remove}/{...} endpoints
 * already implemented in cmd/api/handlers/environments.go. The Go side is
 * AdminLevel-gated because the returned strings either are the enroll secret
 * outright or embed it in a URL ( in the audit), so this
 * client function output should never be cached or logged.
 *
 * The literal action / target strings here are taken from pkg/settings/settings.go
 * (ActionExtend/Expire/Rotate/Notexpire + SetMacPackage/SetMsiPackage/SetDebPackage/SetRpmPackage,
 * DownloadSecret/DownloadCert/DownloadFlags) and pkg/environments/oneliners.go
 * (EnrollShell/EnrollPowershell/RemoveShell/RemovePowershell). If the Go
 * constants change, update these mirrors and the matching switch arms.
 */

import { apiFetch } from './client';

// ---------------------------------------------------------------------------
// Targets accepted by GET /environments/{env}/enroll/{target}
// ---------------------------------------------------------------------------
export type EnrollTarget =
  | 'secret' // raw enroll secret (string)
  | 'cert' // env certificate PEM
  | 'flags' // raw osquery flags file content
  | 'enroll.sh' // bash one-liner installer
  | 'enroll.ps1'; // powershell one-liner installer

// GET /environments/{env}/remove/{target}
export type RemoveTarget = 'remove.sh' | 'remove.ps1';

// ---------------------------------------------------------------------------
// Actions accepted by POST /environments/{env}/enroll/{action}
// ---------------------------------------------------------------------------
export type EnrollAction =
  | 'extend' // push enroll_expire forward
  | 'expire' // invalidate now
  | 'rotate' // generate new secret + reset expire
  | 'notexpire' // permanent secret
  | 'set_pkg' // set macOS package URL
  | 'set_msi' // set Windows package URL
  | 'set_deb' // set Debian package URL
  | 'set_rpm'; // set RPM package URL

// Mirrors of the same actions for the remove-secret lifecycle.
export type RemoveAction = 'extend' | 'expire' | 'rotate' | 'notexpire';

// ---------------------------------------------------------------------------
// Request / response shapes
// ---------------------------------------------------------------------------
// The handler returns {"data": "..."} for every GET target. The action POSTs
// return {"message": "..."}.
interface DataResponse {
  data: string;
}

interface MessageResponse {
  message: string;
}

// Body for the package-set actions. All four fields are optional because the
// handler only reads the one keyed to the action; this avoids needing four
// separate request bodies.
export interface PackageActionBody {
  pkg_url?: string;
  msi_url?: string;
  deb_url?: string;
  rpm_url?: string;
}

// ---------------------------------------------------------------------------
// GET — read enroll material
// ---------------------------------------------------------------------------
export function getEnrollData(env: string, target: EnrollTarget): Promise<DataResponse> {
  return apiFetch<DataResponse>(
    `/api/v1/environments/${encodeURIComponent(env)}/enroll/${encodeURIComponent(target)}`,
  );
}

export function getRemoveData(env: string, target: RemoveTarget): Promise<DataResponse> {
  return apiFetch<DataResponse>(
    `/api/v1/environments/${encodeURIComponent(env)}/remove/${encodeURIComponent(target)}`,
  );
}

// ---------------------------------------------------------------------------
// POST — secret lifecycle and package-URL setters
// ---------------------------------------------------------------------------
export function enrollAction(
  env: string,
  action: EnrollAction,
  body: PackageActionBody = {},
): Promise<MessageResponse> {
  return apiFetch<MessageResponse>(
    `/api/v1/environments/${encodeURIComponent(env)}/enroll/${encodeURIComponent(action)}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  );
}

export function removeAction(
  env: string,
  action: RemoveAction,
): Promise<MessageResponse> {
  return apiFetch<MessageResponse>(
    `/api/v1/environments/${encodeURIComponent(env)}/remove/${encodeURIComponent(action)}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    },
  );
}
