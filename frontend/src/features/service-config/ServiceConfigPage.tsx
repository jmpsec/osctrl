import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { createPortal } from 'react-dom';
import { usePageTitle } from '$/lib/usePageTitle';
import { useParams, useNavigate, Link } from '@tanstack/react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  listServiceConfig,
  updateServiceConfig,
  applyServiceConfig,
  type ServiceConfig,
} from '$/api/service-config';
import { AuthError, ApiError } from '$/api/client';
import { cn } from '$/lib/cn';
import { Skeleton } from '$/components/data/Skeleton';
import { EmptyState } from '$/components/data/EmptyState';
import { ModalShell } from '$/components/feedback/ModalShell';
import { formatRelative } from '$/lib/time';

const SERVICES = ['api', 'tls'] as const;
type Service = (typeof SERVICES)[number];

const SENSITIVE_KEYS = new Set([
  'Password',
  'password',
  'Secret',
  'secret',
  'JWTSecret',
  'jwtSecret',
  'ClientSecret',
  'clientSecret',
  'SecretAccessKey',
  'secretAccessKey',
  'secretKey',
]);

function isSensitive(key: string): boolean {
  return SENSITIVE_KEYS.has(key);
}

const FIELD_HELP: Record<string, string> = {
  // Service
  Listener: 'Network interface to bind to (e.g. 0.0.0.0 for all interfaces, 127.0.0.1 for localhost only).',
  Port: 'TCP port the service listens on.',
  Host: 'Hostname or IP address (context-dependent: service host, database host, Redis host, etc.).',
  LogLevel: 'Minimum log level: debug, info, warn, or error.',
  LogFormat: 'Log output format: console (human-readable) or json (structured).',
  Auth: 'Authentication backend: none, json, db, saml, jwt, oauth, or oidc.',
  AuditLog: 'When enabled, records admin actions to an audit trail.',
  GeoIPDBPath: 'Path to a MaxMind GeoLite2-Country .mmdb file. When set, the API resolves node IPs to country codes. When empty, the feature is disabled.',
  PostureEnabled: 'Controls whether the security & compliance posture system is active. When false (default), the entire posture subsystem is disabled.',
  PostureQueryPrefix: 'Prefix that identifies scheduled queries whose result logs are ingested as node posture data. Only used when PostureEnabled is true.',
  TrustedProxies: 'Comma-separated CIDRs whose X-Real-IP / X-Forwarded-For headers are honored. Empty → forwarding headers ignored, RemoteAddr used.',
  DBHealthCheck: 'Enables background DB liveness monitor. Pings DB every DBHealthInterval seconds; after DBHealthThreshold failures, switches to stale-serve mode.',
  DBHealthInterval: 'Seconds between DB health pings. Only used when DBHealthCheck is true.',
  DBHealthThreshold: 'Consecutive DB ping failures before switching to stale-serve mode.',
  // DB
  Type: 'Backend type (e.g. postgres, mysql, sqlite for databases; stdout, db, s3, etc. for loggers).',
  Name: 'Database name to connect to.',
  Username: 'Database username for authentication.',
  Password: 'Database password or service secret.',
  SSLMode: 'PostgreSQL SSL mode (e.g. disable, require, verify-full).',
  FilePath: 'File path (SQLite database or local log file).',
  ConnRetry: 'Number of connection retry attempts on startup.',
  MaxIdleConns: 'Maximum idle connections in the pool.',
  MaxOpenConns: 'Maximum open connections to the database.',
  ConnMaxLifetime: 'Maximum lifetime of a connection in seconds.',
  // Redis
  ConnectionString: 'Full Redis connection string. When set, overrides Host/Port/Password.',
  DB: 'Redis database index (0–15).',
  // Osquery
  Version: 'Expected osquery version string.',
  TablesFile: 'Path to the osquery tables JSON definition file.',
  Logger: 'Enable osquery result log collection.',
  Config: 'Enable osquery configuration distribution.',
  Query: 'Enable on-demand distributed query support.',
  Carve: 'Enable file carve collection from nodes.',
  Accelerated: 'Allow accelerated check-in intervals for nodes.',
  FileExplorer: 'Enable the file explorer feature for nodes.',
  ReadOnly: 'Run in read-only mode (no writes to osquery nodes).',
  // Metrics
  Enabled: 'Enable or disable this feature.',
  // Debug
  EnableHTTP: 'When true, dumps HTTP requests to the debug file.',
  HTTPFile: 'File path where HTTP debug dumps are written.',
  ShowBody: 'Include request/response body in the debug dump.',
  TargetHostIdentifier: 'Restrict debug dump to a specific node UUID or host_identifier (case-insensitive). Empty dumps all requests.',
  // TLS
  Termination: 'Enable TLS/SSL termination at the service.',
  CertificateFile: 'Path to the TLS certificate file.',
  KeyFile: 'Path to the TLS private key file.',
  // JWT
  JWTSecret: 'Secret key used to sign JWT tokens.',
  HoursToExpire: 'JWT token lifetime in hours.',
  // BatchWriter
  WriterBatchSize: 'Number of records per batch write.',
  WriterTimeout: 'Timeout for batch write operations.',
  WriterBufferSize: 'Buffer size for the batch writer queue.',
  // SAML
  EntityID: 'SP entity identifier — what the IdP knows this service by. Conventionally the metadata URL.',
  ACSURL: 'Assertion Consumer Service URL where the IdP POSTs the SAMLResponse. Must match IdP registration.',
  CertPath: 'Path to the SAML SP certificate file.',
  KeyPath: 'Path to the SAML SP private key file.',
  MetaDataURL: 'IdP metadata URL for automatic SAML configuration.',
  RootURL: 'Root URL of the application (used to build SAML endpoints).',
  LoginURL: 'URL to redirect users for SAML login.',
  LogoutURL: 'URL to redirect users after SAML logout.',
  UsernameAttribute: 'SAML attribute whose value becomes the osctrl username. Empty uses NameID verbatim.',
  SigningCertPath: 'PEM file path to SP signing certificate. Both cert and key must be set to enable request signing.',
  SigningKeyPath: 'PEM file path to SP signing RSA private key.',
  ForceAuthn: 'When true (default), forces re-authentication at the IdP on every login.',
  SPInitiated: 'Enable SP-initiated SAML login flow.',
  JITProvision: 'Automatically create osctrl user accounts on first federated login.',
  // OIDC
  IssuerURL: 'OIDC provider issuer URL (e.g. https://accounts.google.com).',
  ClientID: 'OAuth2 client ID registered with the OIDC provider.',
  ClientSecret: 'OAuth2 client secret.',
  RedirectURL: 'OAuth2 callback URL — must match provider configuration.',
  Scopes: 'OIDC scopes to request (e.g. openid, profile, email).',
  UsernameClaim: 'JWT claim to use as the osctrl username.',
  GroupsClaim: 'JWT claim containing group memberships.',
  RequiredGroups: 'Groups a user must belong to for access.',
  UsePKCE: 'Use Proof Key for Code Exchange for added security.',
  // Logger
  Types: 'Logger backends to use (e.g. stdout, db, s3, graylog, splunk, logstash, kinesis, kafka, elastic).',
  LoggerDBSame: 'Use the same DB connection for logging (no separate logger DB).',
  AlwaysLog: 'Always log, even when no logger backend is configured.',
  // ConfigEndpoints
  Environment: 'Target osctrl environment name.',
  Secret: 'Enrollment secret for this endpoint.',
  IntegrityCheck: 'Verify config integrity before pushing.',
  // S3 (logger/carver)
  Bucket: 'S3 bucket name for storage.',
  Region: 'AWS region for the S3 bucket or Kinesis stream.',
  AccessKey: 'AWS access key ID.',
  SecretAccessKey: 'AWS secret access key.',
  // Local carver
  CarvesDir: 'Local directory to store carved files.',
  // Kinesis
  Stream: 'Kinesis stream name.',
  Endpoint: 'Custom Kinesis endpoint URL (for localstack or VPC endpoints).',
  AccessKeyID: 'AWS access key ID for Kinesis.',
  SessionToken: 'AWS session token (for temporary credentials).',
  // Kafka
  BootstrapServer: 'Kafka bootstrap server address (host:port).',
  SSLCALocation: 'Path to SSL CA certificate for Kafka TLS.',
  ConnectionTimeout: 'Kafka connection timeout duration.',
  Topic: 'Kafka topic to publish logs to.',
  SASL: 'Kafka SASL authentication configuration.',
  Mechanism: 'SASL mechanism (e.g. PLAIN, SCRAM-SHA-256).',
  // Graylog
  URL: 'Graylog or Splunk API endpoint URL.',
  Queries: 'Graylog stream/index for query logs.',
  Status: 'Graylog stream/index for status logs.',
  Results: 'Graylog stream/index for result logs.',
  // Elastic
  IndexPrefix: 'Elasticsearch index name prefix.',
  DateSeparator: 'Date separator in index names (e.g. "." for YYYY.MM.DD).',
  IndexSeparator: 'Separator between prefix and date (e.g. "-" for prefix-YYYY.MM.DD).',
  // Splunk
  Token: 'Splunk HEC (HTTP Event Collector) token.',
  Index: 'Splunk index to write events to.',
  // Logstash
  Protocol: 'Network protocol for Logstash connection (tcp or udp).',
  Path: 'URL path for Logstash HTTP input.',
  // Local logger
  MaxSize: 'Maximum log file size in megabytes before rotation.',
  MaxBackups: 'Maximum number of old log files to retain.',
  MaxAge: 'Maximum days to retain old log files.',
  Compress: 'Compress rotated log files with gzip.',
  // Osctrld
  // (uses Enabled, already defined above)
  // Rate limits
  burst: 'Maximum burst allowed before the limiter starts returning 429.',
  period: 'Refill period for the token bucket, for example 30s, 1m, or 10m.',
  evictAfter: 'How long idle caller buckets are kept before being forgotten.',
  retryAfter: 'Retry-After header value, in seconds, returned with 429 responses.',
  maxBuckets: 'Maximum caller buckets kept in memory. Use 0 for the service default.',
};

type FieldType = 'boolean' | 'number' | 'string' | 'string[]' | 'object' | 'null';

function inferType(value: unknown): FieldType {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'boolean') return 'boolean';
  if (typeof value === 'number') return 'number';
  if (Array.isArray(value) && value.every((v) => typeof v === 'string')) return 'string[]';
  if (typeof value === 'object') return 'object';
  return 'string';
}

type ParsedConfig =
  | { kind: 'object'; fields: Record<string, unknown> }
  | { kind: 'array'; items: Record<string, unknown>[] };

function parseConfigValue(raw: string): ParsedConfig {
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      const items = parsed.filter(
        (item): item is Record<string, unknown> =>
          item && typeof item === 'object' && !Array.isArray(item),
      );
      return { kind: 'array', items };
    }
    if (parsed && typeof parsed === 'object') {
      return { kind: 'object', fields: parsed as Record<string, unknown> };
    }
  } catch { /* fall through */ }
  return { kind: 'object', fields: {} };
}

type RateLimitDraft = {
  burst: number;
  period: number;
  evictAfter: number;
  retryAfter: number;
  maxBuckets: number;
};

const RATE_LIMIT_ORDER = ['login', 'preAuth', 'serviceConfigApply', 'enroll'] as const;
const API_RATE_LIMITS = ['login', 'preAuth', 'serviceConfigApply'] as const;
const TLS_RATE_LIMITS = ['enroll'] as const;
const DURATION_UNITS: Array<[string, number]> = [
  ['h', 3_600_000_000_000],
  ['m', 60_000_000_000],
  ['s', 1_000_000_000],
  ['ms', 1_000_000],
  ['us', 1_000],
  ['ns', 1],
];

function readNumber(obj: Record<string, unknown>, lower: string, upper: string): number {
  const value = obj[lower] ?? obj[upper];
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

function rateLimitNamesForService(service: string): readonly string[] {
  return service === 'tls' ? TLS_RATE_LIMITS : API_RATE_LIMITS;
}

function normalizeRateLimits(value: Record<string, unknown>, service: string): Record<string, RateLimitDraft> {
  const aliases: Record<string, string> = {
    login: 'Login',
    preAuth: 'PreAuth',
    serviceConfigApply: 'ServiceConfigApply',
    enroll: 'Enroll',
  };
  const out: Record<string, RateLimitDraft> = {};
  for (const name of rateLimitNamesForService(service)) {
    const raw = value[name] ?? value[aliases[name]];
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) continue;
    const obj = raw as Record<string, unknown>;
    out[name] = {
      burst: readNumber(obj, 'burst', 'Burst'),
      period: readNumber(obj, 'period', 'Period'),
      evictAfter: readNumber(obj, 'evictAfter', 'EvictAfter'),
      retryAfter: readNumber(obj, 'retryAfter', 'RetryAfter'),
      maxBuckets: readNumber(obj, 'maxBuckets', 'MaxBuckets'),
    };
  }
  return out;
}

function formatDuration(ns: number): string {
  if (!Number.isFinite(ns) || ns <= 0) return '0s';
  for (const [unit, size] of DURATION_UNITS) {
    if (ns % size === 0) return `${ns / size}${unit}`;
  }
  return `${ns}ns`;
}

function parseDuration(raw: string): number | null {
  const match = raw.trim().match(/^(\d+)(ns|us|µs|ms|s|m|h)$/);
  if (!match) return null;
  const amount = Number(match[1]);
  const unit = match[2] === 'µs' ? 'us' : match[2];
  const found = DURATION_UNITS.find(([u]) => u === unit);
  if (!found) return null;
  return amount * found[1];
}

export function ServiceConfigPage() {
  usePageTitle('Service Config');
  const params = useParams({ strict: false });
  const navigate = useNavigate();
  const serviceParam = (params as { service?: string }).service ?? 'api';
  const service: Service = (SERVICES as readonly string[]).includes(serviceParam)
    ? (serviceParam as Service)
    : 'api';

  const [applyErr, setApplyErr] = useState<string | null>(null);
  const [applyFlash, setApplyFlash] = useState(false);
  const [showApplyConfirm, setShowApplyConfirm] = useState(false);
  const [restarting, setRestarting] = useState(false);
  const qc = useQueryClient();
  const {
    data,
    isLoading,
    isFetching,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: ['service-config', service],
    queryFn: () => listServiceConfig(service),
    staleTime: 30_000,
  });

  if (isError && error instanceof AuthError) {
    void navigate({ to: '/login' });
    return null;
  }

  const sections = data ?? [];
  const loading = isLoading;
  const fetching = isFetching;
  const hasError = isError;
  const pageError = error;

  const hasPendingChanges = sections.some((s) => s.Source === 'db');

  const applyMutation = useMutation({
    mutationFn: () => applyServiceConfig(),
    onSuccess: () => {
      setApplyErr(null);
      setApplyFlash(true);
      setRestarting(true);
      const poll = setInterval(() => {
        listServiceConfig(service)
          .then(() => {
            clearInterval(poll);
            setRestarting(false);
            setApplyFlash(false);
            qc.invalidateQueries({ queryKey: ['service-config', service] });
          })
          .catch(() => {});
      }, 2000);
      setTimeout(() => {
        clearInterval(poll);
        setRestarting(false);
      }, 60_000);
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      setApplyErr(e instanceof Error ? e.message : 'Apply failed');
    },
  });

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)] mr-2">
          Service Config
        </h1>
        {hasPendingChanges && !loading && !hasError && !restarting && (
          <button
            type="button"
            disabled={applyMutation.isPending}
            onClick={() => setShowApplyConfirm(true)}
            className={cn(
              'px-3 py-1 text-xs font-medium rounded transition-colors',
              applyMutation.isPending
                ? 'bg-[color:var(--bg-3)] text-[color:var(--text-3)]'
                : 'bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.12)] text-[color:var(--warning)] hover:bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.2)]',
            )}
          >
            {applyMutation.isPending ? 'Restarting…' : applyFlash ? 'Restart triggered ✓' : 'Apply & Restart'}
          </button>
        )}
        {restarting && (
          <span
            aria-live="polite"
            className="text-xs text-[color:var(--text-3)] font-mono-tabular"
          >
            Restarting — waiting for service…
          </span>
        )}
        {applyErr && (
          <span className="text-xs text-[color:var(--danger)]">{applyErr}</span>
        )}
        {fetching && !loading && (
          <span
            aria-live="polite"
            aria-label="Refreshing data"
            className="ml-auto text-[10px] text-[color:var(--text-3)] font-mono-tabular"
          >
            refreshing…
          </span>
        )}
      </div>

      <div
        role="tablist"
        aria-label="Service config service tabs"
        className="flex items-center gap-1 px-2 border-b border-[color:var(--border)] overflow-x-auto"
      >
        {SERVICES.map((s) => (
          <Link
            key={s}
            to="/_app/config/$service"
            params={{ service: s }}
            role="tab"
            aria-selected={s === service}
            className={cn(
              'inline-flex items-center gap-1.5 px-3 pt-2 pb-1.5 text-xs whitespace-nowrap',
              'border-b-2 transition-colors',
              'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
              s === service
                ? 'border-[color:var(--signal)] text-[color:var(--text-1)] font-semibold'
                : 'border-transparent text-[color:var(--text-3)] hover:text-[color:var(--text-1)]',
            )}
          >
            osctrl-{s}
          </Link>
        ))}
      </div>

      <div className="flex-1 overflow-auto min-h-0 p-4">
        {loading && (
          <div className="space-y-2">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-20 w-full" />
            ))}
          </div>
        )}

        {hasError && !loading && (
          <EmptyState
            icon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <circle cx="12" cy="12" r="10" />
                <path d="M12 8v4M12 16h.01" />
              </svg>
            }
            title={pageError instanceof Error ? pageError.message : 'Failed to load service config'}
            action={
              <button
                type="button"
                onClick={() => void refetch()}
                className="px-3 py-1.5 text-xs font-medium rounded bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)] transition-colors"
              >
                Retry
              </button>
            }
          />
        )}

        {!loading && !hasError && sections.length === 0 && (
          <EmptyState
            icon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            }
            title={`No service config for ${service}.`}
          />
        )}

        {!loading && !hasError && sections.length > 0 && (
          <div className="space-y-3">
            {sections.map((s) => (
              <ConfigSectionCard
                key={s.ID}
                section={s}
                service={service}
                onSaved={() => qc.invalidateQueries({ queryKey: ['service-config', service] })}
              />
            ))}
          </div>
        )}
      </div>

      {showApplyConfirm && (
        <ApplyConfirmDialog
          pendingSections={sections.filter((s) => s.Source === 'db')}
          isPending={applyMutation.isPending}
          onConfirm={() => {
            applyMutation.mutate();
            setShowApplyConfirm(false);
          }}
          onCancel={() => setShowApplyConfirm(false)}
        />
      )}
    </div>
  );
}

function ConfigSectionCard({
  section,
  service,
  onSaved,
}: {
  section: ServiceConfig;
  service: string;
  onSaved: () => void;
}) {
  const parsed = useMemo(() => parseConfigValue(section.Value), [section.Value]);
  const isArray = parsed.kind === 'array';
  const originalFields = isArray ? {} as Record<string, unknown> : parsed.fields;
  const editableOriginalFields = useMemo(
    () => (section.Name === 'rateLimits' ? normalizeRateLimits(originalFields, service) : originalFields),
    [originalFields, section.Name, service],
  );
  const arrayItems = isArray ? parsed.items : [];
  const [draft, setDraft] = useState<Record<string, unknown>>(() => ({ ...editableOriginalFields }));
  const [collapsed, setCollapsed] = useState(!section.Editable);
  const [savedFlash, setSavedFlash] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    const p = parseConfigValue(section.Value);
    if (p.kind === 'object') {
      setDraft(section.Name === 'rateLimits' ? normalizeRateLimits(p.fields, service) : { ...p.fields });
    } else {
      setDraft({});
    }
  }, [section.Name, section.Value, service]);

  const dirtyKeys = useMemo(() => {
    const keys: string[] = [];
    for (const key of Object.keys(editableOriginalFields)) {
      if (JSON.stringify(editableOriginalFields[key]) !== JSON.stringify(draft[key])) {
        keys.push(key);
      }
    }
    return keys;
  }, [editableOriginalFields, draft]);

  const dirty = dirtyKeys.length > 0;

  const updateField = useCallback((key: string, value: unknown) => {
    setDraft((prev) => ({ ...prev, [key]: value }));
  }, []);

  const mutation = useMutation({
    mutationFn: () => updateServiceConfig(service, section.Name, { value: draft }),
    onSuccess: () => {
      setErr(null);
      setSavedFlash(true);
      window.setTimeout(() => setSavedFlash(false), 1200);
      onSaved();
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      if (e instanceof ApiError && e.status === 409) {
        setErr('Section is not editable.');
        return;
      }
      if (e instanceof ApiError && e.status === 400) {
        setErr('Invalid value.');
        return;
      }
      setErr(e instanceof Error ? e.message : 'Save failed');
    },
  });

  const fieldEntries = Object.entries(editableOriginalFields);

  const booleanFields = section.Editable
    ? fieldEntries.filter(([, v]) => typeof v === 'boolean')
    : [];
  const nonBooleanFields = section.Editable
    ? fieldEntries.filter(([, v]) => typeof v !== 'boolean')
    : fieldEntries;

  const hasManyBooleans = booleanFields.length >= 3;

  return (
    <section
      className="border border-[color:var(--border)] rounded-md bg-[color:var(--bg-1)]"
      aria-labelledby={`config-${section.Name}-heading`}
    >
      <header
        className="flex items-center gap-3 px-3 py-2 bg-[color:var(--bg-0)] border-b border-[color:var(--border)] cursor-pointer select-none hover:bg-[color-mix(in_srgb,var(--bg-0)_85%,var(--bg-3))] rounded-t-[5px]"
        onClick={() => setCollapsed((c) => !c)}
      >
        <h2
          id={`config-${section.Name}-heading`}
          className="font-display text-sm font-semibold text-[color:var(--text-1)] font-mono-tabular"
        >
          {section.Name}
        </h2>
        <span
          className={cn(
            'px-1.5 py-0.5 rounded text-[10px] font-mono-tabular',
            section.Source === 'db'
              ? 'bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.12)] text-[color:var(--warning)]'
              : 'bg-[color:var(--bg-2)] text-[color:var(--text-3)]',
          )}
          title={section.Source === 'db' ? 'Edited via database' : 'Seeded from YAML file'}
        >
          {section.Source}
        </span>
        <span
          className={cn(
            'px-1.5 py-0.5 rounded text-[10px] font-mono-tabular',
            section.Editable
              ? 'bg-[rgba(var(--signal-r),var(--signal-g),var(--signal-b),0.12)] text-[color:var(--signal)]'
              : 'bg-[color:var(--bg-2)] text-[color:var(--text-3)]',
          )}
        >
          {section.Editable ? 'editable' : 'read-only'}
        </span>
        {dirty && (
          <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.12)] text-[color:var(--warning)]">
            {dirtyKeys.length} {dirtyKeys.length === 1 ? 'change' : 'changes'}
          </span>
        )}
        {section.Info && (
          <p className="text-[10px] text-[color:var(--text-3)] truncate flex-1">
            {section.Info}
          </p>
        )}
        {!section.Info && <div className="flex-1" />}
        <span
          className="text-[10px] tnum text-[color:var(--text-3)] whitespace-nowrap"
          title={section.UpdatedAt}
        >
          updated {formatRelative(section.UpdatedAt)}
        </span>
        {section.Editable && (
          <button
            type="button"
            disabled={!dirty || mutation.isPending}
            onClick={(e) => {
              e.stopPropagation();
              mutation.mutate();
            }}
            className={cn(
              'text-[10px] px-2 py-0.5 rounded font-medium',
              'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
              'disabled:opacity-40 disabled:cursor-not-allowed',
            )}
          >
            {mutation.isPending ? 'Saving…' : savedFlash ? 'Saved ✓' : 'Save'}
          </button>
        )}
        <svg
          className={cn(
            'w-4 h-4 text-[color:var(--text-3)] transition-transform duration-200 shrink-0',
            !collapsed && 'rotate-180',
          )}
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <polyline points="6 9 12 15 18 9" />
        </svg>
      </header>

      {!collapsed && <div>
        {/* Array-type sections (e.g. configEndpoints) */}
        {isArray && (
          arrayItems.length === 0 ? (
            <div className="px-3.5 py-4 text-xs text-[color:var(--text-3)] italic">No items configured.</div>
          ) : (
            arrayItems.map((item, idx) => (
              <div key={idx} className="border-b border-[color:var(--border)] last:border-b-0">
                <div className="px-3.5 py-1.5 bg-[color:var(--bg-0)]">
                  <span className="text-[10px] font-semibold text-[color:var(--text-3)] uppercase tracking-[0.06em] font-mono-tabular">
                    #{idx + 1}
                  </span>
                </div>
                {Object.entries(item).map(([key, value]) => {
                  const type = inferType(value);
                  return (
                    <ReadOnlyFieldRow key={key} fieldKey={key} value={value} type={type} />
                  );
                })}
              </div>
            ))
          )
        )}

        {!isArray && section.Name === 'rateLimits' && section.Editable && (
          <RateLimitsEditor
            value={normalizeRateLimits(draft, service)}
            dirtyKeys={dirtyKeys}
            onChange={(next) => setDraft(next)}
          />
        )}

        {/* Regular object fields */}
        {!isArray && section.Name !== 'rateLimits' && (hasManyBooleans ? nonBooleanFields : fieldEntries).map(([key]) => {
          const originalValue = originalFields[key];
          const currentValue = draft[key];
          const type = inferType(originalValue);

          if (type === 'null') {
            return (
              <FieldRow key={key} fieldKey={key} dirty={dirtyKeys.includes(key)}>
                <span className="text-xs text-[color:var(--text-3)] font-mono-tabular italic">null</span>
              </FieldRow>
            );
          }

          if (type === 'string[]') {
            const arr = currentValue as string[];
            if (!section.Editable) {
              return (
                <ReadOnlyFieldRow key={key} fieldKey={key} value={originalValue} type={type} />
              );
            }
            return (
              <FieldRow key={key} fieldKey={key} dirty={dirtyKeys.includes(key)}>
                <input
                  type="text"
                  value={arr.join(', ')}
                  onChange={(e) => {
                    const parts = e.target.value.split(',').map((s) => s.trim()).filter(Boolean);
                    updateField(key, parts);
                  }}
                  placeholder="comma-separated values"
                  className={cn(
                    'w-full px-3 py-1.5 text-xs rounded-md border',
                    'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
                    'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
                    'placeholder:text-[color:var(--text-3)] placeholder:italic',
                    dirtyKeys.includes(key)
                      ? 'border-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.5)]'
                      : 'border-[color:var(--border)]',
                  )}
                />
              </FieldRow>
            );
          }

          if (type === 'object') {
            return (
              <FieldRow key={key} fieldKey={key} dirty={dirtyKeys.includes(key)}>
                <span className="text-xs text-[color:var(--text-3)] font-mono-tabular italic">
                  {JSON.stringify(currentValue)}
                </span>
              </FieldRow>
            );
          }

          if (!section.Editable) {
            return (
              <ReadOnlyFieldRow
                key={key}
                fieldKey={key}
                value={originalValue}
                type={type}
              />
            );
          }

          if (type === 'boolean' && !hasManyBooleans) {
            return (
              <FieldRow key={key} fieldKey={key} dirty={dirtyKeys.includes(key)}>
                <ToggleSwitch
                  checked={currentValue as boolean}
                  onChange={(v) => updateField(key, v)}
                />
              </FieldRow>
            );
          }

          if (type === 'number') {
            return (
              <FieldRow key={key} fieldKey={key} dirty={dirtyKeys.includes(key)}>
                <input
                  type="number"
                  value={currentValue as number}
                  onChange={(e) => {
                    const v = Number(e.target.value);
                    if (!Number.isNaN(v)) updateField(key, v);
                  }}
                  className={cn(
                    'max-w-[120px] px-3 py-1.5 text-xs rounded-md border',
                    'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
                    'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
                    dirtyKeys.includes(key)
                      ? 'border-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.5)]'
                      : 'border-[color:var(--border)]',
                  )}
                />
              </FieldRow>
            );
          }

          return (
            <FieldRow key={key} fieldKey={key} dirty={dirtyKeys.includes(key)}>
              <input
                type="text"
                value={currentValue as string}
                onChange={(e) => updateField(key, e.target.value)}
                placeholder={currentValue === '' ? 'not set' : undefined}
                className={cn(
                  'w-full px-3 py-1.5 text-xs rounded-md border',
                  'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
                  'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
                  'placeholder:text-[color:var(--text-3)] placeholder:italic',
                  dirtyKeys.includes(key)
                    ? 'border-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.5)]'
                    : 'border-[color:var(--border)]',
                )}
              />
            </FieldRow>
          );
        })}

        {/* Compact boolean grid for sections with many boolean flags */}
        {!isArray && hasManyBooleans && booleanFields.length > 0 && (
          <>
            <div className="h-px bg-[color:var(--border)]" />
            <div className="px-3.5 py-3">
              <p className="text-[11px] font-semibold text-[color:var(--text-3)] uppercase tracking-[0.06em] mb-2.5 font-mono-tabular">
                Feature Toggles
              </p>
              <div className="grid grid-cols-2 gap-2">
                {booleanFields.map(([key]) => (
                  <div
                    key={key}
                    className="flex items-center gap-2.5 px-3 py-2 rounded-md bg-[color:var(--bg-2)] border border-[color:var(--border)] hover:border-[color:var(--border-strong)] transition-colors"
                  >
                    <span className="text-xs font-medium text-[color:var(--text-1)] font-mono-tabular flex-1 flex items-center gap-1.5">
                      {key}
                      <FieldHelpIcon fieldKey={key} />
                    </span>
                    <ToggleSwitch
                      checked={draft[key] as boolean}
                      onChange={(v) => updateField(key, v)}
                    />
                  </div>
                ))}
              </div>
            </div>
          </>
        )}

        {err && (
          <div className="px-3 pb-3">
            <p
              role="alert"
              className="text-xs text-[color:var(--danger)] bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.08)] px-3 py-1.5 rounded-md"
            >
              {err}
            </p>
          </div>
        )}
      </div>}
    </section>
  );
}

function FieldHelpIcon({ fieldKey }: { fieldKey: string }) {
  const help = FIELD_HELP[fieldKey];
  const ref = useRef<HTMLSpanElement>(null);
  const [pos, setPos] = useState<{ x: number; y: number; flip: boolean } | null>(null);

  if (!help) return null;

  const TOOLTIP_W = 260;
  const EDGE_PAD = 8;
  const GAP = 6;

  const show = () => {
    const rect = ref.current?.getBoundingClientRect();
    if (rect) {
      let left = rect.right + 8;
      const rightEdge = left + TOOLTIP_W;
      if (rightEdge > window.innerWidth - EDGE_PAD) {
        left = window.innerWidth - EDGE_PAD - TOOLTIP_W;
      }
      setPos({
        x: left,
        y: rect.top + rect.height / 2,
        flip: false,
      });
    }
  };

  return (
    <span
      ref={ref}
      className="shrink-0"
      onMouseEnter={show}
      onMouseLeave={() => setPos(null)}
    >
      <svg
        className="w-3.5 h-3.5 text-[color:var(--text-3)] hover:text-[color:var(--signal)] cursor-help transition-colors"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <circle cx="12" cy="12" r="10" />
        <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
        <line x1="12" y1="17" x2="12.01" y2="17" />
      </svg>
      {pos && createPortal(
        <span
          className="fixed px-3 py-2 text-[11px] leading-relaxed text-[color:var(--text-1)] bg-[color:var(--bg-0)] border border-[color:var(--border)] rounded-md shadow-lg pointer-events-none"
          style={{
            left: `${pos.x}px`,
            top: `${pos.y}px`,
            width: TOOLTIP_W,
            transform: 'translateY(-50%)',
            zIndex: 9999,
          }}
        >
          {help}
        </span>,
        document.body,
      )}
    </span>
  );
}

function RateLimitsEditor({
  value,
  dirtyKeys,
  onChange,
}: {
  value: Record<string, RateLimitDraft>;
  dirtyKeys: string[];
  onChange: (value: Record<string, RateLimitDraft>) => void;
}) {
  const updateLimit = (
    limitName: string,
    field: keyof RateLimitDraft,
    nextValue: number,
  ) => {
    onChange({
      ...value,
      [limitName]: {
        ...value[limitName],
        [field]: nextValue,
      },
    });
  };

  const limitEntries = RATE_LIMIT_ORDER
    .filter((name) => value[name])
    .map((name) => [name, value[name]] as const);

  if (limitEntries.length === 0) {
    return (
      <div className="px-3.5 py-4 text-xs text-[color:var(--text-3)] italic">
        No rate limits configured.
      </div>
    );
  }

  return (
    <div className="divide-y divide-[color:var(--border)]">
      {limitEntries.map(([name, limit]) => {
        const dirty = dirtyKeys.includes(name) || dirtyKeys.includes(name[0].toUpperCase() + name.slice(1));
        return (
          <div
            key={name}
            className={cn(
              'px-3.5 py-3',
              dirty && 'border-l-[3px] border-l-[color:var(--warning)] pl-[11px] bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.03)]',
            )}
          >
            <div className="flex items-center gap-2 mb-2">
              <h3 className="text-xs font-semibold text-[color:var(--text-1)] font-mono-tabular">
                {name}
              </h3>
              {dirty && (
                <span className="px-1.5 py-0.5 rounded text-[10px] bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.12)] text-[color:var(--warning)]">
                  changed
                </span>
              )}
            </div>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
              <RateLimitNumberInput
                label={`${name} burst`}
                fieldKey="burst"
                value={limit.burst}
                onChange={(next) => updateLimit(name, 'burst', next)}
              />
              <RateLimitDurationInput
                label={`${name} period`}
                fieldKey="period"
                value={limit.period}
                onChange={(next) => updateLimit(name, 'period', next)}
              />
              <RateLimitDurationInput
                label={`${name} evictAfter`}
                fieldKey="evictAfter"
                value={limit.evictAfter}
                onChange={(next) => updateLimit(name, 'evictAfter', next)}
              />
              <RateLimitNumberInput
                label={`${name} retryAfter`}
                fieldKey="retryAfter"
                value={limit.retryAfter}
                onChange={(next) => updateLimit(name, 'retryAfter', next)}
              />
              <RateLimitNumberInput
                label={`${name} maxBuckets`}
                fieldKey="maxBuckets"
                value={limit.maxBuckets}
                onChange={(next) => updateLimit(name, 'maxBuckets', next)}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function RateLimitNumberInput({
  label,
  fieldKey,
  value,
  onChange,
}: {
  label: string;
  fieldKey: keyof RateLimitDraft;
  value: number;
  onChange: (value: number) => void;
}) {
  return (
    <label className="flex flex-col gap-1 min-w-0">
      <span className="text-[10px] font-semibold text-[color:var(--text-3)] uppercase tracking-[0.04em] flex items-center gap-1">
        {fieldKey}
        <FieldHelpIcon fieldKey={fieldKey} />
      </span>
      <input
        aria-label={label}
        type="number"
        min={0}
        value={value}
        onChange={(e) => {
          const next = Number(e.target.value);
          if (Number.isFinite(next)) onChange(next);
        }}
        className={cn(
          'w-full px-2 py-1.5 text-xs rounded-md border border-[color:var(--border)]',
          'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
          'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
        )}
      />
    </label>
  );
}

function RateLimitDurationInput({
  label,
  fieldKey,
  value,
  onChange,
}: {
  label: string;
  fieldKey: keyof RateLimitDraft;
  value: number;
  onChange: (value: number) => void;
}) {
  const [raw, setRaw] = useState(() => formatDuration(value));

  useEffect(() => {
    setRaw(formatDuration(value));
  }, [value]);

  const parsed = parseDuration(raw);
  const invalid = parsed === null;

  return (
    <label className="flex flex-col gap-1 min-w-0">
      <span className="text-[10px] font-semibold text-[color:var(--text-3)] uppercase tracking-[0.04em] flex items-center gap-1">
        {fieldKey}
        <FieldHelpIcon fieldKey={fieldKey} />
      </span>
      <input
        aria-label={label}
        type="text"
        value={raw}
        onChange={(e) => {
          const nextRaw = e.target.value;
          setRaw(nextRaw);
          const next = parseDuration(nextRaw);
          if (next !== null) onChange(next);
        }}
        className={cn(
          'w-full px-2 py-1.5 text-xs rounded-md border',
          'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
          'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
          invalid ? 'border-[color:var(--danger)]' : 'border-[color:var(--border)]',
        )}
      />
    </label>
  );
}

function FieldRow({
  fieldKey,
  dirty,
  children,
}: {
  fieldKey: string;
  dirty: boolean;
  children: React.ReactNode;
}) {
  return (
    <div
      className={cn(
        'flex items-center min-h-[44px] px-3.5 gap-3 border-b border-[color:var(--border)] last:border-b-0',
        dirty && 'border-l-[3px] border-l-[color:var(--warning)] pl-[11px] bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.03)]',
      )}
    >
      <div className="flex items-center gap-2 w-[200px] min-w-[200px] shrink-0">
        <span className="text-xs font-medium text-[color:var(--text-1)] font-mono-tabular">{fieldKey}</span>
        <FieldHelpIcon fieldKey={fieldKey} />
      </div>
      <div className="flex-1 flex items-center min-w-0">
        {children}
      </div>
    </div>
  );
}

function ReadOnlyFieldRow({
  fieldKey,
  value,
  type,
}: {
  fieldKey: string;
  value: unknown;
  type: FieldType;
}) {
  const [revealed, setRevealed] = useState(false);
  const sensitive = isSensitive(fieldKey);

  if (type === 'string[]') {
    const arr = Array.isArray(value) ? (value as string[]) : [];
    return (
      <div className="flex items-center min-h-[44px] px-3.5 gap-3 border-b border-[color:var(--border)] last:border-b-0">
        <div className="flex items-center gap-2 w-[200px] min-w-[200px] shrink-0">
          <span className="text-xs font-medium text-[color:var(--text-1)] font-mono-tabular">{fieldKey}</span>
          <FieldHelpIcon fieldKey={fieldKey} />
        </div>
        <div className="flex-1 flex items-center min-w-0 gap-1.5 flex-wrap py-1.5">
          {arr.length === 0 ? (
            <span className="text-xs text-[color:var(--text-3)] font-mono-tabular italic">empty</span>
          ) : (
            arr.map((item, i) => (
              <span
                key={i}
                className="px-1.5 py-0.5 rounded text-[11px] font-mono-tabular bg-[color:var(--bg-2)] text-[color:var(--text-2)] border border-[color:var(--border)]"
              >
                {item}
              </span>
            ))
          )}
        </div>
      </div>
    );
  }

  const displayValue = type === 'boolean'
    ? (value ? 'true' : 'false')
    : String(value ?? '');

  return (
    <div className="flex items-center min-h-[44px] px-3.5 gap-3 border-b border-[color:var(--border)] last:border-b-0">
      <div className="flex items-center gap-2 w-[200px] min-w-[200px] shrink-0">
        <span className="text-xs font-medium text-[color:var(--text-1)] font-mono-tabular">{fieldKey}</span>
        <FieldHelpIcon fieldKey={fieldKey} />
      </div>
      <div className="flex-1 flex items-center min-w-0">
        {sensitive ? (
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-[color:var(--text-2)] font-mono-tabular">
              {revealed
                ? (displayValue || <span className="text-[color:var(--text-3)] italic">empty</span>)
                : '●●●●●●'}
            </span>
            <button
              type="button"
              onClick={() => setRevealed((r) => !r)}
              className="inline-flex items-center justify-center w-7 h-7 rounded border border-[color:var(--border)] bg-[color:var(--bg-2)] text-[color:var(--text-3)] hover:text-[color:var(--text-1)] hover:border-[color:var(--border-strong)] transition-colors shrink-0"
              title={revealed ? 'Hide' : 'Reveal'}
            >
              {revealed ? (
                <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
                  <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
                  <path d="M14.12 14.12a3 3 0 1 1-4.24-4.24" />
                  <line x1="1" y1="1" x2="23" y2="23" />
                </svg>
              ) : (
                <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
              )}
            </button>
          </div>
        ) : (
          <span className="text-xs text-[color:var(--text-2)] font-mono-tabular py-1.5">
            {displayValue || <span className="text-[color:var(--text-3)] italic">empty</span>}
          </span>
        )}
      </div>
    </div>
  );
}

function ToggleSwitch({
  checked,
  onChange,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
}) {
  return (
    <div className="flex items-center gap-2.5">
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={cn(
          'relative w-9 h-5 rounded-full border transition-colors shrink-0',
          checked
            ? 'bg-[color:var(--signal-deep)] border-[color:var(--signal)]'
            : 'bg-[color:var(--bg-3)] border-[color:var(--border)]',
        )}
      >
        <span
          className={cn(
            'absolute top-0.5 left-0.5 w-3.5 h-3.5 rounded-full transition-transform',
            checked
              ? 'translate-x-4 bg-[color:var(--signal)]'
              : 'translate-x-0 bg-[color:var(--text-3)]',
          )}
        />
      </button>
      <span
        className={cn(
          'text-[11px]',
          checked ? 'text-[color:var(--signal)]' : 'text-[color:var(--text-3)]',
        )}
      >
        {checked ? 'enabled' : 'disabled'}
      </span>
    </div>
  );
}

export default ServiceConfigPage;

function ApplyConfirmDialog({
  pendingSections,
  isPending,
  onConfirm,
  onCancel,
}: {
  pendingSections: ServiceConfig[];
  isPending: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <ModalShell
      title="Apply & Restart"
      titleId="apply-confirm-title"
      onClose={onCancel}
      panelClassName="max-w-md"
    >
      <div className="space-y-4">
        <p className="text-sm text-[color:var(--text-1)]">
          This will restart the osctrl-api service to apply the following
          configuration changes. The service will be briefly unavailable.
        </p>
        <div className="rounded-md border border-[color:var(--border)] bg-[color:var(--bg-0)] p-3">
          <p className="text-[10px] uppercase tracking-[0.08em] text-[color:var(--text-3)] mb-2">
            Pending changes ({pendingSections.length})
          </p>
          <ul className="space-y-1">
            {pendingSections.map((s) => (
              <li
                key={s.ID}
                className="flex items-center gap-2 text-xs text-[color:var(--text-2)]"
              >
                <span className="font-mono-tabular text-[color:var(--text-1)]">
                  {s.Name}
                </span>
                {s.Info && (
                  <span className="text-[color:var(--text-3)] truncate">
                    — {s.Info}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>
        <div className="flex items-center justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onCancel}
            disabled={isPending}
            className="px-3 py-1.5 text-xs font-medium rounded border border-[color:var(--border)] text-[color:var(--text-2)] hover:bg-[color:var(--bg-2)] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={isPending}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded transition-colors',
              'bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.16)] text-[color:var(--warning)]',
              'hover:bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.24)]',
              'disabled:opacity-40 disabled:cursor-not-allowed',
            )}
          >
            {isPending ? 'Restarting…' : 'Restart now'}
          </button>
        </div>
      </div>
    </ModalShell>
  );
}
