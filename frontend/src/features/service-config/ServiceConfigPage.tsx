import { useState, useEffect, useCallback, useMemo, useRef, useContext, useLayoutEffect, createContext } from 'react';
import { createPortal } from 'react-dom';
import { usePageTitle } from '$/lib/usePageTitle';
import { useParams, useNavigate, Link } from '@tanstack/react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  listServiceConfig,
  updateServiceConfig,
  applyServiceConfig,
  getServiceCommand,
  getServiceConfigStatus,
  persistServiceConfig,
  type ServiceConfig,
} from '$/api/service-config';
import { getFeatures } from '$/api/features';
import { AuthError, ApiError } from '$/api/client';
import { cn } from '$/lib/cn';
import { Skeleton } from '$/components/data/Skeleton';
import { EmptyState } from '$/components/data/EmptyState';
import { ModalShell } from '$/components/feedback/ModalShell';
import { formatRelative } from '$/lib/time';

const SERVICES = ['api', 'tls'] as const;
type Service = (typeof SERVICES)[number];

// Acknowledged per browser session, not permanently: every fresh visit should
// see the warning again, but switching between the api/tls tabs should not
// re-ask.
const WARNING_ACK_KEY = 'osctrl.service-config.warning-ack';

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

// Keys come in three shapes, resolved most-specific first by resolveScoped():
//   `${service}:${section}.${field}` -> `${section}.${field}` -> `${field}`
// The scoped keys carry the text from the annotated sample YAML (deploy/config/{api,tls}.yml);
// the bare keys are the hand-written generic fallbacks for fields the YAML does not annotate.
const FIELD_HELP: Record<string, string> = {
  // --- YAML-annotated: service section
  'api:service.Auth': 'Valid values: "jwt", "none". `none` requires OSCTRL_INSECURE_NO_AUTH=1 in the environment and is intended for local-dev only — it impersonates super-admin on every request. Production deployments MUST use `jwt`.',
  'tls:service.Auth': 'Valid value: "none". osquery authentication uses enroll secrets and node_key; osctrl-tls refuses to start with any other value (validAuth in pkg/config/validation.go).',
  'api:service.AuditLog': 'Write security-relevant API actions to audit_logs.',
  'tls:service.AuditLog': 'Write security-relevant TLS activity, such as enroll failures, to audit_logs.',
  'api:service.TrustedProxies': "Comma-separated CIDR list whose X-Real-IP / X-Forwarded-For headers utils.GetIP will trust. Leave empty (default) when osctrl-api is directly internet-facing — forwarding headers are then ignored and RemoteAddr is used verbatim, preventing header-spoofed rate-limit bypass and audit-log poisoning. Set to your edge proxy's CIDR(s) when osctrl-api sits behind a trusted reverse proxy (e.g. `10.0.0.0/8` or `192.0.2.1/32,2001:db8::/64`).",
  'tls:service.TrustedProxies': 'Comma-separated CIDR list whose X-Real-IP / X-Forwarded-For headers utils.GetIP will trust. osctrl-tls is typically internet-facing for osquery node enrollment; keep empty unless you operate it behind a trusted reverse proxy that forwards client IPs. Empty (default) prevents header-spoofed enroll-rate-limit bypass and audit-log poisoning.',
  'api:service.GeoIPDBPath': 'Path to a MaxMind GeoLite2-Country .mmdb file. When set, node IP addresses are resolved to ISO 3166-1 alpha-2 country codes and included in the node API response (shown as flag emojis in the SPA nodes table and node detail page). Empty (default) disables GeoIP entirely — no lookups, no country codes, no overhead. Download the free database from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data — update weekly for best accuracy. Example: /data/GeoLite2-Country.mmdb',
  'tls:service.GeoIPDBPath': 'Path to a MaxMind GeoLite2-Country .mmdb file. Currently consumed by osctrl-api node responses; kept here so the shared service section is complete across sample configs. Empty disables GeoIP.',
  'api:service.ServiceConfigEnabled': 'Master switch for this page and the /api/v1/service-config endpoints. It does not change how configuration loads: every boot seeds the YAML sections into the service_config table and resolves those rows back, so the services always run on the stored values. Turning it off and restarting removes the endpoints and hides this section — values can then only be changed in the database rows or the YAML file, and are picked up on the next restart.',
  'tls:service.ServiceConfigEnabled': 'Only osctrl-api serves the service-config endpoints, so this value is inert for osctrl-tls — it is kept so the service section round-trips unchanged. osctrl-tls seeds its YAML sections into the service_config table and resolves those rows at startup either way.',
  'api:service.MFARequired': 'Require a second authentication factor for password logins. When true, a user without one is sent through authenticator-app enrollment at their next login rather than being locked out — no session is issued until a factor exists and is proven. Service accounts authenticate with a token and are exempt; federated logins are governed by the identity provider. Users can enroll voluntarily from their profile whether or not this is set.',
  'tls:service.MFARequired': 'Inert for osctrl-tls — osctrl-api owns the interactive login. Kept so the service section round-trips unchanged.',
  'service.MFAIssuer': 'Label authenticator apps show next to the account, and the name shown in the WebAuthn prompt. Empty falls back to "osctrl (<host>)". Changing it does not invalidate existing enrollments; apps keep the old label until the user re-enrolls.',
  'service.MFARPID': 'WebAuthn Relying Party ID: the registrable domain passkeys and security keys are bound to, with no scheme or port. Empty uses the service host. Changing it invalidates every credential already registered — users would have to register their keys again.',
  'service.MFAOrigins': 'Comma-separated origins the SPA is served from, including scheme and any non-default port (https://osctrl.example.com). Empty uses https://<rp id>. The browser refuses a WebAuthn ceremony whose origin is not in this list, so it has to match the URL users actually visit.',
  'api:service.PostureEnabled': 'Enable the security & compliance posture system. When false (default), posture API endpoints are not registered and the SPA hides posture controls. When true, the API serves posture data from the shared database (collected by osctrl-tls).',
  'tls:service.PostureEnabled': 'Enable the security & compliance posture system. When false (default), no posture data is collected, no posture API endpoints are available, and the posture tab is hidden in the SPA. When true, result logs from posture-prefixed scheduled queries are ingested and stored per node.',
  'api:service.PostureQueryPrefix': 'Only used by osctrl-tls for ingestion; kept here so the service configuration shape is complete and can round-trip through the API.',
  'tls:service.PostureQueryPrefix': 'Prefix for scheduled query names whose results are ingested as node posture data (security & compliance). Queries in the osquery schedule named e.g. "osctrl:posture:packages" will have their results stored as the "packages" posture category. Only used when postureEnabled is true.',
  'api:service.DBHealthCheck': 'DB health monitor. When enabled, osctrl-api pings the database every dbHealthInterval seconds. After dbHealthThreshold consecutive failures, EnvCache switches to stale-serve mode: cached entries are served on DB miss instead of returning 500, and TTLs are extended to ~60m so cached envs stay warm for the duration of the outage. This keeps the API responding to read-only env lookups during a DB outage. Write paths still require the DB and will fail. The stale-serve window is bounded at 60m so rotated enroll secrets are not accepted indefinitely. Disabled by default; enable in production where DB blips are expected and API availability for read paths is prioritized.',
  'tls:service.DBHealthCheck': 'DB health monitor. When enabled, osctrl-tls pings the database every dbHealthInterval seconds. After dbHealthThreshold consecutive failures, EnvCache and SettingsCache switch to stale-serve mode: cached entries are served on DB miss instead of returning 500, and TTLs are extended to ~60m so cached envs/settings stay warm for the duration of the outage. This keeps osquery nodes that already have a cached env row receiving config/log/query responses during a DB outage. The stale-serve window is bounded at 60m so rotated enroll secrets are not accepted indefinitely. Disabled by default; enable in production where DB blips are expected and osquery fleet stability is prioritized.',
  'api:service.DBHealthThreshold': 'Consecutive failures before EnvCache enters stale-serve mode.',
  'tls:service.DBHealthThreshold': 'Consecutive failures before caches enter stale-serve mode.',
  // --- YAML-annotated: osquery section
  'api:osquery.Version': 'osquery schema version shown to query-building UI.',
  'tls:osquery.Version': 'osquery schema version used for table metadata.',
  'osquery.TablesFile': 'JSON schema file with osquery table metadata.',
  'api:osquery.Logger': 'Whether osquery log endpoints/features are enabled.',
  'tls:osquery.Logger': 'Enables POST /{env}/log.',
  'api:osquery.Config': 'Whether remote config management is enabled.',
  'tls:osquery.Config': 'Enables POST /{env}/config.',
  'api:osquery.Query': 'Whether distributed query APIs are enabled.',
  'tls:osquery.Query': 'Enables distributed query read/write endpoints.',
  'api:osquery.Carve': 'Whether file carve APIs are enabled.',
  'tls:osquery.Carve': 'Enables file carve init/block endpoints.',
  'api:osquery.Accelerated': 'Whether accelerated query polling features are enabled.',
  'tls:osquery.Accelerated': 'Allows accelerated query polling responses.',
  'api:osquery.FileExplorer': 'Enables accelerated file explorer routes when query and accelerated are also true.',
  'tls:osquery.FileExplorer': 'Enables file explorer query behavior when accelerated/query are also enabled.',
  'api:osquery.ReadOnly': 'Prevents API-driven osquery configuration changes when true.',
  'tls:osquery.ReadOnly': 'Prevents config changes through operator surfaces when true.',
  // --- YAML-annotated: logger / carver / debug
  'logger.Type': 'Valid values: "none", "stdout", "file", "db", "graylog", "splunk", "logstash", "kinesis", "s3", "kafka", "elastic"',
  'logger.Types': 'Optional multi-destination logging/export. Empty uses `type`.',
  'logger.AlwaysLog': 'Also persist status/on-demand query logs in DB even with external exporters.',
  'logger.DB': 'Separate DB destination for log records when loggerDBSame is false. Fields match the top-level db section.',
  'carver.Type': 'Valid values: "local", "db", "s3". ("none" is documented in the sample YAML but rejected at startup.)',
  'debug.ShowBody': 'Include request bodies. May contain secrets or node data.',
  'debug.TargetHostIdentifier': "When non-empty, only dump requests from the osquery node whose UUID (or enroll host_identifier) matches this value (case-insensitive). Empty dumps every request when enableHttp is true. Useful to isolate one host's traffic on a busy server.",
  // --- YAML-annotated: metrics / osctrld
  'metrics.Enabled': 'Enables a separate Prometheus metrics listener.',
  'osctrld.Enabled': 'Enables osctrld flags/cert/verify/script endpoints.',
  // --- YAML-annotated: rate limiters
  'api:rateLimits.login': 'Password and SSO login initiation attempts per client IP.',
  'api:rateLimits.preAuth': 'Read-only pre-auth routes, such as login environment/method discovery.',
  'api:rateLimits.serviceConfigApply': 'POST /api/v1/service-config/apply restart requests.',
  'tls:rateLimits.enroll': 'osquery enroll attempts per client IP.',
  // --- YAML-annotated: SAML
  'saml.Enabled': 'Enables SAML routes when true.',
  'saml.EntityID': 'SP entity ID — what the IdP knows us by, conventionally the metadata URL.',
  'saml.CertPath': 'Legacy SAML certificate path; consumed only by osctrl-admin, ignored by osctrl-api.',
  'saml.KeyPath': 'Legacy SAML private key path; consumed only by osctrl-admin, ignored by osctrl-api.',
  'saml.RootURL': 'Legacy service root URL; consumed only by osctrl-admin, ignored by osctrl-api.',
  'saml.LoginURL': 'Legacy IdP login URL; consumed only by osctrl-admin, ignored by osctrl-api.',
  'saml.SPInitiated': 'Legacy flag from the old admin service; ignored by osctrl-api.',
  'saml.ACSURL': 'Where the IdP POSTs the SAMLResponse; must end with /api/v1/auth/saml/acs',
  'saml.MetaDataURL': 'IdP metadata XML — fetched once at startup for signing certs + SSO endpoint.',
  'saml.LogoutURL': 'IdP session-termination URL (e.g. https://<tenant>.auth0.com/v2/logout). Returned to the SPA on logout so the IdP session dies too; without it the next SSO click silently re-authenticates.',
  'saml.JITProvision': 'Auto-create osctrl users on first login, as non-admin.',
  'saml.UsernameAttribute': 'Attribute (Name or FriendlyName) whose value becomes the osctrl username. Empty = use the NameID verbatim. Usernames must match ^[a-zA-Z0-9_-]{1,64}$, so email-format NameIDs are rejected — point this at a short handle instead.',
  'saml.SigningCertPath': 'PEM cert + RSA key for signing outbound AuthnRequests. Both must be set to enable signing; some IdPs require it and all should support it.',
  'saml.SigningKeyPath': 'PEM cert + RSA key for signing outbound AuthnRequests. Both must be set to enable signing; some IdPs require it and all should support it.',
  'saml.ForceAuthn': 'Force re-authentication at the IdP on every login. Defaults true — it is the substitute for SAML SLO, which is not implemented yet.',
  // --- YAML-annotated: OIDC
  'oidc.Enabled': 'Enables OIDC routes when true.',
  'oidc.IssuerURL': 'Realm root — /.well-known/openid-configuration is appended automatically.',
  'oidc.RedirectURL': 'Must match the IdP client config and end with /api/v1/auth/oidc/callback',
  'oidc.Scopes': 'Empty defaults to [openid, profile, email].',
  'oidc.UsernameClaim': "Empty defaults to preferred_username. Same charset rule as SAML applies, so `email` and Auth0's `sub` will be rejected — use `nickname` there.",
  'oidc.GroupsClaim': 'Empty defaults to `groups`.',
  'oidc.RequiredGroups': 'Login is denied unless the user belongs to at least one of these. Empty disables the group gate.',
  'oidc.JITProvision': 'Auto-create osctrl users on first login, as non-admin.',
  'oidc.UsePKCE': 'PKCE (S256) for the authorization code flow.',
  // --- Section-scoped disambiguation for names that mean different things per section
  'service.Host': 'Public hostname of this service, used to build URLs handed to nodes and clients.',
  'db.Host': 'Database server hostname or IP address.',
  'redis.Host': 'Redis server hostname or IP address.',
  'db.Port': 'TCP port of the database server.',
  'redis.Port': 'TCP port of the Redis server.',
  'db.Type': 'Database engine: postgres, mysql or sqlite. Unknown values silently fall back to postgres.',
  'db.ConnRetry': 'Seconds to keep retrying the DB connection at startup; 0 fails fast.',
  'redis.ConnRetry': 'Seconds to keep retrying the Redis connection at startup; 0 fails fast.',
  // Service
  Listener: 'Network interface to bind to (e.g. 0.0.0.0 for all interfaces, 127.0.0.1 for localhost only).',
  Port: 'TCP port the service listens on.',
  LogLevel: 'Minimum log level: debug, info, warn, or error.',
  LogFormat: 'Log output format: console (human-readable) or json (structured).',
  DBHealthInterval: 'Seconds between DB health pings. Only used when DBHealthCheck is true.',
  // DB
  Name: 'Database name to connect to.',
  Username: 'Database username for authentication.',
  Password: 'Database password or service secret.',
  SSLMode: 'PostgreSQL SSL mode (e.g. disable, require, verify-full).',
  FilePath: 'File path (SQLite database or local log file).',
  MaxIdleConns: 'Maximum idle connections in the pool.',
  MaxOpenConns: 'Maximum open connections to the database.',
  ConnMaxLifetime: 'Maximum lifetime of a connection in seconds.',
  // Redis
  ConnectionString: 'Full Redis connection string. When set, overrides Host/Port/Password.',
  DB: 'Redis database index (0–15).',
  // Debug
  EnableHTTP: 'When true, dumps HTTP requests to the debug file.',
  HTTPFile: 'File path where HTTP debug dumps are written.',
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
  // OIDC
  ClientID: 'OAuth2 client ID registered with the OIDC provider.',
  ClientSecret: 'OAuth2 client secret.',
  // Logger
  LoggerDBSame: 'Use the same DB connection for logging (no separate logger DB).',
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

// Same key shapes as FIELD_HELP. Values are the exact lowercase strings the Go side compares against.
// Only editable sections reach the select branch, so read-only sections (db, logger, carver) get no entries.
const FIELD_ENUMS: Record<string, readonly string[]> = {
  'service.LogLevel': ['debug', 'info', 'warn', 'error'],
  'service.LogFormat': ['json', 'console'],
  'api:service.Auth': ['jwt', 'none'],
  // osctrl-tls refuses to boot on anything but "none" (validAuth in pkg/config/validation.go).
  'tls:service.Auth': ['none'],
};

function resolveScoped<T>(
  map: Record<string, T>,
  service: string,
  section: string,
  field: string,
): T | undefined {
  return map[`${service}:${section}.${field}`] ?? map[`${section}.${field}`] ?? map[field];
}

// What each section is for, transcribed from the section header comments in
// deploy/config/{api,tls}.yml. Keyed `${service}:${section}` where the two
// sample files describe the section differently, bare `${section}` where they agree.
const SECTION_HELP: Record<string, string> = {
  service: 'Main HTTP service behavior and shared service-level features.',
  'api:db': 'Database configuration. This is the primary source of truth for API state.',
  'tls:db': 'Database configuration. This is the primary source of truth for fleet state.',
  batchWriter: 'Batch writer configuration for coalescing node last-seen updates.',
  'api:redis': 'Redis cache configuration. Used for env cache, activity tiles, and query cache.',
  'tls:redis': 'Redis cache configuration. Used for env/settings caches, query cache, and activity.',
  rateLimits: 'HTTP request rate limits. Values match the built-in defaults.',
  'api:osquery': 'osquery feature switches used by API handlers and the frontend feature API.',
  'tls:osquery': 'osquery remote API feature switches.',
  configEndpoints:
    'Optional config endpoint fan-out. Entries contain shared secrets, so leave empty unless osctrl-tls should POST generated configs to another endpoint.',
  osctrld: 'osctrld endpoint configuration.',
  metrics: 'Metrics configuration (Prometheus).',
  'api:tls': 'TLS termination configuration for serving HTTPS directly from osctrl-api.',
  'tls:tls': 'TLS termination configuration for serving HTTPS directly from osctrl-tls.',
  saml: 'SAML 2.0 federated login. Disabled by default; when enabled the API fetches the IdP metadata at startup and REFUSES TO START if that fails, rather than serving a login page with a broken SSO button. The SPA discovers this via GET /api/v1/auth/methods and renders a "Continue with SAML" button automatically — no frontend rebuild needed. Register osctrl with the IdP by pointing it at the SP metadata URL: https://<host>/api/v1/auth/saml/metadata. Note: certPath, keyPath, rootUrl, loginUrl and spInitiated are legacy fields consumed only by osctrl-admin; osctrl-api ignores them. See docs/auth-providers.md for per-IdP walkthroughs.',
  oidc: 'OIDC federated login. Same posture as SAML: disabled by default, fail-fast on discovery errors at startup, advertised to the SPA through /api/v1/auth/methods. Both protocols can be enabled at the same time.',
  jwt: 'JWT authentication configuration. Used for API bearer tokens and SPA cookies.',
  logger: 'Logger configuration to handle received logs from osquery nodes.',
  carver: 'Carver configuration to handle file carves from osquery nodes.',
  debug: 'Debug configuration for dumping incoming HTTP requests. Use only temporarily.',
};

// One glyph per section so cards are told apart at a glance while scrolling.
// Path data only — rendered by <SectionIcon> in the house 24x24 stroke style.
const SECTION_ICONS: Record<string, string> = {
  service: 'M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01',
  db: 'M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3zM4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3',
  batchWriter: 'M3 6h18M3 12h18M3 18h10',
  redis: 'M12 3l9 5-9 5-9-5 9-5zM3 13l9 5 9-5M3 17l9 4 9-4',
  rateLimits: 'M12 21a9 9 0 1 0-9-9M12 7v5l3 2M3 12H1M12 3V1',
  // The osquery brand mark: four blades pinwheeling around an empty diamond.
  // Geometry taken from the osquery icon font that shipped with the removed
  // osctrl-admin (cmd/admin/static/fonts/osquery.svg), redrawn on a clean
  // lattice — the original is a 40KB bitmap trace.
  osquery: 'M12 7 7 7 2 12 7 12ZM7 12 7 17 12 22 12 17ZM12 17 17 17 22 12 17 12ZM17 12 17 7 12 2 12 7Z',
  configEndpoints: 'M4 7h6M14 7h6M8 3v8M4 17h16M8 13v8',
  // The osctrl brand mark: control tower + broadcast waves, with the deck windows
  // cut back in (the silhouette in public/img/osctrl-mark.svg drops them). Path data
  // is that file, with its translate/scale baked into the 24x24 box via svgo.
  osctrld:
    'M10.836.42C8.796.654 6.96 1.446 5.358 2.778c-.306.258-.558.498-.558.54s.162.234.354.426l.354.354.324-.3c1.29-1.2 2.934-1.974 4.836-2.274.774-.12 2.31-.084 3.006.066 1.68.372 3.042 1.038 4.29 2.1l.468.408.372-.372.366-.372-.36-.336C17.43 1.74 15.552.822 13.65.504 12.984.396 11.472.348 10.836.42M10.71 3.27a7.1 7.1 0 0 0-2.574 1.008c-.576.378-1.296.978-1.296 1.08 0 .042.162.234.354.426l.36.354.354-.324a6.2 6.2 0 0 1 2.394-1.35c.648-.192 1.908-.264 2.646-.144 1.152.186 2.262.738 3.18 1.584l.258.24.372-.378.372-.372-.33-.306a7.33 7.33 0 0 0-3.654-1.818c-.606-.108-1.854-.108-2.436 0M11.04 6.036c-.576.126-1.308.516-1.764.936-.216.198-.396.39-.396.432 0 .036.162.228.36.426l.36.354.18-.216c.258-.312.846-.684 1.302-.828.528-.162 1.278-.162 1.764 0 .468.162.786.36 1.182.744l.318.306.372-.384.366-.378-.426-.408c-.942-.9-2.304-1.272-3.618-.984m-.438 3.132c-.072.078-.102.258-.114.702l-.018.6-.942.03c-.762.024-.96.048-1.038.126-.054.054-.45.636-.876 1.29-.522.804-.774 1.248-.774 1.362 0 .09.066.3.15.462s.15.306.15.324c0 .012-.204.036-.456.048-.39.018-.474.042-.57.162-.06.078-.114.186-.114.246 0 .15 2.016 4.032 2.142 4.122.054.042.24.078.414.078h.312l.024.744c.024.87.084.996.48.996H9.6v1.524c0 .954.024 1.59.066 1.71.114.324.474.414.702.168.126-.132.132-.192.144-1.752l.018-1.62h2.94l.018 1.62c.012 1.56.018 1.62.144 1.752.228.246.588.156.702-.168.042-.12.066-.756.066-1.71V20.46h.228c.396 0 .456-.126.48-.996l.024-.744h.312c.174 0 .36-.036.414-.078.126-.09 2.142-3.972 2.142-4.122 0-.06-.054-.168-.114-.246-.096-.12-.18-.144-.57-.162-.252-.012-.456-.036-.456-.048 0-.018.066-.162.15-.324s.15-.372.15-.462c0-.114-.252-.558-.774-1.362-.426-.654-.822-1.236-.876-1.29-.072-.078-.27-.102-.948-.126l-.852-.03-.018-.312c-.018-.348-.15-.498-.432-.498-.27 0-.384.138-.42.486l-.03.324h-1.44l-.018-.6c-.018-.69-.084-.81-.432-.81-.138 0-.258.042-.318.108m4.98 3.114c.318.492.588.93.6.984.018.054-.054.264-.156.468l-.186.366H8.16l-.186-.366c-.102-.204-.174-.414-.156-.468.012-.054.282-.492.6-.984L9 11.4h6.006zM14.22 19.17v.45H9.78v-.9h4.44zM7.21 14.99H8.89L10.33 17.87H8.65ZM9.85 14.99H14.24L12.8 17.87H11.29ZM15.2 14.99H16.89L15.44 17.87H13.76Z',
  metrics: 'M4 20V10M10 20V4M16 20v-8M22 20H2',
  tls: 'M7 11V8a5 5 0 0 1 10 0v3M5 11h14v10H5z',
  saml: 'M12 3l8 4v5c0 5-3.4 8.4-8 9-4.6-.6-8-4-8-9V7l8-4zM9 12l2 2 4-4',
  oidc: 'M12 3l8 4v5c0 5-3.4 8.4-8 9-4.6-.6-8-4-8-9V7l8-4zM12 10a1.6 1.6 0 1 0 0 3.2 1.6 1.6 0 0 0 0-3.2zM12 13.2V16',
  jwt: 'M15 7a4 4 0 1 1-3.9 5H7v3H4v-3l3-3h4.1A4 4 0 0 1 15 7z',
  logger: 'M4 4h11l5 5v11H4zM15 4v5h5M8 13h8M8 17h5',
  carver: 'M14 3l7 7-4 4-7-7zM10 7l-7 7v7h7l7-7',
  debug: 'M8 6a4 4 0 0 1 8 0v2H8zM6 12h12v3a6 6 0 0 1-12 0zM3 11h3M18 11h3M4 18l2-1M20 18l-2-1',
};

// Brand marks are solid logos, not line glyphs, so they fill instead of stroke.
// evenodd makes the osctrl deck windows read as holes rather than filled slabs.
const FILLED_ICONS = new Set(['osquery', 'osctrld']);

function SectionIcon({ name }: { name: string }) {
  const d = SECTION_ICONS[name];
  if (!d) return null;
  const filled = FILLED_ICONS.has(name);
  return (
    <svg
      aria-hidden="true"
      className="w-4 h-4 shrink-0 text-[color:var(--text-3)]"
      viewBox="0 0 24 24"
      fill={filled ? 'currentColor' : 'none'}
      fillRule={filled ? 'evenodd' : undefined}
      stroke={filled ? 'none' : 'currentColor'}
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d={d} />
    </svg>
  );
}

const FieldScope = createContext({ service: '', section: '' });

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

  const [showWarning, setShowWarning] = useState(() => {
    try {
      return window.sessionStorage.getItem(WARNING_ACK_KEY) !== '1';
    } catch {
      return true; // sessionStorage blocked — warn anyway
    }
  });
  const [applyErr, setApplyErr] = useState<string | null>(null);
  const [applyFlash, setApplyFlash] = useState(false);
  const [showApplyConfirm, setShowApplyConfirm] = useState(false);
  const [restarting, setRestarting] = useState(false);
  const [restartStatus, setRestartStatus] = useState<string | null>(null);
  const [persisting, setPersisting] = useState(false);
  const [persistFlash, setPersistFlash] = useState(false);
  // Writing to disk flips every section back to source=yaml, which would
  // otherwise hide Apply & Restart — leaving the changes on disk but never
  // picked up by the running service. Keep offering the restart once we have
  // written in this session.
  // ponytail: session-local, so a page reload forgets it. Recording the
  // service's boot time and comparing it against section UpdatedAt would
  // survive reloads, if operators hit this.
  const [persistedThisSession, setPersistedThisSession] = useState(false);
  const qc = useQueryClient();
  // Server-side switch (service.serviceConfigEnabled). When it is off the
  // service-config endpoints are not registered at all, so do not even ask
  // for the sections — explain where the values live instead.
  const { data: features } = useQuery({
    queryKey: ['features'],
    queryFn: () => getFeatures(),
    staleTime: 5 * 60_000,
  });
  const configDisabled = features?.service_config === false;
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
    enabled: !!features?.service_config,
  });

  // Whether the service's own process can write its config file. Only that
  // process can know — osctrl-tls runs elsewhere and reports it at boot.
  const { data: fileStatus } = useQuery({
    queryKey: ['service-config-status', service],
    queryFn: () => getServiceConfigStatus(service),
    staleTime: 30_000,
    enabled: !!features?.service_config,
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
  // Only shout when the service actually reported it cannot write. While the
  // status is still loading or failed to load, fileStatus is undefined — the
  // button stays disabled but stays quiet rather than flashing red.
  const cannotWrite = fileStatus?.file_writable === false;

  // Writing the file does not touch the running service, so there is no
  // restart to wait on. osctrl-api writes inline and returns done; osctrl-tls
  // returns a queued command it consumes on its next poll, so watch the
  // status endpoint until the pending changes clear.
  const persistMutation = useMutation({
    mutationFn: () => persistServiceConfig(service),
    onSuccess: (resp) => {
      setApplyErr(null);
      const done = () => {
        setPersisting(false);
        setPersistFlash(true);
        setPersistedThisSession(true);
        setTimeout(() => setPersistFlash(false), 3000);
        qc.invalidateQueries({ queryKey: ['service-config', service] });
        qc.invalidateQueries({ queryKey: ['service-config-status', service] });
      };
      if (!resp.command) {
        done();
        return;
      }
      setPersisting(true);
      let timeout: ReturnType<typeof setTimeout>;
      const poll = setInterval(() => {
        getServiceConfigStatus(service)
          .then((status) => {
            if (!status.pending_changes) {
              clearInterval(poll);
              clearTimeout(timeout);
              done();
            }
          })
          .catch(() => {});
      }, 2000);
      timeout = setTimeout(() => {
        clearInterval(poll);
        setPersisting(false);
        setApplyErr(`osctrl-${service} did not write its configuration file within 60 seconds.`);
      }, 60_000);
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      setPersisting(false);
      setApplyErr(e instanceof Error ? e.message : 'Write to disk failed');
    },
  });

  const writeBusy = persisting || persistMutation.isPending;

  const applyMutation = useMutation({
    mutationFn: () => applyServiceConfig(service),
    onSuccess: (resp) => {
      setApplyErr(null);
      setApplyFlash(true);
      setRestarting(true);
      // The restart makes the config live, so nothing is left to apply.
      setPersistedThisSession(false);
      setRestartStatus(resp.command?.status ?? null);
      if (service === 'tls' && resp.command?.command_id) {
        const commandID = resp.command.command_id;
        let timeout: ReturnType<typeof setTimeout>;
        const poll = setInterval(() => {
          getServiceCommand(commandID)
            .then((cmd) => {
              setRestartStatus(cmd.status);
              if (cmd.status === 'recovered') {
                clearInterval(poll);
                clearTimeout(timeout);
                setRestarting(false);
                setApplyFlash(false);
                qc.invalidateQueries({ queryKey: ['service-config', service] });
              }
              if (cmd.status === 'expired') {
                clearInterval(poll);
                clearTimeout(timeout);
                setRestarting(false);
                setApplyErr('TLS restart command expired before osctrl-tls consumed it.');
              }
            })
            .catch(() => {});
        }, 2000);
        timeout = setTimeout(() => {
          clearInterval(poll);
          setRestarting(false);
          setApplyErr('TLS restart recovery was not confirmed within 60 seconds.');
        }, 60_000);
        return;
      }
      const poll = setInterval(() => {
        listServiceConfig(service)
          .then(() => {
            clearInterval(poll);
            setRestarting(false);
            setApplyFlash(false);
            setRestartStatus(null);
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
      setRestartStatus(null);
      setApplyErr(e instanceof Error ? e.message : 'Apply failed');
    },
  });

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)] mr-2">
          Service Config
        </h1>
        {(hasPendingChanges || persistedThisSession) && !loading && !hasError && !restarting && (
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
        {hasPendingChanges && !loading && !hasError && !restarting && (
          <>
            <button
              type="button"
              disabled={!fileStatus?.file_writable || writeBusy}
              title={
                fileStatus?.file_writable
                  ? `Write these changes to ${fileStatus.file_path} so they survive a redeploy`
                  : `Cannot write the configuration file${fileStatus?.file_reason ? `: ${fileStatus.file_reason}` : ''}`
              }
              onClick={() => persistMutation.mutate()}
              className={cn(
                'px-3 py-1 text-xs font-medium rounded transition-colors',
                cannotWrite
                  ? 'bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.12)] text-[color:var(--danger)] cursor-not-allowed'
                  : !fileStatus?.file_writable || writeBusy
                    ? 'bg-[color:var(--bg-3)] text-[color:var(--text-3)] cursor-not-allowed'
                    : 'bg-[color:var(--bg-3)] text-[color:var(--text-2)] hover:bg-[color:var(--bg-4)]',
              )}
            >
              {cannotWrite
                ? 'Cannot Write to Disk ✕'
                : writeBusy
                  ? 'Writing…'
                  : persistFlash
                    ? 'Written to disk ✓'
                    : 'Write to Disk'}
            </button>
            {cannotWrite && (
              <span
                aria-live="polite"
                className="text-xs text-[color:var(--danger)]"
              >
                ({fileStatus?.file_reason || 'configuration file is not writable'})
              </span>
            )}
          </>
        )}
        {restarting && (
          <span
            aria-live="polite"
            className="text-xs text-[color:var(--text-3)] font-mono-tabular"
          >
            {service === 'tls' && restartStatus
              ? `osctrl-tls restart ${restartStatus}…`
              : `Restarting — waiting for osctrl-${service}…`}
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
        {configDisabled && (
          <EmptyState
            icon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M7 11V8a5 5 0 0 1 9.5-2M5 11h14v10H5z" />
              </svg>
            }
            title="Service configuration is not available."
            description="osctrl-api runs with service.serviceConfigEnabled = false, so the /api/v1/service-config endpoints are not registered. Each service still seeds its YAML sections into the service_config table and resolves those rows at startup, so values can be changed directly in the database and are picked up on the next restart. Set serviceConfigEnabled: true (or --service-config-enabled / SERVICE_CONFIG_ENABLED=true) and restart osctrl-api to manage them here."
          />
        )}

        {!configDisabled && loading && (
          <div className="space-y-2">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-20 w-full" />
            ))}
          </div>
        )}

        {!configDisabled && hasError && !loading && (
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

        {!configDisabled && !loading && !hasError && sections.length === 0 && (
          <EmptyState
            icon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            }
            title={`No service config for ${service}.`}
          />
        )}

        {!configDisabled && !loading && !hasError && sections.length > 0 && (
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

      {showWarning && !configDisabled && (
        <ImpactWarningDialog
          onAcknowledge={() => {
            try {
              window.sessionStorage.setItem(WARNING_ACK_KEY, '1');
            } catch { /* blocked — warn again next mount */ }
            setShowWarning(false);
          }}
        />
      )}

      {showApplyConfirm && (
        <ApplyConfirmDialog
          service={service}
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

  const scope = useMemo(() => ({ service, section: section.Name }), [service, section.Name]);
  const sectionHelp = SECTION_HELP[`${service}:${section.Name}`] ?? SECTION_HELP[section.Name];

  return (
    <FieldScope.Provider value={scope}><section
      className="border border-[color:var(--border)] rounded-md bg-[color:var(--bg-1)]"
      aria-labelledby={`config-${section.Name}-heading`}
    >
      <header
        className="sticky top-0 z-10 flex items-center gap-3 px-3 py-2 bg-[color:var(--bg-0)] border-b border-[color:var(--border)] cursor-pointer select-none hover:bg-[color-mix(in_srgb,var(--bg-0)_85%,var(--bg-3))] rounded-t-[5px]"
        onClick={() => setCollapsed((c) => !c)}
      >
        <div className="flex items-center gap-2 shrink-0">
          <SectionIcon name={section.Name} />
          <h2
            id={`config-${section.Name}-heading`}
            className="font-display text-sm font-semibold text-[color:var(--text-1)] font-mono-tabular"
          >
            {section.Name}
          </h2>
        </div>
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
        {/* Collapsed cards keep the one-line summary; expanded ones show the
            fuller section description in the body instead, so it is not said twice. */}
        {section.Info && collapsed ? (
          <p className="text-[10px] text-[color:var(--text-3)] truncate flex-1">
            {section.Info}
          </p>
        ) : (
          <div className="flex-1" />
        )}
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
        {sectionHelp && (
          <p className="px-3.5 py-2.5 text-[11px] leading-relaxed text-[color:var(--text-2)] bg-[color:var(--bg-2)] border-b border-[color:var(--border)]">
            {sectionHelp}
          </p>
        )}
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

          const enumValues = resolveScoped(FIELD_ENUMS, service, section.Name, key);
          if (enumValues) {
            const current = String(currentValue ?? '');
            // Derived from the persisted value, not the draft: an undocumented value has to stay
            // selectable after the user picks a documented one, since the card has no reset.
            const persisted = String(originalValue ?? '');
            const options = enumValues.includes(persisted) ? enumValues : [...enumValues, persisted];
            return (
              <FieldRow key={key} fieldKey={key} dirty={dirtyKeys.includes(key)}>
                <select
                  aria-label={key}
                  value={current}
                  onChange={(e) => updateField(key, e.target.value)}
                  className={cn(
                    'px-3 py-1.5 text-xs rounded-md border',
                    'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
                    'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
                    dirtyKeys.includes(key)
                      ? 'border-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.5)]'
                      : 'border-[color:var(--border)]',
                  )}
                >
                  {options.map((v) => (
                    <option key={v} value={v}>
                      {enumValues.includes(v)
                        ? v
                        : v === ''
                          ? '(not set)'
                          : `${v} (persisted, not a documented value)`}
                    </option>
                  ))}
                </select>
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
    </section></FieldScope.Provider>
  );
}

const TOOLTIP_W = 320;
const EDGE_PAD = 8;

function FieldHelpIcon({ fieldKey }: { fieldKey: string }) {
  const scope = useContext(FieldScope);
  const help = resolveScoped(FIELD_HELP, scope.service, scope.section, fieldKey);
  const ref = useRef<HTMLSpanElement>(null);
  const tipRef = useRef<HTMLSpanElement>(null);
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null);
  const [top, setTop] = useState(0);

  // Long YAML annotations make tall tooltips; clamp against the measured height before paint.
  useLayoutEffect(() => {
    const el = tipRef.current;
    if (!pos || !el) return;
    const h = el.getBoundingClientRect().height;
    const maxTop = Math.max(EDGE_PAD, window.innerHeight - EDGE_PAD - h);
    setTop(Math.min(Math.max(pos.y - h / 2, EDGE_PAD), maxTop));
  }, [pos]);

  if (!help) return null;

  const show = () => {
    const rect = ref.current?.getBoundingClientRect();
    if (rect) {
      let left = rect.right + 8;
      const rightEdge = left + TOOLTIP_W;
      if (rightEdge > window.innerWidth - EDGE_PAD) {
        left = window.innerWidth - EDGE_PAD - TOOLTIP_W;
      }
      const y = rect.top + rect.height / 2;
      setTop(y);
      setPos({ x: left, y });
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
          ref={tipRef}
          className="fixed block px-3 py-2 text-[11px] leading-relaxed text-[color:var(--text-1)] bg-[color:var(--bg-0)] border border-[color:var(--border)] rounded-md shadow-lg pointer-events-none overflow-hidden"
          style={{
            left: `${pos.x}px`,
            top: `${top}px`,
            width: TOOLTIP_W,
            maxHeight: `calc(100vh - ${EDGE_PAD * 2}px)`,
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
              <h3 className="text-xs font-semibold text-[color:var(--text-1)] font-mono-tabular flex items-center gap-1.5">
                {name}
                <FieldHelpIcon fieldKey={name} />
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

function ImpactWarningDialog({ onAcknowledge }: { onAcknowledge: () => void }) {
  return (
    <ModalShell
      title="⚠ Changes here affect running services"
      titleId="service-config-warning-title"
      onClose={onAcknowledge}
      panelClassName="max-w-md"
    >
      <div className="space-y-4">
        <p className="text-sm text-[color:var(--text-1)]">
          This section edits the live configuration of osctrl-api and
          osctrl-tls. Incorrect values, or applying them, may degrade or break
          the availability and stability of these services — including osquery
          node enrollment, logging and this console itself.
        </p>
        <p className="text-xs text-[color:var(--text-2)]">
          Changes are staged in the database until you apply them, and applying
          them restarts the service. Review each value before saving.
        </p>
        <div className="flex items-center justify-end pt-2">
          <button
            type="button"
            onClick={onAcknowledge}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded transition-colors',
              'bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.16)] text-[color:var(--warning)]',
              'hover:bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.24)]',
            )}
          >
            I understand
          </button>
        </div>
      </div>
    </ModalShell>
  );
}

function ApplyConfirmDialog({
  service,
  pendingSections,
  isPending,
  onConfirm,
  onCancel,
}: {
  service: string;
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
          This will restart the osctrl-{service} service to apply the following
          configuration changes. The service will be briefly unavailable.
        </p>
        <div className="rounded-md border border-[color:var(--border)] bg-[color:var(--bg-0)] p-3">
          <p className="text-[10px] uppercase tracking-[0.08em] text-[color:var(--text-3)] mb-2">
            Pending changes ({pendingSections.length})
          </p>
          {pendingSections.length === 0 && (
            <p className="text-xs text-[color:var(--text-3)]">
              Already written to disk — restarting loads them from the
              configuration file.
            </p>
          )}
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
