/**
 * en/common.ts — English source catalog.
 *
 * Keys are namespaced by feature area; every language must provide the
 * same keys. This module is imported statically (fallback language) so
 * no runtime fetch is ever needed for English.
 */

export const en = {
  common: {
    search: 'Search',
    clearSearch: 'Clear search',
    signOut: 'Sign out',
    commandCenter: 'Command Center',
    cancel: 'Cancel',
    save: 'Save',
    close: 'Close',
    loading: 'Loading…',
    error: 'Something went wrong',
    retry: 'Retry',
  },
  pagination: {
    noResults: 'No results',
    /** "1–25 of 3,481" — count is pre-formatted with locale separators. */
    range: '{start}–{end} of {count}',
    prev: 'Prev',
    next: 'Next',
    previousPage: 'Previous page',
    nextPage: 'Next page',
  },
  pageTitle: {
    settings: 'Settings',
    authProviders: 'Auth Providers',
    serviceConfig: 'Service Config',
    logSinks: 'Log Sinks',
    nodes: 'Nodes',
    node: 'Node',
    enroll: 'Enroll',
    environments: 'Environments',
    configuration: 'Configuration',
    health: 'Health',
    queries: 'Queries',
    newQuery: 'New Query',
    query: 'Query',
    savedQueries: 'Saved Queries',
    tags: 'Tags',
    alerts: 'Alerts',
    dashboard: 'Dashboard',
    audit: 'Audit',
    profile: 'Profile',
    users: 'Users',
    newCarve: 'New Carve',
    carves: 'Carves',
    carve: 'Carve',
  },
  health: {
    /** "as of 14:32:05" — time is pre-formatted. */
    asOf: 'as of {time}',
  },
  nodes: {
    /** ICU plural: "1 error" / "3 errors". */
    errors: '{count, plural, one {# error} other {# errors}}',
    bytes: '{count} B',
  },
  users: {
    /** Token expiry line on the Users page. Date is pre-formatted. */
    tokenExpires: 'Expires: {date}',
  },
  dashboard: {
    responses: '{executions} of {expected} responses',
    nodes: '{executions} of {expected} nodes',
    total: '{count} total',
    hosts: '{count} hosts',
  },
  language: {
    /** aria/title for the language selector button. */
    changeLanguage: 'Change language',
    /** How each option reads inside the menu (endonym + tag). */
    current: 'Current language',
  },
  time: {
    /** Compact relative units: "3s", "4m", "2h", "1d". */
    secondsShort: '{count}s',
    minutesShort: '{count}m',
    hoursShort: '{count}h',
    daysShort: '{count}d',
    /** Future: "in 3s" */
    inSeconds: 'in {count}s',
    inMinutes: 'in {count}m',
    inHours: 'in {count}h',
    inDays: 'in {count}d',
    /** Bucket-relative phrasing for activity rollups. */
    justNow: 'just now',
    withinLastHour: 'within the last hour',
    hoursAgo: '{count}h ago',
    daysAgo: '{count}d ago',
  },
  theme: {
    toLight: 'Switch to light theme',
    toDark: 'Switch to dark theme',
  },
  nav: {
    workspace: 'Workspace',
    organization: 'Organization',
    admin: 'Admin',
    dashboard: 'Dashboard',
    nodes: 'Nodes',
    queries: 'Queries',
    saved: 'Saved',
    carves: 'Carves',
    tags: 'Tags',
    enrollment: 'Enrollment',
    configuration: 'Configuration',
    auditTrail: 'Audit Trail',
    myActivity: 'My Activity',
    operators: 'Operators',
    profile: 'Profile',
    environments: 'Environments',
    settings: 'Settings',
    serviceConfig: 'Service Config',
    logSinks: 'Log Sinks',
    alerts: 'Alerts',
    health: 'Health',
    authProviders: 'Auth Providers',
  },
  topbar: {
    openNavigation: 'Open navigation menu',
    expandNavigation: 'Expand navigation',
    collapseNavigation: 'Collapse navigation',
    openCommandPalette: 'Open command palette',
    breadcrumb: 'Breadcrumb',
    userMenu: 'User menu for {name}',
  },
  commandPalette: {
    title: 'Command palette',
    searchLabel: 'Command search',
    placeholder: 'Type to filter… Up/Down + Enter',
    noMatches: 'No matches.',
    /** Keyboard legend. */
    legend: '⌘K toggle · Esc close · ↑↓ navigate · ↵ activate',
    goToEnv: 'Go to env · {name}',
    editConfig: 'Edit config · {name}',
    /** Static page hints. */
    dashboardHint: 'Cross-env summary',
    operatorsHint: 'Users + permissions',
    profileHint: 'My account',
    environmentsHint: 'Create / edit envs',
    auditHint: 'Filtered log read',
    configHint: 'osquery config sections',
    settingsHint: 'Service settings',
  },
  login: {
    title: 'Login',
    /** Marketing panel */
    tagline: 'Performant OSQuery Fleet Management',
    environmentAware: 'Environment aware',
    fleetOperations: 'osquery fleet operations',
    hero: 'See the whole environment. Act on one endpoint.',
    observe: 'Observe',
    query: 'Query',
    investigate: 'Investigate',
    /** Auth form */
    signIn: 'Sign in',
    signInAria: 'Sign in',
    signingIn: 'Signing in…',
    welcomeBack: 'Welcome back',
    welcomeDescription: 'Sign in to continue to your osquery control workspace.',
    username: 'Username',
    password: 'Password',
    usernameRequired: 'Username is required',
    passwordRequired: 'Password is required',
    showPassword: 'Show password',
    hidePassword: 'Hide password',
    orContinueWith: 'or continue with',
    continueOidc: 'Continue with OIDC',
    continueSaml: 'Continue with SAML',
    protectedBy: 'Protected by your deployment\u2019s authentication policy.',
    loginFailed: 'Login failed',
    /** MFA */
    verifyIdentity: 'Verify your identity',
    setUpTwoFactor: 'Set up two-factor authentication',
    setUpDescription: 'Scan the code with an authenticator app, then enter the verification code it shows.',
    verifyDescription: 'Enter the current code from your authenticator app.',
    recoveryDescription: 'Enter one of the recovery codes you saved when you enrolled.',
    authenticationCode: 'Authentication code',
    recoveryCode: 'Recovery code',
    verify: 'Verify',
    verifying: 'Verifying…',
    confirmSignIn: 'Confirm and sign in',
    useSecurityKey: 'Use a security key or passkey',
    useAuthenticatorCode: 'Use authenticator code',
    useRecoveryCode: 'Use a recovery code',
    backToSignIn: 'Back to sign in',
    cantScan: 'Can\u2019t scan? Enter this key manually.',
    qrAlt: 'Authenticator enrollment QR code',
    saveRecoveryCodes: 'Save your recovery codes',
    saveRecoveryDescription: 'Each code signs you in once if you lose your authenticator. They are shown only now.',
    savedContinue: 'I have saved them — continue',
    verificationFailed: 'Verification failed',
    securityKeyFailed: 'Security key verification failed',
  },
} as const;

/**
 * The English catalog doubles as the key contract: every other language
 * must implement exactly the same (possibly nested) keys. Literal types
 * are widened to `string` so translated values can differ; the compile
 * error a missing/renamed key produces is the sync guarantee.
 */
type Widen<T> = {
  [K in keyof T]: T[K] extends string ? string : Widen<T[K]>;
};

export type Messages = Widen<typeof en>;
