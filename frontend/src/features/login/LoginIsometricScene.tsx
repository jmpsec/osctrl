/**
 * A lightweight, theme-aware product illustration for the login screen.
 * The scene is deliberately native SVG so it stays crisp, loads instantly,
 * and can inherit the application palette without a second image asset.
 */
export function LoginIsometricScene() {
  return (
    <svg
      className="login-isometric-scene"
      viewBox="0 0 760 640"
      fill="none"
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        <filter id="login-scene-shadow" x="-40%" y="-40%" width="180%" height="180%">
          <feDropShadow dx="0" dy="18" stdDeviation="18" floodColor="var(--login-scene-shadow)" floodOpacity="0.24" />
        </filter>
        <filter id="login-scene-soft-shadow" x="-30%" y="-30%" width="160%" height="160%">
          <feDropShadow dx="0" dy="8" stdDeviation="8" floodColor="var(--login-scene-shadow)" floodOpacity="0.18" />
        </filter>
        <pattern id="login-scene-grid-pattern" width="96" height="56" patternUnits="userSpaceOnUse">
          <path d="M-48 0 48 56M48 0l96 56M-48 56 48 0M48 56l96-56" stroke="var(--login-scene-grid)" strokeWidth="1.25" />
        </pattern>
      </defs>

      {/* The operating plane deliberately continues beyond the illustration frame. */}
      <path
        className="login-scene-grid-plane"
        d="M380 126 1052 512 380 898-292 512 380 126Z"
        fill="var(--login-scene-grid-fill)"
        stroke="var(--login-scene-grid-border)"
        strokeWidth="1.5"
      />
      <path
        className="login-scene-grid"
        d="M380 126 1052 512 380 898-292 512 380 126Z"
        fill="url(#login-scene-grid-pattern)"
      />

      <g className="login-scene-links" stroke="var(--login-scene-link)" strokeWidth="2" strokeLinecap="round">
        <path d="M-64 450c154-52 251-41 330 13" strokeDasharray="5 9" />
        <path d="M824 450c-154-52-251-41-330 13" strokeDasharray="5 9" />
        <path d="M24 548c124-22 202-18 268 16" strokeDasharray="5 9" />
        <path d="M736 548c-124-22-202-18-268 16" strokeDasharray="5 9" />
      </g>

      <g className="login-scene-packet login-scene-packet-a">
        <circle cx="187" cy="433" r="5" fill="var(--login-scene-accent)" />
      </g>
      <g className="login-scene-packet login-scene-packet-b">
        <circle cx="573" cy="433" r="5" fill="var(--login-scene-success)" />
      </g>

      {/* Ground plinth */}
      <g className="login-scene-tower-base" filter="url(#login-scene-shadow)">
        <path d="m380 392 176 101-176 101-176-101 176-101Z" fill="var(--login-scene-surface)" stroke="var(--login-scene-edge)" strokeWidth="1.5" />
        <path d="m204 493 176 101v28L204 521v-28Z" fill="var(--login-scene-side-dark)" stroke="var(--login-scene-edge)" strokeWidth="1.5" />
        <path d="m380 594 176-101v28L380 622v-28Z" fill="var(--login-scene-side)" stroke="var(--login-scene-edge)" strokeWidth="1.5" />
        <path d="m250 493 130-75 130 75-130 75-130-75Z" fill="var(--login-scene-accent-soft)" stroke="var(--login-scene-accent)" strokeWidth="1.5" />
        <circle cx="253" cy="504" r="5" fill="var(--login-scene-success)" />
        <circle cx="273" cy="515" r="5" fill="var(--login-scene-accent)" />
      </g>

      {/* Tapered tower shaft */}
      <g className="login-scene-tower-shaft" filter="url(#login-scene-soft-shadow)">
        <path d="m333 272 47 27v181l-74-43 20-135 7-30Z" fill="var(--login-scene-surface)" stroke="var(--login-scene-edge)" strokeWidth="1.5" />
        <path d="m380 299 47-27 27 165-74 43V299Z" fill="var(--login-scene-side)" stroke="var(--login-scene-edge)" strokeWidth="1.5" />
        <path d="m320 346 60 35 60-35" stroke="var(--login-scene-edge)" strokeWidth="1.5" opacity="0.7" />
        <path d="m314 392 66 38 66-38" stroke="var(--login-scene-edge)" strokeWidth="1.5" opacity="0.7" />
        <path d="m352 328 28 16 28-16" stroke="var(--login-scene-accent)" strokeWidth="3" strokeLinecap="round" />
      </g>

      {/* Panoramic control room */}
      <g className="login-scene-tower-cabin" filter="url(#login-scene-soft-shadow)">
        <path d="m254 165 126 73v70l-105-61-21-82Z" fill="var(--login-scene-screen)" stroke="var(--login-scene-edge)" strokeWidth="1.5" />
        <path d="m380 238 126-73-21 82-105 61v-70Z" fill="var(--login-scene-screen-alt)" stroke="var(--login-scene-edge)" strokeWidth="1.5" />

        <g stroke="var(--login-scene-screen-ink)" strokeWidth="1.5" opacity="0.55">
          <path d="m287 184 2 82M320 203l1 82M350 220v82M473 184l-2 82M440 203l-1 82M410 220v82" />
        </g>
        <path d="m275 247 105 61v16l-101-58-4-19Z" fill="var(--login-scene-side-dark)" stroke="var(--login-scene-edge)" strokeWidth="1.5" />
        <path d="m380 308 105-61-4 19-101 58v-16Z" fill="var(--login-scene-side)" stroke="var(--login-scene-edge)" strokeWidth="1.5" />
        <circle cx="286" cy="221" r="5" fill="var(--login-scene-success)" />
      </g>

      {/* Roof deck and signal mast */}
      <g className="login-scene-antenna" strokeLinecap="round">
        <path d="M380 110V44" stroke="var(--login-scene-screen-ink)" strokeWidth="4" />
        <circle cx="380" cy="38" r="7" fill="var(--login-scene-success)" stroke="var(--login-scene-screen)" strokeWidth="3" />
        <path d="M362 57a26 26 0 0 1 36 0M350 44a43 43 0 0 1 60 0" stroke="var(--login-scene-link)" strokeWidth="2" />
      </g>
      <g className="login-scene-tower-roof" filter="url(#login-scene-soft-shadow)">
        <path d="m380 88 139 80-139 80-139-80 139-80Z" fill="var(--login-scene-surface)" stroke="var(--login-scene-edge)" strokeWidth="1.5" />
        <path d="m241 168 139 80v17l-139-80v-17Z" fill="var(--login-scene-side-dark)" stroke="var(--login-scene-edge)" strokeWidth="1.5" />
        <path d="m380 248 139-80v17l-139 80v-17Z" fill="var(--login-scene-side)" stroke="var(--login-scene-edge)" strokeWidth="1.5" />
        <path d="m334 168 46-27 46 27-46 27-46-27Z" fill="var(--login-scene-accent-soft)" stroke="var(--login-scene-accent)" strokeWidth="1.5" />
        <path d="m366 168 14-8 14 8-14 8-14-8Z" fill="var(--login-scene-accent)" />
      </g>

      <g className="login-scene-caption">
        <rect x="298" y="568" width="164" height="34" rx="17" fill="var(--login-scene-caption)" stroke="var(--login-scene-caption-border)" />
        <circle cx="320" cy="585" r="4" fill="var(--login-scene-success)" />
        <text x="336" y="590" fill="var(--login-scene-ink)" className="login-scene-status">Control plane online</text>
      </g>
    </svg>
  );
}
