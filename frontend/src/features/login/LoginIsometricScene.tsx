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
      </defs>

      <g className="login-scene-grid" stroke="var(--login-scene-grid)" strokeWidth="1">
        <path d="M42 434 380 628 718 434" />
        <path d="M42 386 380 580 718 386" />
        <path d="M42 338 380 532 718 338" />
        <path d="M42 290 380 484 718 290" />
        <path d="m90 462 338-194" />
        <path d="m162 504 338-194" />
        <path d="m234 546 338-194" />
        <path d="m306 588 338-194" />
        <path d="m670 462-338-194" />
        <path d="m598 504-338-194" />
        <path d="m526 546-338-194" />
        <path d="m454 588-338-194" />
      </g>

      <g className="login-scene-links" stroke="var(--login-scene-link)" strokeWidth="2" strokeLinecap="round">
        <path d="M210 215c32 7 64 30 88 58" strokeDasharray="5 8" />
        <path d="M550 215c-32 7-64 30-88 58" strokeDasharray="5 8" />
        <path d="M175 405c42-1 91 13 127 38" strokeDasharray="5 8" />
        <path d="M585 405c-42-1-91 13-127 38" strokeDasharray="5 8" />
      </g>

      <g className="login-scene-packet login-scene-packet-a">
        <circle cx="266" cy="252" r="5" fill="var(--login-scene-accent)" />
      </g>
      <g className="login-scene-packet login-scene-packet-b">
        <circle cx="494" cy="252" r="5" fill="var(--login-scene-success)" />
      </g>

      {/* Linux endpoint */}
      <g className="login-scene-node login-scene-node-a" filter="url(#login-scene-soft-shadow)">
        <path d="m104 157 106-61 106 61-106 61-106-61Z" fill="var(--login-scene-surface)" stroke="var(--login-scene-edge)" />
        <path d="m104 157 106 61v18l-106-61v-18Z" fill="var(--login-scene-side-dark)" stroke="var(--login-scene-edge)" />
        <path d="m210 218 106-61v18l-106 61v-18Z" fill="var(--login-scene-side)" stroke="var(--login-scene-edge)" />
        <path d="m159 159 51-29 51 29-51 29-51-29Z" fill="var(--login-scene-screen)" />
        <path d="m188 150-10 7 10 7M199 169h25" stroke="var(--login-scene-screen-ink)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
        <circle cx="130" cy="166" r="4" fill="var(--login-scene-success)" />
        <text x="210" y="78" textAnchor="middle" fill="var(--login-scene-muted)" className="login-scene-label">Linux endpoints</text>
      </g>

      {/* macOS endpoint */}
      <g className="login-scene-node login-scene-node-b" filter="url(#login-scene-soft-shadow)">
        <path d="m444 157 106-61 106 61-106 61-106-61Z" fill="var(--login-scene-surface)" stroke="var(--login-scene-edge)" />
        <path d="m444 157 106 61v18l-106-61v-18Z" fill="var(--login-scene-side-dark)" stroke="var(--login-scene-edge)" />
        <path d="m550 218 106-61v18l-106 61v-18Z" fill="var(--login-scene-side)" stroke="var(--login-scene-edge)" />
        <path d="m499 159 51-29 51 29-51 29-51-29Z" fill="var(--login-scene-screen)" />
        <path d="M536 149c0-8 6-13 14-13s14 5 14 13c0 11-7 20-14 20s-14-9-14-20Z" stroke="var(--login-scene-screen-ink)" strokeWidth="3" />
        <path d="M550 135c0-5 4-9 9-9" stroke="var(--login-scene-screen-ink)" strokeWidth="3" strokeLinecap="round" />
        <circle cx="470" cy="166" r="4" fill="var(--login-scene-success)" />
        <text x="550" y="78" textAnchor="middle" fill="var(--login-scene-muted)" className="login-scene-label">macOS endpoints</text>
      </g>

      {/* Windows endpoint */}
      <g className="login-scene-node login-scene-node-c" filter="url(#login-scene-soft-shadow)">
        <path d="m69 404 106-61 106 61-106 61-106-61Z" fill="var(--login-scene-surface)" stroke="var(--login-scene-edge)" />
        <path d="m69 404 106 61v18L69 422v-18Z" fill="var(--login-scene-side-dark)" stroke="var(--login-scene-edge)" />
        <path d="m175 465 106-61v18l-106 61v-18Z" fill="var(--login-scene-side)" stroke="var(--login-scene-edge)" />
        <path d="m124 406 51-29 51 29-51 29-51-29Z" fill="var(--login-scene-screen)" />
        <g fill="var(--login-scene-screen-ink)">
          <path d="m153 397 19-10v17l-19 10v-17Z" />
          <path d="m177 384 20-11v17l-20 11v-17Z" />
          <path d="m153 418 19-10v17l-19 10v-17Z" />
          <path d="m177 405 20-11v17l-20 11v-17Z" />
        </g>
        <circle cx="95" cy="413" r="4" fill="var(--login-scene-success)" />
        <text x="175" y="504" textAnchor="middle" fill="var(--login-scene-muted)" className="login-scene-label">Windows endpoints</text>
      </g>

      {/* Query result surface */}
      <g className="login-scene-node login-scene-node-d" filter="url(#login-scene-soft-shadow)">
        <path d="m479 404 106-61 106 61-106 61-106-61Z" fill="var(--login-scene-surface)" stroke="var(--login-scene-edge)" />
        <path d="m479 404 106 61v18l-106-61v-18Z" fill="var(--login-scene-side-dark)" stroke="var(--login-scene-edge)" />
        <path d="m585 465 106-61v18l-106 61v-18Z" fill="var(--login-scene-side)" stroke="var(--login-scene-edge)" />
        <path d="m534 406 51-29 51 29-51 29-51-29Z" fill="var(--login-scene-screen)" />
        <path d="m552 411 12-9 12 3 13-16 15 10 14-12" stroke="var(--login-scene-success)" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />
        <circle cx="505" cy="413" r="4" fill="var(--login-scene-accent)" />
        <text x="585" y="504" textAnchor="middle" fill="var(--login-scene-muted)" className="login-scene-label">Query results</text>
      </g>

      {/* Central control plane */}
      <g className="login-scene-core" filter="url(#login-scene-shadow)">
        <path d="m235 354 145-84 145 84-145 84-145-84Z" fill="var(--login-scene-side-dark)" opacity="0.48" />
        <path d="m222 324 158-91 158 91-158 91-158-91Z" fill="var(--login-scene-surface)" stroke="var(--login-scene-edge)" strokeWidth="1.5" />
        <path d="m222 324 158 91v34l-158-91v-34Z" fill="var(--login-scene-side-dark)" stroke="var(--login-scene-edge)" strokeWidth="1.5" />
        <path d="m380 415 158-91v34l-158 91v-34Z" fill="var(--login-scene-side)" stroke="var(--login-scene-edge)" strokeWidth="1.5" />

        <path d="m293 323 87-50 87 50-87 50-87-50Z" fill="var(--login-scene-accent-soft)" stroke="var(--login-scene-accent)" strokeWidth="2" />
        <path d="m346 317 34-20 34 20-34 20-34-20Z" fill="var(--login-scene-accent)" />
        <path d="m368 317 9 9 17-20" stroke="var(--login-scene-accent-ink)" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />

        <circle cx="258" cy="338" r="5" fill="var(--login-scene-success)" />
        <circle cx="275" cy="348" r="5" fill="var(--login-scene-accent)" />
        <path d="m420 380 64-37" stroke="var(--login-scene-ink)" strokeWidth="3" strokeLinecap="round" opacity="0.55" />
        <path d="m433 387 51-29" stroke="var(--login-scene-ink)" strokeWidth="3" strokeLinecap="round" opacity="0.3" />
      </g>

      <g className="login-scene-caption">
        <rect x="287" y="487" width="186" height="34" rx="17" fill="var(--login-scene-caption)" stroke="var(--login-scene-caption-border)" />
        <circle cx="309" cy="504" r="4" fill="var(--login-scene-success)" />
        <text x="325" y="509" fill="var(--login-scene-ink)" className="login-scene-status">Environment connected</text>
      </g>
    </svg>
  );
}
