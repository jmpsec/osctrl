/**
 * The login illustration is intentionally reduced to the circuit field.
 * Keeping it as SVG preserves the isometric projection and responsive fade
 * without carrying the visual weight of a foreground object.
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
        <filter id="login-scene-circuit-tint" colorInterpolationFilters="sRGB">
          <feFlood floodColor="var(--login-scene-circuit)" result="circuit-color" />
          <feComposite in="circuit-color" in2="SourceAlpha" operator="in" />
        </filter>
        <linearGradient
          id="login-scene-plane-fade"
          x1="0"
          y1="30"
          x2="0"
          y2="640"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0" stopColor="white" stopOpacity="0" />
          <stop offset="0.24" stopColor="white" stopOpacity="1" />
          <stop offset="0.72" stopColor="white" stopOpacity="1" />
          <stop offset="1" stopColor="white" stopOpacity="0" />
        </linearGradient>
        <mask
          id="login-scene-plane-mask"
          x="-600"
          y="0"
          width="1960"
          height="640"
          maskUnits="userSpaceOnUse"
        >
          <rect
            x="-600"
            y="0"
            width="1960"
            height="640"
            fill="url(#login-scene-plane-fade)"
          />
        </mask>
        <pattern
          id="login-scene-circuit-pattern"
          width="304"
          height="304"
          patternUnits="userSpaceOnUse"
          patternTransform="matrix(.8 .46 -.8 .46 380 76)"
        >
          <image
            href="/img/circuit.svg"
            width="304"
            height="304"
            filter="url(#login-scene-circuit-tint)"
          />
        </pattern>
      </defs>

      <g mask="url(#login-scene-plane-mask)">
        <path
          d="M380-180 1320 360 380 900-560 360 380-180Z"
          fill="var(--login-scene-grid-fill)"
        />
        <path
          className="login-scene-circuit-plane"
          d="M380-180 1320 360 380 900-560 360 380-180Z"
          fill="url(#login-scene-circuit-pattern)"
        />
      </g>

      <image
        className="login-scene-control-tower"
        href="/img/osquery-control-tower-simple.png"
        x="40"
        y="-6"
        width="680"
        height="654"
        preserveAspectRatio="xMidYMid meet"
      />
    </svg>
  );
}
