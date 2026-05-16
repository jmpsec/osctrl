/**
 * Sparkline — tiny inline SVG line chart, no library dependency.
 * Per brand guide §08: 22px tall by default, no axes, no labels.
 */

interface SparklineProps {
  points: number[];
  color?: string;
  width?: number;
  height?: number;
  strokeWidth?: number;
}

export function Sparkline({
  points,
  color = 'currentColor',
  width = 80,
  height = 22,
  strokeWidth = 1.5,
}: SparklineProps) {
  if (points.length < 2) return null;

  const min = Math.min(...points);
  const max = Math.max(...points);
  const range = max - min || 1; // avoid division by zero for flat lines

  const pad = strokeWidth;
  const innerW = width - pad * 2;
  const innerH = height - pad * 2;

  const toX = (i: number) => pad + (i / (points.length - 1)) * innerW;
  const toY = (v: number) => pad + (1 - (v - min) / range) * innerH;

  const d = points
    .map((v, i) => `${i === 0 ? 'M' : 'L'} ${toX(i).toFixed(2)} ${toY(v).toFixed(2)}`)
    .join(' ');

  return (
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      aria-hidden
      role="presentation"
      style={{ display: 'block', overflow: 'visible' }}
    >
      <polyline
        points={points
          .map((v, i) => `${toX(i).toFixed(2)},${toY(v).toFixed(2)}`)
          .join(' ')}
        fill="none"
        stroke={color}
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
        // Fallback via explicit d attribute is not needed; polyline is sufficient.
        // Using polyline instead of path for simplicity.
        // The `d` variable above is kept for potential future path-fill variant.
        data-sparkline-path={d}
      />
    </svg>
  );
}
