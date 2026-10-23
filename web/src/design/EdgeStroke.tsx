import { useId } from 'react';
import { useTheme } from './theme';
import { conditionalDash, edgeDash, type EdgeKind } from './tokens';

export interface EdgeStrokeProps {
  kind: EdgeKind;
  /** SVG path data from source to target. */
  d: string;
  width?: number;
  conditional?: boolean;
  dimmed?: boolean;
  /** Animate a moving dash along the path (disabled by prefers-reduced-motion). */
  flow?: boolean;
}

export function edgeColor(kind: EdgeKind, theme: ReturnType<typeof useTheme>): string {
  return kind === 'member_of' || kind === 'admin' ? theme.colors.edgeStructural : theme.edge[kind];
}

/** One edge: categorical color, stroke pattern by kind, arrowhead. */
export function EdgeStroke({
  kind,
  d,
  width = 1.75,
  conditional = false,
  dimmed = false,
  flow = false,
}: EdgeStrokeProps) {
  const theme = useTheme();
  const markerId = useId();
  const color = edgeColor(kind, theme);
  const dash = conditional ? conditionalDash : edgeDash[kind];
  // Fixed-size arrowhead: grows slowly with width so thick choke edges stay legible.
  const arrow = 7 + width;
  return (
    <g opacity={dimmed ? 0.15 : 1}>
      <defs>
        <marker
          id={markerId}
          viewBox="0 0 10 10"
          refX="9"
          refY="5"
          markerUnits="userSpaceOnUse"
          markerWidth={arrow}
          markerHeight={arrow}
          orient="auto-start-reverse"
        >
          <path d="M0 0 L10 5 L0 10 Z" fill={color} />
        </marker>
      </defs>
      <path
        d={d}
        fill="none"
        stroke={color}
        strokeWidth={width}
        strokeDasharray={dash === 'none' ? undefined : dash}
        strokeLinecap="round"
        markerEnd={`url(#${markerId})`}
      />
      {flow && (
        <path
          className="edge-flow"
          d={d}
          fill="none"
          stroke={theme.colors.surface}
          strokeOpacity={0.85}
          strokeWidth={Math.max(1, width / 2)}
          strokeLinecap="round"
        />
      )}
    </g>
  );
}
