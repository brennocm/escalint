import { glyphDash, glyphPath, sinkInnerRadius, tierRingRadius } from './glyphs';
import { useTheme } from './theme';
import {
  dimmedOpacity,
  nodeLabels,
  staleOpacity,
  tierRingWidth,
  type NodeKind,
  type Tier,
} from './tokens';

export type GlyphState = 'normal' | 'hover' | 'selected' | 'dimmed';

export interface GlyphProps {
  kind: NodeKind;
  tier: Tier;
  radius: number;
  x?: number;
  y?: number;
  state?: GlyphState;
  stale?: boolean;
  /** Tier depends on an unevaluated condition (tier_conditional). */
  conditional?: boolean;
  /** Accessible name; defaults to the node kind. */
  label?: string;
}

/** One node: shape by kind, outer ring colored by tier, state as halo/opacity. */
export function Glyph({
  kind,
  tier,
  radius,
  x = 0,
  y = 0,
  state = 'normal',
  stale = false,
  conditional = false,
  label,
}: GlyphProps) {
  const theme = useTheme();
  const ring = tierRingRadius(radius);
  const ringDash = stale ? '1 3' : conditional ? '4 3' : undefined;
  let opacity = 1;
  if (state === 'dimmed') opacity = dimmedOpacity;
  else if (stale) opacity = staleOpacity;
  const isSink = kind === 'tier0_sink';
  const shapeStroke = isSink ? theme.tier[0] : theme.colors.nodeStroke;

  return (
    <g transform={`translate(${String(x)} ${String(y)})`} opacity={opacity}>
      <title>{label ?? nodeLabels[kind]}</title>
      {(state === 'hover' || state === 'selected') && (
        <circle
          r={ring + 4}
          fill="none"
          stroke={theme.colors.focus}
          strokeWidth={state === 'selected' ? 2.5 : 1.5}
          strokeOpacity={state === 'selected' ? 1 : 0.6}
        />
      )}
      {!isSink && (
        <circle
          r={ring}
          fill="none"
          stroke={theme.tier[tier]}
          strokeWidth={tierRingWidth(tier)}
          strokeDasharray={ringDash}
        />
      )}
      <path
        d={glyphPath(kind, radius)}
        fill={theme.colors.nodeFill}
        stroke={shapeStroke}
        strokeWidth={isSink ? 2.5 : 1.5}
        strokeDasharray={glyphDash(kind, radius)}
        strokeLinejoin="round"
      />
      {isSink && (
        <circle r={sinkInnerRadius(radius)} fill="none" stroke={theme.tier[0]} strokeWidth={2.5} />
      )}
    </g>
  );
}
