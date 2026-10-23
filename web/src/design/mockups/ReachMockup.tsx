import { EdgeStroke } from '../EdgeStroke';
import { Glyph } from '../Glyph';
import { edges, nodeById } from '../mock/vulnerableAccount';
import { useTheme } from '../theme';
import { nodeRadius, typography } from '../tokens';

const CX = 330;
const CY = 270;
const RINGS = [0, 95, 175, 250];
// Ring labels sit in the lower-left gap, where no node is placed.
const LABEL_ANGLE = (128 * Math.PI) / 180;

/** Hand-placed angles (degrees, clockwise from 3 o'clock) mimicking the
 * barycentric ordering the real layout will compute: children sit near the
 * angle of the node they reach. */
const placement: Record<string, { hop: number; angle: number }> = {
  sink: { hop: 0, angle: 0 },
  lambdaAdmin: { hop: 1, angle: 200 },
  deploy: { hop: 1, angle: 320 },
  orgAdmin: { hop: 1, angle: 80 },
  alice: { hop: 2, angle: 168 },
  devs: { hop: 2, angle: 200 },
  lambdaSvc: { hop: 2, angle: 232 },
  github: { hop: 2, angle: 298 },
  ci: { hop: 2, angle: 342 },
  audit: { hop: 2, angle: 80 },
  vendor: { hop: 3, angle: 64 },
  anyone: { hop: 3, angle: 96 },
};

function position(id: string): { x: number; y: number } {
  const p = placement[id];
  if (!p) {
    return { x: CX, y: CY };
  }
  const r = RINGS[p.hop] ?? 0;
  const a = (p.angle * Math.PI) / 180;
  return { x: CX + r * Math.cos(a), y: CY + r * Math.sin(a) };
}

/** Reach view mockup: who can reach effective admin (dir=in), rings by hops. */
export function ReachMockup() {
  const theme = useTheme();
  const shown = edges.filter(
    (e) => e.id !== 'e8' && placement[e.from] && placement[e.to] && e.kind !== 'member_of',
  );
  const maxReach = 24;
  return (
    <svg
      viewBox="0 0 660 560"
      role="img"
      aria-labelledby="reach-mockup-title"
      className="mockup-svg"
    >
      <title id="reach-mockup-title">
        Reach mockup: principals that can reach effective admin, arranged in rings by hop count
      </title>
      <rect width={660} height={560} rx={12} fill={theme.colors.surface} />
      {RINGS.slice(1).map((r, i) => (
        <g key={r}>
          <circle
            cx={CX}
            cy={CY}
            r={r}
            fill="none"
            stroke={theme.colors.border}
            strokeDasharray="2 4"
          />
          <text
            x={CX + r * Math.cos(LABEL_ANGLE) + 4}
            y={CY + r * Math.sin(LABEL_ANGLE) + 12}
            fill={theme.colors.textMuted}
            fontFamily={typography.fontSans}
            fontSize={10.5}
          >
            {i + 1} hop{i === 0 ? '' : 's'}
          </text>
        </g>
      ))}
      {shown.map((e) => {
        const a = position(e.from);
        const b = position(e.to);
        // Stop short of the target so the arrowhead is not hidden by the glyph.
        const len = Math.hypot(b.x - a.x, b.y - a.y);
        const k = (len - 20) / len;
        const end = { x: a.x + (b.x - a.x) * k, y: a.y + (b.y - a.y) * k };
        return (
          <EdgeStroke
            key={e.id}
            kind={e.kind}
            d={`M${a.x.toFixed(1)} ${a.y.toFixed(1)} L${end.x.toFixed(1)} ${end.y.toFixed(1)}`}
            conditional={e.conditional ?? false}
          />
        );
      })}
      {Object.keys(placement).map((id) => {
        const node = nodeById(id);
        const p = position(id);
        const r = id === 'sink' ? 16 : nodeRadius(node.reachable, maxReach);
        const below = p.y >= CY;
        return (
          <g key={id}>
            <Glyph kind={node.kind} tier={node.tier} radius={r} x={p.x} y={p.y} label={node.name} />
            <text
              x={p.x}
              y={below ? p.y + r + 18 : p.y - r - 10}
              textAnchor="middle"
              fill={theme.colors.text}
              fontFamily={typography.fontSans}
              fontSize={11}
              stroke={theme.colors.surface}
              strokeWidth={3}
              paintOrder="stroke"
            >
              {node.name.length > 22 ? `${node.name.slice(0, 20)}…` : node.name}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
