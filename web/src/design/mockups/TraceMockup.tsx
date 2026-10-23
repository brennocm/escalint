import { DetectionIndicator } from '../DetectionIndicator';
import { EdgeStroke } from '../EdgeStroke';
import { Glyph } from '../Glyph';
import { edgeById, nodeById, type MockEdge } from '../mock/vulnerableAccount';
import { useTheme } from '../theme';
import { typography } from '../tokens';

const CARD_W = 196;
const CARD_H = 64;
const GAP = 168;

function chokeWidth(pathsCut = 0): number {
  // Log scale of paths cut through the edge (docs/design.md, "Choke points").
  return 1.75 + 1.5 * Math.log2(1 + pathsCut);
}

function NodeCard({
  id,
  x,
  y,
  muted = false,
}: {
  id: string;
  x: number;
  y: number;
  muted?: boolean;
}) {
  const theme = useTheme();
  const node = nodeById(id);
  const isSink = node.kind === 'tier0_sink';
  return (
    <g transform={`translate(${String(x)} ${String(y)})`} opacity={muted ? 0.55 : 1}>
      <rect
        width={CARD_W}
        height={CARD_H}
        rx={10}
        fill={theme.colors.surfaceRaised}
        stroke={isSink ? theme.tier[0] : theme.colors.border}
        strokeWidth={isSink ? 2 : 1}
      />
      <Glyph
        kind={node.kind}
        tier={node.tier}
        radius={11}
        x={30}
        y={CARD_H / 2}
        label={node.name}
      />
      <text
        x={56}
        y={27}
        fill={theme.colors.text}
        fontFamily={typography.fontSans}
        fontSize={13}
        fontWeight={600}
      >
        {node.name}
      </text>
      <text
        x={56}
        y={45}
        fill={theme.colors.textMuted}
        fontFamily={typography.fontMono}
        fontSize={10.5}
      >
        {isSink ? 'account 111111111111' : `Tier ${String(node.tier)} · ${node.account}`}
      </text>
    </g>
  );
}

function EdgeLabel({ edge, x, y }: { edge: MockEdge; x: number; y: number }) {
  const theme = useTheme();
  const lines = edge.kind === 'admin' ? ['effective admin'] : edge.actions;
  return (
    <g transform={`translate(${String(x)} ${String(y)})`}>
      {lines.map((line, i) => (
        <text
          key={line}
          y={i * 13}
          textAnchor="middle"
          fill={theme.colors.textMuted}
          fontFamily={typography.fontMono}
          fontSize={9.5}
        >
          {line}
        </text>
      ))}
      {edge.ruleId && (
        <text
          y={lines.length * 13 + 2}
          textAnchor="middle"
          fill={theme.colors.text}
          fontFamily={typography.fontMono}
          fontSize={9.5}
          fontWeight={600}
        >
          {edge.ruleId}
          {edge.pathfindingId ? ` · ${edge.pathfindingId}` : ''}
        </text>
      )}
    </g>
  );
}

function PathRow({ edgeIds, y, muted = false }: { edgeIds: string[]; y: number; muted?: boolean }) {
  const theme = useTheme();
  const first = edgeById(edgeIds[0] ?? '');
  const nodeIds = [first.from, ...edgeIds.map((id) => edgeById(id).to)];
  const xOf = (i: number) => 16 + i * (CARD_W + GAP);
  return (
    <g>
      {edgeIds.map((id, i) => {
        const edge = edgeById(id);
        const x1 = xOf(i) + CARD_W;
        const x2 = xOf(i + 1) - 4;
        const cy = y + CARD_H / 2;
        const choke = (edge.pathsCut ?? 0) >= 3;
        return (
          <g key={id} opacity={muted ? 0.55 : 1}>
            <EdgeStroke
              kind={edge.kind}
              d={`M${String(x1)} ${String(cy)} L${String(x2)} ${String(cy)}`}
              width={chokeWidth(edge.pathsCut)}
              conditional={edge.conditional ?? false}
              flow={!muted}
            />
            <DetectionIndicator state={edge.detection} x={(x1 + x2) / 2} y={cy} size={9} />
            <EdgeLabel edge={edge} x={(x1 + x2) / 2} y={cy + 20} />
            {choke && !muted && (
              <text
                x={(x1 + x2) / 2}
                y={cy - 14}
                textAnchor="middle"
                fill={theme.colors.text}
                fontFamily={typography.fontSans}
                fontSize={9.5}
                fontWeight={600}
              >
                choke point · cuts {edge.pathsCut}
              </text>
            )}
          </g>
        );
      })}
      {nodeIds.map((id, i) => (
        <NodeCard key={`${id}-${String(i)}`} id={id} x={xOf(i)} y={y} muted={muted} />
      ))}
    </g>
  );
}

/** Trace view mockup: path p3 plus the alternative k-path p4 stacked below. */
export function TraceMockup() {
  const theme = useTheme();
  return (
    <svg
      viewBox="0 0 1340 310"
      role="img"
      aria-labelledby="trace-mockup-title"
      className="mockup-svg"
    >
      <title id="trace-mockup-title">
        Trace mockup: ci-deployer reaches effective admin through alice and LambdaExecAdmin
      </title>
      <rect width={1340} height={310} rx={12} fill={theme.colors.surface} />
      <text
        x={16}
        y={30}
        fill={theme.colors.text}
        fontFamily={typography.fontSans}
        fontSize={15}
        fontWeight={600}
      >
        Path p3 · ci-deployer → effective admin
      </text>
      <text
        x={16}
        y={48}
        fill={theme.severity.critical}
        fontFamily={typography.fontSans}
        fontSize={12}
        fontWeight={600}
      >
        CRITICAL · 3 steps · 1 step only partially visible in CloudTrail
      </text>
      <PathRow edgeIds={['e8', 'e1', 'e2']} y={66} />
      <text
        x={16}
        y={212}
        fill={theme.colors.textMuted}
        fontFamily={typography.fontSans}
        fontSize={11.5}
      >
        Alternative path (k = 2)
      </text>
      <PathRow edgeIds={['e9', 'e4']} y={222} muted />
    </svg>
  );
}
