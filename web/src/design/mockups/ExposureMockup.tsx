import { exposure, nodeById, services } from '../mock/vulnerableAccount';
import { useTheme } from '../theme';
import { capabilityLabels, capabilityLevels, typography } from '../tokens';

// Rows already in seriation order: identical profiles are adjacent.
const rows = ['lambdaAdmin', 'orgAdmin', 'deploy', 'ci', 'alice', 'devs', 'audit', 'readonly'];
const CELL = 34;
const LEFT = 150;
const TOP = 60;

/** Exposure view mockup: principals × services, strongest capability class. */
export function ExposureMockup() {
  const theme = useTheme();
  const width = LEFT + services.length * CELL + 110;
  const height = TOP + rows.length * CELL + 130;
  const rowWrite = (id: string) =>
    Object.values(exposure[id] ?? {}).filter((l) => l === 'write' || l === 'permission_management')
      .length;
  const colPm = (svc: (typeof services)[number]) =>
    rows.filter((id) => exposure[id]?.[svc] === 'permission_management').length;

  return (
    <svg
      viewBox={`0 0 ${String(width)} ${String(height)}`}
      role="img"
      aria-labelledby="exposure-mockup-title"
      className="mockup-svg"
    >
      <title id="exposure-mockup-title">
        Exposure mockup: strongest capability class per principal and service
      </title>
      <rect width={width} height={height} rx={12} fill={theme.colors.surface} />
      {services.map((svc, c) => (
        <text
          key={svc}
          x={LEFT + c * CELL + CELL / 2}
          y={TOP - 10}
          textAnchor="middle"
          fill={theme.colors.textMuted}
          fontFamily={typography.fontMono}
          fontSize={10}
        >
          {svc === 'secretsmanager' ? 'secrets' : svc}
        </text>
      ))}
      {rows.map((id, r) => {
        const node = nodeById(id);
        const y = TOP + r * CELL;
        const bar = rowWrite(id);
        return (
          <g key={id}>
            <text
              x={LEFT - 10}
              y={y + CELL / 2 + 4}
              textAnchor="end"
              fill={theme.colors.text}
              fontFamily={typography.fontSans}
              fontSize={11.5}
            >
              {node.name}
            </text>
            {services.map((svc, c) => {
              const level = exposure[id]?.[svc];
              return (
                <rect
                  key={svc}
                  x={LEFT + c * CELL + 1}
                  y={y + 1}
                  width={CELL - 2}
                  height={CELL - 2}
                  rx={4}
                  fill={level ? theme.intensity[level] : theme.colors.bg}
                  stroke={theme.colors.border}
                />
              );
            })}
            <rect
              x={LEFT + services.length * CELL + 10}
              y={y + 9}
              width={bar * 11}
              height={CELL - 18}
              rx={3}
              fill={theme.colors.edgeStructural}
            />
            <text
              x={LEFT + services.length * CELL + 16 + bar * 11}
              y={y + CELL / 2 + 4}
              fill={theme.colors.textMuted}
              fontFamily={typography.fontMono}
              fontSize={10}
            >
              {bar}
            </text>
          </g>
        );
      })}
      {services.map((svc, c) => {
        const n = colPm(svc);
        const base = TOP + rows.length * CELL + 8;
        return (
          <g key={svc}>
            <rect
              x={LEFT + c * CELL + 9}
              y={base}
              width={CELL - 18}
              height={n * 9}
              rx={3}
              fill={theme.colors.edgeStructural}
            />
            <text
              x={LEFT + c * CELL + CELL / 2}
              y={base + n * 9 + 12}
              textAnchor="middle"
              fill={theme.colors.textMuted}
              fontFamily={typography.fontMono}
              fontSize={10}
            >
              {n}
            </text>
          </g>
        );
      })}
      <g transform={`translate(16 ${String(height - 44)})`}>
        {capabilityLevels.map((level, i) => (
          <g
            key={level}
            transform={`translate(${String((i % 2) * 180)} ${String(Math.floor(i / 2) * 20)})`}
          >
            <rect
              width={14}
              height={14}
              rx={3}
              fill={theme.intensity[level]}
              stroke={theme.colors.border}
            />
            <text
              x={20}
              y={11}
              fill={theme.colors.textMuted}
              fontFamily={typography.fontSans}
              fontSize={10.5}
            >
              {capabilityLabels[level]}
            </text>
          </g>
        ))}
      </g>
      <text
        x={LEFT + services.length * CELL + 10}
        y={TOP - 10}
        fill={theme.colors.textMuted}
        fontFamily={typography.fontSans}
        fontSize={10}
      >
        write+
      </text>
    </svg>
  );
}
