import { useTheme } from './theme';
import { detectionLabels, type DetectionState } from './tokens';

/**
 * CloudTrail visibility of a step. Shape carries the meaning (filled disc,
 * half disc, slashed ring); color only repeats it.
 */
export function DetectionIndicator({
  state,
  x = 0,
  y = 0,
  size = 10,
}: {
  state: DetectionState;
  x?: number;
  y?: number;
  size?: number;
}) {
  const theme = useTheme();
  const color = theme.detection[state];
  const r = size / 2;
  return (
    <g transform={`translate(${String(x)} ${String(y)})`}>
      <title>{detectionLabels[state]}</title>
      <circle r={r + 2} fill={theme.colors.surface} />
      {state === 'visible' && <circle r={r} fill={color} />}
      {state === 'partial' && (
        <>
          <circle r={r - 0.75} fill="none" stroke={color} strokeWidth={1.5} />
          <path
            d={`M0 ${String(-r)} A${String(r)} ${String(r)} 0 0 0 0 ${String(r)} Z`}
            fill={color}
          />
        </>
      )}
      {state === 'blind' && (
        <>
          <circle r={r - 0.75} fill="none" stroke={color} strokeWidth={1.5} />
          <line
            x1={-r * 0.7}
            y1={r * 0.7}
            x2={r * 0.7}
            y2={-r * 0.7}
            stroke={color}
            strokeWidth={1.75}
            strokeLinecap="round"
          />
        </>
      )}
    </g>
  );
}
