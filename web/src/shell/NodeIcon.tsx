import type { Node } from '../contract/analysis';
import { Glyph } from '../design/Glyph';
import type { Tier } from '../design/tokens';

/** A node glyph as an inline icon (decorative: the text next to it names
 * the node). */
export function NodeIcon({
  node,
  size = 20,
}: {
  readonly node: Pick<Node, 'kind' | 'tier' | 'flags' | 'tier_conditional'>;
  readonly size?: number;
}) {
  const r = size * 0.32;
  return (
    <svg
      className="node-icon"
      width={size}
      height={size}
      viewBox={`${String(-size / 2)} ${String(-size / 2)} ${String(size)} ${String(size)}`}
      aria-hidden="true"
      focusable="false"
    >
      <Glyph
        kind={node.kind}
        tier={node.tier as Tier}
        radius={r}
        stale={node.flags.includes('stale')}
        conditional={node.tier_conditional}
      />
    </svg>
  );
}
