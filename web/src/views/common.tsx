import type { Indexes } from '../data/indexes';
import { displayName } from '../shell/names';
import { NodeIcon } from '../shell/NodeIcon';

/** A node reference: glyph and name, linking to its Reach view. */
export function NodeRef({
  ix,
  id,
  pseudonyms,
}: {
  readonly ix: Indexes;
  readonly id: string;
  readonly pseudonyms: boolean;
}) {
  const n = ix.nodes.get(id);
  if (!n) return <span className="mono">{id}</span>;
  return (
    <a className="node-ref" href={`#/reach/${n.id}?sel=${n.id}`}>
      <NodeIcon node={n} size={16} />
      <span>{displayName(n, pseudonyms)}</span>
    </a>
  );
}

export function Severity({ value }: { readonly value: string }) {
  return <span className={`sev sev--${value}`}>{value}</span>;
}
