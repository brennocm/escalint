import type { Indexes } from '../data/indexes';
import { severityRank } from '../data/indexes';
import { to, type Route } from '../state/route';
import { displayAccount, displayArn, displayName } from './names';
import { NodeIcon } from './NodeIcon';

interface Props {
  readonly ix: Indexes;
  readonly sel: string;
  readonly pseudonyms: boolean;
  readonly onNavigate: (r: Route) => void;
  readonly onClose: () => void;
}

/** Details of the selected node, edge, path or finding. */
export function DetailsPanel({ ix, sel, pseudonyms, onNavigate, onClose }: Props) {
  const node = ix.nodes.get(sel);
  const edge = ix.edges.get(sel);
  const path = ix.paths.get(sel);
  const finding = ix.findings.get(sel);
  const name = (id: string): string => {
    const n = ix.nodes.get(id);
    return n ? displayName(n, pseudonyms) : id;
  };
  return (
    <aside className="details" aria-label="Details">
      <div className="details__head">
        <h2 className="details__title">Details</h2>
        <button
          type="button"
          className="button button--ghost"
          aria-label="Close details"
          onClick={onClose}
        >
          ×
        </button>
      </div>
      {node && (
        <section>
          <h3 className="details__name">
            <NodeIcon node={node} /> {displayName(node, pseudonyms)}
          </h3>
          <dl className="details__facts">
            <dt>Kind</dt>
            <dd>{node.kind}</dd>
            <dt>Tier</dt>
            <dd>
              {node.tier}
              {node.tier_conditional ? ' (conditional)' : ''}
            </dd>
            {node.account && (
              <>
                <dt>Account</dt>
                <dd>{displayAccount(node.account, pseudonyms)}</dd>
              </>
            )}
            <dt>ARN</dt>
            <dd className="mono">{displayArn(node, pseudonyms)}</dd>
            {node.blast && (
              <>
                <dt>Blast radius</dt>
                <dd>
                  {node.blast.reachable_principals} principals reachable
                  {node.blast.reaches_tier0 ? ', reaches Tier 0' : ''}; permission management in{' '}
                  {node.blast.capabilities.permission_management.length} services
                </dd>
              </>
            )}
            {node.flags.length > 0 && (
              <>
                <dt>Flags</dt>
                <dd>{node.flags.join(', ')}</dd>
              </>
            )}
          </dl>
          <div className="details__actions">
            <button
              type="button"
              className="button"
              onClick={() => {
                onNavigate({ ...to('reach', node.id), sel: node.id });
              }}
            >
              Where can it go
            </button>
            <button
              type="button"
              className="button"
              onClick={() => {
                onNavigate({ ...to('reach', node.id), dir: 'in', sel: node.id });
              }}
            >
              Who reaches it
            </button>
          </div>
          {(ix.pathsByNode.get(node.id) ?? [])
            .filter((p) => p.source === node.id)
            .slice(0, 5)
            .map((p) => (
              <p key={p.id}>
                <a href={`#/path/${p.id}`}>
                  {p.severity} path, {p.length} step(s)
                </a>
              </p>
            ))}
          <FindingList ix={ix} ids={(ix.findingsByNode.get(node.id) ?? []).map((f) => f.id)} />
        </section>
      )}
      {edge && (
        <section>
          <h3 className="details__name">
            {name(edge.from)} → {name(edge.to)}
          </h3>
          <dl className="details__facts">
            <dt>Kind</dt>
            <dd>
              {edge.kind}
              {edge.latent ? ' (latent)' : ''}
            </dd>
            <dt>Status</dt>
            <dd>{edge.status}</dd>
            <dt>Actions</dt>
            <dd className="mono">{edge.required_actions.join(', ') || '—'}</dd>
            {edge.conditions_unevaluated.length > 0 && (
              <>
                <dt>Not evaluated</dt>
                <dd className="mono">{edge.conditions_unevaluated.join(', ')}</dd>
              </>
            )}
            {edge.prerequisites_unverified.length > 0 && (
              <>
                <dt>Unverified</dt>
                <dd>{edge.prerequisites_unverified.join('; ')}</dd>
              </>
            )}
            <dt>Rules</dt>
            <dd>{edge.rule_ids.join(', ') || '—'}</dd>
          </dl>
          <FindingList ix={ix} ids={(ix.findingsByEdge.get(edge.id) ?? []).map((f) => f.id)} />
        </section>
      )}
      {path && (
        <section>
          <h3 className="details__name">
            {path.severity} path, {path.length} step(s)
          </h3>
          <p>
            {name(path.source)} → {name(path.target)}
          </p>
          <a href={`#/path/${path.id}`}>Open the trace</a>
        </section>
      )}
      {finding && (
        <section>
          <h3 className="details__name">
            {finding.rule_id}: {finding.title}
          </h3>
          <p>{pseudonyms ? 'Message hidden while pseudonyms are on.' : finding.message}</p>
          <p className="muted">{finding.remediation}</p>
        </section>
      )}
      {!node && !edge && !path && !finding && <p className="muted">Nothing selected.</p>}
    </aside>
  );
}

function FindingList({ ix, ids }: { readonly ix: Indexes; readonly ids: readonly string[] }) {
  if (ids.length === 0) return null;
  const list = ids
    .map((id) => ix.findings.get(id))
    .filter((f) => f !== undefined)
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
  return (
    <ul className="details__findings">
      {list.map((f) => (
        <li key={f.id}>
          <span className={`sev sev--${f.severity}`}>{f.severity}</span> {f.rule_id} {f.title}
        </li>
      ))}
    </ul>
  );
}
