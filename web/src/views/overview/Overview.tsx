import { useMemo } from 'react';
import { DetectionIndicator } from '../../design/DetectionIndicator';
import { emptyFilters, formatHash, to } from '../../state/route';
import { NodeRef, Severity } from '../common';
import type { ViewProps } from '../registry';
import { overview, pathVisibility } from './model';

const tierNames = [
  'Tier 0 — admin',
  'Tier 1 — path to admin',
  'Tier 2 — sensitive',
  'Tier 3 — other',
];

function Card({
  label,
  value,
  href,
  hint,
}: {
  label: string;
  value: number;
  href: string;
  hint?: string;
}) {
  return (
    <a className="card" href={href}>
      <span className="card__value">{value}</span>
      <span className="card__label">{label}</span>
      {hint && <span className="card__hint">{hint}</span>}
    </a>
  );
}

export function Overview({ ix, pseudonyms }: ViewProps) {
  const m = useMemo(() => overview(ix), [ix]);
  const atlasTier = (t: number): string =>
    formatHash({ ...to('atlas'), filters: { ...emptyFilters, tiers: [t] } });
  const findingsSev = (s: string): string =>
    formatHash({ ...to('findings'), filters: { ...emptyFilters, severities: [s] } });
  const a = ix.analysis;
  return (
    <div className="overview">
      <h1 className="view__title">Overview</h1>
      <p className="muted">
        {a.snapshot.accounts.length} account(s), {a.stats.nodes} nodes, {a.stats.edges} edges
        {a.snapshot.collected_at ? `, collected ${a.snapshot.collected_at.slice(0, 10)}` : ''}.
      </p>
      <section aria-labelledby="ov-principals">
        <h2 id="ov-principals" className="section__title">
          Principals by tier
        </h2>
        <div className="cards">
          {m.principalsByTier.map((count, t) => (
            <Card key={t} label={tierNames[t] ?? ''} value={count} href={atlasTier(t)} />
          ))}
        </div>
      </section>
      <section aria-labelledby="ov-risk">
        <h2 id="ov-risk" className="section__title">
          Escalation
        </h2>
        <div className="cards">
          <Card
            label="Critical paths to Tier 0"
            value={m.criticalPaths}
            href={findingsSev('critical')}
            hint={`${String(m.conditionalPaths)} conditional`}
          />
          <Card
            label="Critical paths CloudTrail cannot see"
            value={m.blindCriticalPaths}
            href={findingsSev('critical')}
          />
          <Card
            label="Choke points (cut several paths)"
            value={m.chokePoints}
            href={formatHash(to('fix'))}
          />
          <Card
            label="External accounts trusted"
            value={m.externalAccounts}
            href={formatHash({
              ...to('atlas'),
              filters: { ...emptyFilters, kinds: ['external_account'] },
            })}
          />
          <Card
            label="ATT&CK techniques exhibited"
            value={m.techniques}
            href={formatHash(to('findings'))}
          />
        </div>
      </section>
      <section aria-labelledby="ov-findings">
        <h2 id="ov-findings" className="section__title">
          Findings
        </h2>
        <div className="cards">
          {Object.entries(m.findingsBySeverity).map(([sev, count]) => (
            <Card key={sev} label={sev} value={count} href={findingsSev(sev)} />
          ))}
          <Card
            label="suppressed"
            value={m.suppressed}
            href={formatHash({ ...to('findings'), filters: { ...emptyFilters, suppressed: true } })}
          />
        </div>
      </section>
      <div className="overview__lists">
        <section aria-labelledby="ov-paths">
          <h2 id="ov-paths" className="section__title">
            Worst paths
          </h2>
          {m.worstPaths.length === 0 ? (
            <p className="muted">No path reaches Tier 0.</p>
          ) : (
            <ol className="rank-list">
              {m.worstPaths.map((p) => (
                <li key={p.id}>
                  <Severity value={p.severity} />{' '}
                  <NodeRef ix={ix} id={p.source} pseudonyms={pseudonyms} />{' '}
                  <a href={formatHash(to('path', p.id))}>
                    {p.length} step(s){p.status === 'conditional' ? ', conditional' : ''}
                  </a>{' '}
                  <svg
                    width="14"
                    height="14"
                    viewBox="-7 -7 14 14"
                    role="img"
                    aria-label={`CloudTrail visibility: ${pathVisibility(ix, p)}`}
                  >
                    <DetectionIndicator state={pathVisibility(ix, p)} size={10} />
                  </svg>
                </li>
              ))}
            </ol>
          )}
        </section>
        <section aria-labelledby="ov-fix">
          <h2 id="ov-fix" className="section__title">
            Fix first
          </h2>
          {m.topFixes.length === 0 ? (
            <p className="muted">Nothing to fix.</p>
          ) : (
            <ol className="rank-list">
              {m.topFixes.map((s) => (
                <li key={s.order}>
                  {pseudonyms ? `Change ${s.edge_id}` : s.change}{' '}
                  <span className="muted">(cuts {s.paths_cut.length} path(s))</span>
                </li>
              ))}
            </ol>
          )}
          <a href={formatHash(to('fix'))}>Full fix plan</a>
        </section>
      </div>
    </div>
  );
}
