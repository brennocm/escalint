import { useMemo } from 'react';
import { AttackBadge } from '../../design/AttackBadge';
import { DetectionIndicator } from '../../design/DetectionIndicator';
import { detectionLabels } from '../../design/tokens';
import { displayName } from '../../shell/names';
import { formatHash, to } from '../../state/route';
import { Severity } from '../common';
import type { ViewProps } from '../registry';
import { detectionRows, eventCounts } from './model';

export function Detect({ ix, pseudonyms }: ViewProps) {
  const rows = useMemo(() => detectionRows(ix), [ix]);
  const events = useMemo(() => eventCounts(rows), [rows]);
  const techniques = ix.analysis.attack.techniques;
  const techniqueInfo = new Map(
    ix.analysis.rules.flatMap((r) => r.attack.map((t) => [t.id, t] as const)),
  );
  const blind = rows.filter((r) => r.edge.detection.visibility === 'blind').length;
  const name = (id: string): string => {
    const n = ix.nodes.get(id);
    return n ? displayName(n, pseudonyms) : id;
  };
  return (
    <div className="detect">
      <h1 className="view__title">Detect</h1>
      <p className="muted">
        What CloudTrail records for each step of the enumerated paths (ADR 0022). {blind} of{' '}
        {rows.length} step(s) leave no management event: detect those through their prerequisites or
        data events, or prevent them.
      </p>
      <div className="overview__lists">
        <section aria-labelledby="det-events">
          <h2 id="det-events" className="section__title">
            Events to alert on
          </h2>
          {events.length === 0 ? (
            <p className="muted">No path steps.</p>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">eventName</th>
                  <th scope="col">eventSource</th>
                  <th scope="col">Kind</th>
                  <th scope="col">Path steps</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={`${e.source}/${e.name}`}>
                    <td className="mono">{e.name}</td>
                    <td className="mono">{e.source}</td>
                    <td>{e.kind}</td>
                    <td>{e.steps}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
        <section aria-labelledby="det-attack">
          <h2 id="det-attack" className="section__title">
            MITRE ATT&amp;CK techniques exhibited
          </h2>
          {techniques.length === 0 ? (
            <p className="muted">No technique: no finding maps to ATT&amp;CK.</p>
          ) : (
            <ul className="rank-list">
              {techniques.map((t) => {
                const info = techniqueInfo.get(t.id);
                return (
                  <li key={t.id}>
                    <AttackBadge
                      techniqueId={t.id}
                      name={info?.name ?? t.id}
                      tactics={[...(info?.tactics ?? [])]}
                    />{' '}
                    <span className="muted">
                      {t.findings} finding(s), {t.paths} path(s)
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
          <p className="muted">
            MITRE ATT&amp;CK® {ix.analysis.catalogs.attack}. ATT&amp;CK is a registered trademark of
            The MITRE Corporation.
          </p>
        </section>
      </div>
      <section aria-labelledby="det-steps">
        <h2 id="det-steps" className="section__title">
          Steps of the paths
        </h2>
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Path</th>
              <th scope="col">Step</th>
              <th scope="col">Visibility</th>
              <th scope="col">Events</th>
              <th scope="col">Blind spots</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={`${r.path.id}-${String(r.step)}`}>
                <td>
                  <Severity value={r.path.severity} />{' '}
                  <a href={formatHash(to('path', r.path.id))}>{name(r.path.source)}</a>
                </td>
                <td>
                  {r.step}. {r.edge.kind} → {name(r.edge.to)}
                </td>
                <td>
                  <svg width="14" height="14" viewBox="-7 -7 14 14" aria-hidden="true">
                    <DetectionIndicator state={r.edge.detection.visibility} size={10} />
                  </svg>{' '}
                  {detectionLabels[r.edge.detection.visibility]}
                  {r.edge.detection.requires_data_events ? ' (data events)' : ''}
                </td>
                <td className="mono">
                  {r.edge.detection.events.map((e) => e.name).join(', ') || '—'}
                </td>
                <td className="cell-wrap">{r.edge.detection.blind_spots.join(' ') || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
