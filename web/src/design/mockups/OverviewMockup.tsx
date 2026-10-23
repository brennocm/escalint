import { AttackBadge } from '../AttackBadge';
import { DetectionIndicator } from '../DetectionIndicator';
import { Glyph } from '../Glyph';
import { edgeById, fixPlan, nodeById, nodes, paths } from '../mock/vulnerableAccount';
import { useTheme } from '../theme';
import { tiers } from '../tokens';

/** Splits `width` into consecutive segments proportional to `counts`. */
function stackSegments(counts: number[], width: number): { x: number; w: number }[] {
  const total = counts.reduce((a, b) => a + b, 0);
  return counts.map((c, i) => {
    const before = counts.slice(0, i).reduce((a, b) => a + b, 0);
    return total === 0 ? { x: 0, w: 0 } : { x: (before / total) * width, w: (c / total) * width };
  });
}

function TierBar() {
  const theme = useTheme();
  const principals = nodes.filter((n) => ['user', 'role', 'group'].includes(n.kind));
  const segments = stackSegments(
    tiers.map((t) => principals.filter((n) => n.tier === t).length),
    240,
  );
  return (
    <svg
      viewBox="0 0 240 28"
      preserveAspectRatio="xMinYMid meet"
      className="tier-bar"
      role="img"
      aria-label="Principals by tier"
    >
      {tiers.map((t, i) => {
        const seg = segments[i] ?? { x: 0, w: 0 };
        return (
          <rect
            key={t}
            x={seg.x}
            y={0}
            width={Math.max(0, seg.w - 2)}
            height={12}
            rx={3}
            fill={theme.tier[t]}
          />
        );
      })}
    </svg>
  );
}

/** Overview mockup: the entry point. Every number links to a filtered view. */
export function OverviewMockup() {
  const principals = nodes.filter((n) => ['user', 'role', 'group'].includes(n.kind));
  return (
    <div className="overview">
      <div className="kpis">
        <section className="kpi">
          <h4>Principals by tier</h4>
          <p className="kpi__value">{principals.length}</p>
          <TierBar />
          <p className="kpi__legend">
            {tiers.map((t) => (
              <span key={t}>
                T{t}: {principals.filter((n) => n.tier === t).length}
              </span>
            ))}
          </p>
        </section>
        <section className="kpi">
          <h4>Critical paths</h4>
          <p className="kpi__value kpi__value--critical">{paths.length}</p>
          <p className="kpi__note">1 depends on an unevaluated condition</p>
        </section>
        <section className="kpi">
          <h4>Choke points</h4>
          <p className="kpi__value">2</p>
          <p className="kpi__note">fixing 2 edges cuts 5 of 5 paths</p>
        </section>
        <section className="kpi">
          <h4>Detection blind spots</h4>
          <p className="kpi__value">1</p>
          <p className="kpi__note">critical path with a step invisible without data events</p>
        </section>
      </div>
      <div className="overview__columns">
        <section className="panel">
          <h4>Worst paths</h4>
          <ol className="path-list">
            {paths.map((p) => {
              const first = edgeById(p.edges[0] ?? '');
              const source = nodeById(first.from);
              const states = p.edges.map((id) => edgeById(id).detection);
              const worst = states.includes('blind')
                ? 'blind'
                : states.includes('partial')
                  ? 'partial'
                  : 'visible';
              return (
                <li key={p.id}>
                  <svg width={28} height={28} viewBox="-14 -14 28 28" aria-hidden="true">
                    <Glyph kind={source.kind} tier={source.tier} radius={7} />
                  </svg>
                  <span className="path-list__name">{source.name}</span>
                  <span className="path-list__meta">
                    {p.edges.length} steps{p.conditional ? ' · conditional' : ''}
                  </span>
                  <svg width={16} height={16} viewBox="-8 -8 16 16" aria-hidden="true">
                    <DetectionIndicator state={worst} size={9} />
                  </svg>
                  <span className="badge badge--critical">critical</span>
                </li>
              );
            })}
          </ol>
        </section>
        <section className="panel">
          <h4>Fix plan (top)</h4>
          <ol className="fix-list">
            {fixPlan.map((f) => (
              <li key={f.order}>
                <span>{f.change}</span>
                <span className="fix-list__cut">cuts {f.pathsCut}</span>
              </li>
            ))}
          </ol>
          <h4>ATT&amp;CK techniques (sample, unverified)</h4>
          <div className="badges">
            <AttackBadge
              techniqueId="T1098.003"
              name="Additional Cloud Roles"
              tactics={['Persistence', 'Privilege Escalation']}
            />
            <AttackBadge
              techniqueId="T1548.005"
              name="Temporary Elevated Cloud Access"
              tactics={['Privilege Escalation', 'Defense Evasion']}
            />
          </div>
        </section>
      </div>
    </div>
  );
}
