import type { Indexes } from '../../data/indexes';
import { severityRank } from '../../data/indexes';
import type { FixStep, Path } from '../../contract/analysis';

export interface OverviewModel {
  readonly principalsByTier: readonly [number, number, number, number];
  readonly criticalPaths: number;
  readonly conditionalPaths: number;
  readonly blindCriticalPaths: number;
  readonly chokePoints: number;
  readonly externalAccounts: number;
  readonly findingsBySeverity: Readonly<Record<string, number>>;
  readonly suppressed: number;
  readonly techniques: number;
  readonly worstPaths: readonly Path[];
  readonly topFixes: readonly FixStep[];
}

/** A path is blind when some step leaves no management event in CloudTrail. */
export function pathVisibility(ix: Indexes, p: Path): 'visible' | 'partial' | 'blind' {
  let worst: 'visible' | 'partial' | 'blind' = 'visible';
  for (const id of p.edges) {
    const v = ix.edges.get(id)?.detection.visibility ?? 'visible';
    if (v === 'blind') return 'blind';
    if (v === 'partial') worst = 'partial';
  }
  return worst;
}

export function overview(ix: Indexes): OverviewModel {
  const a = ix.analysis;
  const tiers: [number, number, number, number] = [0, 0, 0, 0];
  for (const n of a.nodes) {
    if (n.kind === 'user' || n.kind === 'role' || n.kind === 'group')
      tiers[n.tier as 0 | 1 | 2 | 3]++;
  }
  const findingsBySeverity: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  let suppressed = 0;
  for (const f of a.findings) {
    if (f.suppressed) suppressed++;
    else findingsBySeverity[f.severity] = (findingsBySeverity[f.severity] ?? 0) + 1;
  }
  const critical = a.paths.filter((p) => p.severity === 'critical');
  const worstPaths = [...a.paths]
    .sort(
      (x, y) =>
        severityRank(x.severity) - severityRank(y.severity) ||
        x.length - y.length ||
        (x.id < y.id ? -1 : 1),
    )
    .slice(0, 5);
  return {
    principalsByTier: tiers,
    criticalPaths: critical.length,
    conditionalPaths: a.paths.filter((p) => p.status === 'conditional').length,
    blindCriticalPaths: critical.filter((p) => pathVisibility(ix, p) === 'blind').length,
    chokePoints: a.choke_points.filter((c) => c.paths_cut > 1).length,
    externalAccounts: a.nodes.filter((n) => n.kind === 'external_account').length,
    findingsBySeverity,
    suppressed,
    techniques: a.attack.techniques.length,
    worstPaths,
    topFixes: a.fix_plan.slice(0, 5),
  };
}
