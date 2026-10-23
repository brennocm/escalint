import type { Indexes } from '../data/indexes';
import { nodeLabel } from '../data/indexes';
import type { Candidate } from '../search/fuzzy';
import { to, type Route, type View } from '../state/route';
import { displayName } from './names';

export const viewTitles: Record<View, string> = {
  overview: 'Overview',
  atlas: 'Atlas',
  path: 'Trace',
  reach: 'Reach',
  exposure: 'Exposure',
  findings: 'Findings',
  fix: 'Fix plan',
  detect: 'Detect',
  diff: 'Diff',
};

/** Searchable entries: views, principals (name and ARN), rules and paths. */
export function candidates(ix: Indexes, pseudonyms: boolean): Candidate[] {
  const out: Candidate[] = [];
  for (const v of ['overview', 'atlas', 'exposure', 'findings', 'fix', 'detect'] as const) {
    out.push({
      key: `view:${v}`,
      kind: 'view',
      text: viewTitles[v],
      label: viewTitles[v],
      detail: 'View',
      tier: 4,
    });
  }
  if (ix.analysis.diff) {
    out.push({
      key: 'view:diff',
      kind: 'view',
      text: 'Diff',
      label: 'Diff',
      detail: 'View',
      tier: 4,
    });
  }
  for (const n of ix.analysis.nodes) {
    if (n.kind === 'tier0_sink') continue;
    const label = displayName(n, pseudonyms);
    const text = pseudonyms ? `${label} ${n.id}` : `${nodeLabel(n)} ${n.arn ?? ''}`.trim();
    out.push({
      key: n.id,
      kind: 'node',
      text,
      label,
      detail: `${n.kind} · tier ${String(n.tier)}`,
      tier: n.tier,
    });
  }
  for (const r of ix.analysis.rules) {
    out.push({
      key: r.id,
      kind: 'rule',
      text: `${r.id} ${r.title}`,
      label: r.id,
      detail: r.title,
      tier: 4,
    });
    for (const t of r.attack) {
      out.push({
        key: `${r.id}:${t.id}`,
        kind: 'rule',
        text: `${t.id} ${t.name}`,
        label: t.id,
        detail: `${t.name} · ${r.id}`,
        tier: 4,
      });
    }
  }
  for (const p of ix.analysis.paths) {
    out.push({
      key: p.id,
      kind: 'path',
      text: p.id,
      label: p.id,
      detail: `${p.severity} path, ${String(p.length)} step(s)`,
      tier: 4,
    });
  }
  return out;
}

/** Where choosing a candidate leads. */
export function routeFor(c: Candidate): Route {
  switch (c.kind) {
    case 'view':
      return to(c.key.slice('view:'.length) as View);
    case 'node':
      return { ...to('reach', c.key), sel: c.key };
    case 'path':
      return to('path', c.key);
    case 'rule':
    case 'finding': {
      const rule = c.key.split(':')[0] ?? c.key;
      return { ...to('findings'), filters: { ...to('findings').filters, rules: [rule] } };
    }
  }
}
