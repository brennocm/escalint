import type { Edge, Evidence, PolicyDoc } from '../contract/analysis';
import type { Indexes } from '../data/indexes';

const stageText: Record<string, string> = {
  identity: 'identity policy',
  boundary: 'permissions boundary',
  resource: 'resource policy',
};

function policyLabel(ev: Evidence, doc: PolicyDoc | undefined): string {
  if (ev.policy.startsWith('rewritten-trust:')) return 'the trust policy the attacker would write';
  if (ev.policy.startsWith('trust:'))
    return `the trust policy of ${ev.policy.slice('trust:'.length)}`;
  return doc ? `${doc.name} (${ev.policy})` : ev.policy;
}

function statementLabel(ev: Evidence): string {
  return ev.sid
    ? `statement Sid=${ev.sid} (#${String(ev.statement_index)})`
    : `statement #${String(ev.statement_index)}`;
}

/** Plain-language trace of why an edge exists, from its evidence. */
export function explain(ix: Indexes, e: Edge): string[] {
  const docs = new Map(ix.analysis.policies.map((p) => [p.source, p]));
  const lines: string[] = [];
  const byAction = new Map<string, Evidence[]>();
  for (const ev of e.evidence) {
    const list = byAction.get(ev.action) ?? [];
    list.push(ev);
    byAction.set(ev.action, list);
  }
  for (const action of e.required_actions) {
    const evs = byAction.get(action) ?? [];
    if (evs.length === 0) {
      lines.push(`${action}: required by the rule; no evidence statement recorded.`);
      continue;
    }
    const parts = evs.map(
      (ev) =>
        `${stageText[ev.stage] ?? ev.stage}: ${ev.effect === 'Allow' ? 'allowed' : 'denied'} by ${statementLabel(ev)} of ${policyLabel(ev, docs.get(ev.policy))}`,
    );
    lines.push(`${action}: ${parts.join('; ')}.`);
  }
  const boundary = e.evidence.some((ev) => ev.stage === 'boundary');
  const principal = ix.nodes.get(e.actor ?? e.from);
  if (!boundary && principal && (principal.kind === 'user' || principal.kind === 'role')) {
    lines.push(
      principal.flags.includes('no_boundary')
        ? 'No permissions boundary is attached.'
        : 'The permissions boundary does not deny these actions.',
    );
  }
  lines.push(
    ix.analysis.snapshot.organization
      ? 'Service control policies were evaluated and do not deny these actions.'
      : 'No organization data in the snapshot: SCPs and RCPs were not evaluated.',
  );
  if (e.conditions_unevaluated.length) {
    lines.push(`Conditional: escalint could not evaluate ${e.conditions_unevaluated.join(', ')}.`);
  }
  if (e.prerequisites_unverified.length) {
    lines.push(`Conditional: not verified that ${e.prerequisites_unverified.join('; ')}.`);
  }
  return lines;
}
