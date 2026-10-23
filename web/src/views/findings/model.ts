import type { Finding } from '../../contract/analysis';
import type { Indexes } from '../../data/indexes';
import { severityRank } from '../../data/indexes';
import type { Filters } from '../../state/route';

export type SortKey = 'severity' | 'rule' | 'subject';

export function subjectName(ix: Indexes, f: Finding): string {
  const n = f.node_id ? ix.nodes.get(f.node_id) : undefined;
  return n?.arn ?? n?.name ?? f.location.entity;
}

/** Findings matching the route filters, sorted. Suppressed findings are
 * shown only with the suppressed filter on (then only them). */
export function filterFindings(ix: Indexes, f: Filters, sort: SortKey = 'severity'): Finding[] {
  const text = f.text.trim().toLowerCase();
  const out = ix.analysis.findings.filter((x) => {
    if (f.suppressed !== (x.suppressed !== null)) return false;
    if (f.severities.length && !f.severities.includes(x.severity)) return false;
    if (f.rules.length && !f.rules.includes(x.rule_id)) return false;
    if (f.accounts.length && !f.accounts.includes(x.location.account)) return false;
    if (f.tiers.length || f.kinds.length) {
      const n = x.node_id ? ix.nodes.get(x.node_id) : undefined;
      if (!n) return false;
      if (f.tiers.length && !f.tiers.includes(n.tier)) return false;
      if (f.kinds.length && !f.kinds.includes(n.kind)) return false;
    }
    if (text) {
      const hay = `${x.rule_id} ${x.title} ${x.message} ${subjectName(ix, x)}`.toLowerCase();
      if (!hay.includes(text)) return false;
    }
    return true;
  });
  const by: Record<SortKey, (a: Finding, b: Finding) => number> = {
    severity: (a, b) =>
      severityRank(a.severity) - severityRank(b.severity) ||
      cmp(a.rule_id, b.rule_id) ||
      cmp(a.id, b.id),
    rule: (a, b) =>
      cmp(a.rule_id, b.rule_id) ||
      severityRank(a.severity) - severityRank(b.severity) ||
      cmp(a.id, b.id),
    subject: (a, b) => cmp(subjectName(ix, a), subjectName(ix, b)) || cmp(a.id, b.id),
  };
  return out.sort(by[sort]);
}

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Visible slice of a virtualized list. */
export function windowRange(
  scrollTop: number,
  viewport: number,
  rowHeight: number,
  count: number,
  overscan = 8,
): [number, number] {
  const first = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
  const last = Math.min(count, Math.ceil((scrollTop + viewport) / rowHeight) + overscan);
  return [first, Math.max(first, last)];
}

/** One CSV cell (RFC 4180). Cells that a spreadsheet would run as a
 * formula (=, +, -, @, tab, CR) are prefixed with a quote: names come from
 * the account and are attacker-controlled. */
export function csvCell(value: string): string {
  const safe = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return /[",\r\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

export function toCSV(ix: Indexes, findings: readonly Finding[]): string {
  const header = [
    'id',
    'severity',
    'rule_id',
    'title',
    'subject',
    'message',
    'policy',
    'statement_index',
    'path_id',
    'suppressed',
  ];
  const rows = findings.map((f) => [
    f.id,
    f.severity,
    f.rule_id,
    f.title,
    subjectName(ix, f),
    f.message,
    f.location.policy,
    String(f.location.statement_index),
    f.path_id ?? '',
    f.suppressed ? f.suppressed.reason : '',
  ]);
  return [header, ...rows].map((r) => r.map(csvCell).join(',')).join('\r\n') + '\r\n';
}
