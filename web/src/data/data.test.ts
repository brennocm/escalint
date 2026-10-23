import { describe, expect, it, vi } from 'vitest';
import { buildIndexes, isPrincipal, nodeLabel, severityRank } from './indexes';
import { LoadError, detectSource, loadAnalysis, parseAnalysis } from './load';
import { hardened, vulnerable } from './fixtures';

describe('parseAnalysis', () => {
  it('accepts the generated fixture', () => {
    const a = parseAnalysis(JSON.stringify(vulnerable));
    expect(a.nodes.length).toBeGreaterThan(10);
  });
  it.each([
    ['not json', '{', /not valid JSON/],
    ['array', '[]', /JSON object/],
    ['future version', '{"schema_version":"2"}', /unsupported schema_version "2"/],
    ['missing arrays', '{"schema_version":"1","nodes":[]}', /no edges array/],
  ])('rejects %s', (_name, text, msg) => {
    expect(() => parseAnalysis(text)).toThrow(msg);
  });
});

describe('loadAnalysis', () => {
  it('reads inline data', async () => {
    const el = document.createElement('script');
    el.type = 'application/json';
    el.id = 'escalint-data';
    el.textContent = JSON.stringify(hardened);
    document.body.append(el);
    expect(detectSource()).toEqual({ kind: 'inline', elementId: 'escalint-data' });
    const a = await loadAnalysis({ kind: 'inline', elementId: 'escalint-data' });
    expect(a.schema_version).toBe('1');
    el.remove();
    await expect(
      loadAnalysis({ kind: 'inline', elementId: 'escalint-data' }),
    ).rejects.toBeInstanceOf(LoadError);
  });
  it('fetches a URL', async () => {
    const ok = vi.fn().mockResolvedValue(new Response(JSON.stringify(hardened)));
    await expect(
      loadAnalysis({ kind: 'url', url: 'analysis.json' }, document, ok),
    ).resolves.toMatchObject({ schema_version: '1' });
    expect(ok).toHaveBeenCalledWith('analysis.json', {
      credentials: 'same-origin',
      cache: 'no-store',
    });
    const missing = vi.fn().mockResolvedValue(new Response('', { status: 404 }));
    await expect(loadAnalysis({ kind: 'url', url: 'x.json' }, document, missing)).rejects.toThrow(
      'HTTP 404',
    );
  });
  it('defaults to analysis.json and validates dataset names', () => {
    expect(detectSource()).toEqual({ kind: 'url', url: 'analysis.json' });
    window.history.replaceState(null, '', '?dataset=synthetic-2k');
    expect(detectSource()).toEqual({ kind: 'url', url: 'data/synthetic-2k.json' });
    window.history.replaceState(null, '', '?dataset=../../etc');
    expect(detectSource()).toEqual({ kind: 'url', url: 'analysis.json' });
    window.history.replaceState(null, '', '/');
  });
});

describe('buildIndexes', () => {
  const ix = buildIndexes(vulnerable);
  it('indexes every collection by ID', () => {
    expect(ix.nodes.size).toBe(vulnerable.nodes.length);
    expect(ix.edges.size).toBe(vulnerable.edges.length);
    expect(ix.rules.get('EL-PE-001')?.severity).toBe('critical');
  });
  it('builds sorted adjacency in both directions', () => {
    let outCount = 0;
    for (const [from, list] of ix.out) {
      outCount += list.length;
      for (const e of list) expect(e.from).toBe(from);
      const tos = list.map((e) => e.to);
      expect([...tos].sort()).toEqual(tos);
    }
    expect(outCount).toBe(vulnerable.edges.length);
    for (const [to, list] of ix.in) for (const e of list) expect(e.to).toBe(to);
  });
  it('groups by tier, account, finding and path', () => {
    const tierTotal = [...ix.byTier.values()].reduce((s, l) => s + l.length, 0);
    expect(tierTotal).toBe(vulnerable.nodes.length);
    expect(ix.accounts).toEqual(['111111111111']);
    const p = vulnerable.paths[0];
    expect(p).toBeDefined();
    if (p) {
      expect(ix.pathsByNode.get(p.source)).toContain(p);
      expect(ix.pathsByEdge.get(p.edges[0] ?? '')).toContain(p);
    }
    const withNode = vulnerable.findings.find((f) => f.node_id);
    expect(withNode && ix.findingsByNode.get(withNode.node_id ?? '')).toContain(withNode);
    expect(ix.maxReach).toBeGreaterThan(0);
    expect(ix.chokeByEdge.size).toBe(vulnerable.choke_points.length);
    expect(ix.fixByEdge.size).toBe(vulnerable.fix_plan.length);
  });
  it('labels and ranks', () => {
    const sink = vulnerable.nodes.find((n) => n.kind === 'tier0_sink');
    expect(sink && nodeLabel(sink)).toBe('Effective admin (111111111111)');
    expect(severityRank('critical')).toBe(0);
    expect(severityRank('nope')).toBe(5);
    expect(vulnerable.nodes.filter(isPrincipal).length).toBeGreaterThan(0);
  });
});
