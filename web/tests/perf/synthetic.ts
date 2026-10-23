// A synthetic analysis.json for performance budgets: n principals, about
// 4n edges, a few hundred paths. Shapes match the contract; values are fake.

const hex = (i: number, salt: number): string =>
  ((i * 2654435761 + salt) >>> 0).toString(16).padStart(8, '0') + i.toString(16).padStart(8, '0');

export function syntheticAnalysis(n: number, edgesPerNode = 4): string {
  const kinds = ['user', 'role', 'role', 'group'];
  const nodes = Array.from({ length: n }, (_, i) => ({
    id: `n_${hex(i, 1)}`,
    kind: kinds[i % 4],
    arn: `arn:aws:iam::111111111111:role/synthetic-${String(i)}`,
    name: `synthetic-${String(i)}`,
    account: i % 10 === 0 ? '222222222222' : '111111111111',
    path: '/',
    tags: {},
    tier: i < 20 ? 0 : i % 7 === 0 ? 1 : i % 3 === 0 ? 2 : 3,
    tier_conditional: false,
    service_linked: false,
    blast: {
      reachable_principals: i % 50,
      reaches_tier0: i % 7 === 0,
      capabilities: {
        permission_management: i % 9 === 0 ? ['iam'] : [],
        write: ['s3'],
        read: ['ec2', 'logs'],
        list: [],
      },
    },
    last_used: null,
    flags: i % 11 === 0 ? ['stale'] : [],
    group: null,
  }));
  const edges: { id: string; from: string; to: string; [key: string]: unknown }[] = [];
  for (let i = 0; i < n; i++) {
    for (let k = 1; k <= edgesPerNode; k++) {
      const j = (i * 7 + k * 13) % n;
      if (j === i) continue;
      edges.push({
        id: `e_${hex(i * 10 + k, 2)}`,
        from: nodes[i]?.id ?? '',
        to: nodes[j]?.id ?? '',
        kind: ['assume', 'credential', 'passrole_compute', 'modify_permissions'][k % 4],
        rule_ids: ['EL-PE-014'],
        pathfinding_ids: [],
        status: k === 3 ? 'conditional' : 'allowed',
        required_actions: ['sts:AssumeRole'],
        evidence: [],
        conditions_unevaluated: [],
        prerequisites_unverified: [],
        latent: false,
        actor: null,
        attack: [],
        detection: {
          events: [],
          blind_spots: [],
          requires_data_events: false,
          status: 'verified',
          visibility: 'visible',
        },
      });
    }
  }
  const paths = Array.from({ length: 300 }, (_, p) => {
    const e = edges[p * 37];
    return {
      id: `p_${hex(p, 3)}`,
      source: e?.from,
      target: nodes[0]?.id,
      edges: [e?.id],
      nodes: [e?.from, nodes[0]?.id],
      length: 1,
      status: 'allowed',
      severity: 'critical',
    };
  });
  const findings = paths.map((p, i) => ({
    id: `f_${hex(i, 4)}`,
    rule_id: 'EL-PE-014',
    severity: 'critical',
    title: 'Assume a more privileged role',
    message: 'synthetic',
    node_id: p.source,
    edge_id: p.edges[0],
    path_id: p.id,
    latent: false,
    location: {
      account: '111111111111',
      entity: '',
      policy: '',
      statement_index: -1,
      path: '',
      line: null,
    },
    remediation: '',
    suppressed: null,
  }));
  return JSON.stringify({
    schema_version: '1',
    generator: { name: 'escalint', version: 'perf', commit: 'none' },
    snapshot: {
      format: 'envelope',
      collected_at: null,
      partition: 'aws',
      accounts: ['111111111111'],
      redacted: false,
      organization: null,
    },
    catalogs: { service_reference: '', pathfinding: '', attack: '' },
    options: {
      max_depth: 6,
      k_paths: 3,
      experimental: false,
      min_severity: '',
      enabled_rules: ['EL-PE-014'],
    },
    rules: [
      {
        id: 'EL-PE-014',
        title: 'Assume a more privileged role',
        category: 'principal-access',
        severity: 'medium',
        status: 'stable',
        edge_kind: 'assume',
        pathfinding_ids: [],
        required_actions: [],
        prerequisites: [],
        attack: [],
        attack_unmapped_reason: null,
        remediation: '',
        references: [],
      },
    ],
    nodes,
    edges,
    paths,
    findings,
    suppressions: [],
    choke_points: [],
    cycles: [],
    fix_plan: [],
    notes: [],
    stats: { nodes: n, edges: edges.length, paths: paths.length, findings: findings.length },
    groupings: [],
    attack: { version: '', techniques: [] },
    policies: [],
  });
}
