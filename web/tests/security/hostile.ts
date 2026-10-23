// A hostile analysis.json: the vulnerable fixture with attacker-controlled
// strings in every place an account owner controls (names, ARNs, tags,
// paths, policy documents, finding messages, rule-adjacent text).

const payloads = [
  '<img src=x onerror="window.__xss=1">',
  '<script>window.__xss=1</script>',
  'javascript:window.__xss=1',
  '"><svg onload=window.__xss=1>',
  '‮evil‬',
  '{{constructor.constructor("window.__xss=1")()}}',
  '</script><script>window.__xss=1</script>',
  `long-${'A'.repeat(64 * 1024)}`,
];

type Mutable = Record<string, unknown>;

export function hostileAnalysis(base: string): string {
  const a = JSON.parse(base) as Mutable;
  let i = 0;
  const next = (): string => payloads[i++ % payloads.length] ?? '';
  for (const n of a.nodes as Mutable[]) {
    if (n.kind === 'tier0_sink') continue;
    const p = next();
    n.name = p;
    if (typeof n.arn === 'string') n.arn = `arn:aws:iam::111111111111:role/${p}`;
    n.tags = { [next()]: next() };
    n.path = `/${next()}/`;
  }
  for (const f of a.findings as Mutable[]) {
    f.message = next();
    f.title = next();
    f.remediation = next();
    (f.location as Mutable).policy = next();
  }
  for (const p of a.policies as Mutable[]) {
    p.name = next();
    p.document = {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'X',
          Effect: 'Allow',
          Action: [next()],
          Resource: [next()],
          Condition: { StringLike: { 'aws:PrincipalTag/x': [next()] } },
        },
      ],
    };
  }
  for (const s of a.fix_plan as Mutable[]) s.change = next();
  a.notes = [next(), next()];
  return JSON.stringify(a);
}
