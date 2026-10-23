// Hand-drawn sample of examples/vulnerable-account for the Phase 1D mockups.
// Fake identifiers only (111111111111 analyzed, 999999999999 external). The
// real data comes from analysis.json once the engine exists.
import type {
  CapabilityLevel,
  DetectionState,
  EdgeKind,
  NodeKind,
  Severity,
  Tier,
} from '../tokens';

export interface MockNode {
  id: string;
  kind: NodeKind;
  name: string;
  account: string;
  tier: Tier;
  reachable: number;
  stale?: boolean;
}

export interface MockEdge {
  id: string;
  from: string;
  to: string;
  kind: EdgeKind;
  actions: string[];
  ruleId?: string;
  pathfindingId?: string;
  conditional?: boolean;
  detection: DetectionState;
  pathsCut?: number;
}

export interface MockPath {
  id: string;
  edges: string[];
  severity: Severity;
  conditional?: boolean;
}

export const nodes: MockNode[] = [
  { id: 'alice', kind: 'user', name: 'alice', account: '111111111111', tier: 1, reachable: 6 },
  { id: 'ci', kind: 'user', name: 'ci-deployer', account: '111111111111', tier: 1, reachable: 9 },
  { id: 'devs', kind: 'group', name: 'developers', account: '111111111111', tier: 2, reachable: 3 },
  {
    id: 'deploy',
    kind: 'role',
    name: 'AppDeployRole',
    account: '111111111111',
    tier: 1,
    reachable: 7,
  },
  {
    id: 'lambdaAdmin',
    kind: 'role',
    name: 'LambdaExecAdmin',
    account: '111111111111',
    tier: 0,
    reachable: 24,
  },
  {
    id: 'orgAdmin',
    kind: 'role',
    name: 'OrgAdmin',
    account: '111111111111',
    tier: 0,
    reachable: 24,
  },
  {
    id: 'audit',
    kind: 'role',
    name: 'VendorAuditRole',
    account: '111111111111',
    tier: 1,
    reachable: 4,
  },
  {
    id: 'readonly',
    kind: 'role',
    name: 'ReadOnlyLegacy',
    account: '111111111111',
    tier: 3,
    reachable: 0,
    stale: true,
  },
  {
    id: 'lambdaSvc',
    kind: 'service',
    name: 'lambda.amazonaws.com',
    account: 'aws',
    tier: 3,
    reachable: 1,
  },
  {
    id: 'vendor',
    kind: 'external_account',
    name: '999999999999',
    account: '999999999999',
    tier: 3,
    reachable: 5,
  },
  {
    id: 'github',
    kind: 'federated',
    name: 'token.actions.githubusercontent.com',
    account: '111111111111',
    tier: 3,
    reachable: 8,
  },
  { id: 'anyone', kind: 'any_principal', name: '*', account: '*', tier: 3, reachable: 2 },
  {
    id: 'sink',
    kind: 'tier0_sink',
    name: 'Effective admin',
    account: '111111111111',
    tier: 0,
    reachable: 0,
  },
];

export const edges: MockEdge[] = [
  {
    id: 'e1',
    from: 'alice',
    to: 'lambdaAdmin',
    kind: 'passrole_compute',
    actions: ['iam:PassRole', 'lambda:CreateFunction', 'lambda:InvokeFunction'],
    ruleId: 'EL-PE-022',
    pathfindingId: 'lambda-001',
    detection: 'partial',
    pathsCut: 3,
  },
  { id: 'e2', from: 'lambdaAdmin', to: 'sink', kind: 'admin', actions: [], detection: 'visible' },
  {
    id: 'e3',
    from: 'github',
    to: 'deploy',
    kind: 'trust',
    actions: ['sts:AssumeRoleWithWebIdentity'],
    ruleId: 'EL-TR-003',
    detection: 'visible',
  },
  {
    id: 'e4',
    from: 'deploy',
    to: 'sink',
    kind: 'modify_permissions',
    actions: ['iam:PutRolePolicy'],
    ruleId: 'EL-PE-002',
    pathfindingId: 'iam-005',
    detection: 'visible',
    pathsCut: 2,
  },
  {
    id: 'e5',
    from: 'vendor',
    to: 'audit',
    kind: 'trust',
    actions: ['sts:AssumeRole'],
    ruleId: 'EL-TR-005',
    detection: 'visible',
  },
  {
    id: 'e6',
    from: 'audit',
    to: 'orgAdmin',
    kind: 'assume',
    actions: ['sts:AssumeRole'],
    ruleId: 'EL-PE-014',
    pathfindingId: 'sts-001',
    conditional: true,
    detection: 'visible',
  },
  { id: 'e7', from: 'orgAdmin', to: 'sink', kind: 'admin', actions: [], detection: 'visible' },
  {
    id: 'e8',
    from: 'ci',
    to: 'alice',
    kind: 'credential',
    actions: ['iam:CreateAccessKey', 'iam:DeleteAccessKey'],
    ruleId: 'EL-PE-010',
    pathfindingId: 'iam-003',
    detection: 'visible',
  },
  {
    id: 'e9',
    from: 'ci',
    to: 'deploy',
    kind: 'modify_trust',
    actions: ['iam:UpdateAssumeRolePolicy'],
    ruleId: 'EL-PE-013',
    pathfindingId: 'iam-012',
    detection: 'visible',
  },
  { id: 'e10', from: 'alice', to: 'devs', kind: 'member_of', actions: [], detection: 'visible' },
  {
    id: 'e11',
    from: 'lambdaSvc',
    to: 'lambdaAdmin',
    kind: 'trust',
    actions: ['sts:AssumeRole'],
    detection: 'visible',
  },
  {
    id: 'e12',
    from: 'devs',
    to: 'lambdaAdmin',
    kind: 'update_code',
    actions: ['lambda:UpdateFunctionCode', 'lambda:InvokeFunction'],
    ruleId: 'EL-PE-028',
    pathfindingId: 'lambda-004',
    detection: 'blind',
  },
  {
    id: 'e13',
    from: 'anyone',
    to: 'audit',
    kind: 'trust',
    actions: ['sts:AssumeRole'],
    ruleId: 'EL-TR-001',
    conditional: true,
    detection: 'visible',
  },
];

export const paths: MockPath[] = [
  { id: 'p1', edges: ['e1', 'e2'], severity: 'critical' },
  { id: 'p2', edges: ['e3', 'e4'], severity: 'critical' },
  { id: 'p3', edges: ['e8', 'e1', 'e2'], severity: 'critical' },
  { id: 'p4', edges: ['e9', 'e4'], severity: 'critical' },
  { id: 'p5', edges: ['e5', 'e6', 'e7'], severity: 'critical', conditional: true },
];

export const fixPlan = [
  {
    order: 1,
    change: 'Scope iam:PassRole in policy DevLambda (Sid=AllowPassRole) to non-admin roles',
    pathsCut: 3,
  },
  {
    order: 2,
    change: 'Remove iam:PutRolePolicy from AppDeployRole inline policy "deploy"',
    pathsCut: 2,
  },
  { order: 3, change: 'Add sts:ExternalId condition to VendorAuditRole trust policy', pathsCut: 1 },
  {
    order: 4,
    change: 'Restrict GitHub OIDC sub to repo:example-org/app:ref:refs/heads/main',
    pathsCut: 1,
  },
];

export const services = ['iam', 'sts', 'lambda', 's3', 'kms', 'secretsmanager', 'ec2'] as const;

/** Strongest capability per principal and service (absent = none). */
export const exposure: Record<
  string,
  Partial<Record<(typeof services)[number], CapabilityLevel>>
> = {
  lambdaAdmin: {
    iam: 'permission_management',
    sts: 'write',
    lambda: 'permission_management',
    s3: 'permission_management',
    kms: 'permission_management',
    secretsmanager: 'permission_management',
    ec2: 'permission_management',
  },
  orgAdmin: {
    iam: 'permission_management',
    sts: 'write',
    lambda: 'permission_management',
    s3: 'permission_management',
    kms: 'permission_management',
    secretsmanager: 'permission_management',
    ec2: 'permission_management',
  },
  deploy: { iam: 'permission_management', sts: 'write', lambda: 'write', s3: 'write', ec2: 'read' },
  ci: { iam: 'permission_management', lambda: 'write', s3: 'write' },
  alice: { iam: 'write', lambda: 'write', s3: 'read', ec2: 'list' },
  devs: { lambda: 'write', s3: 'read', ec2: 'list' },
  audit: { iam: 'read', sts: 'write', s3: 'list', ec2: 'read' },
  readonly: { iam: 'list', s3: 'list', ec2: 'list' },
};

export function nodeById(id: string): MockNode {
  const node = nodes.find((n) => n.id === id);
  if (!node) {
    throw new Error(`unknown mock node ${id}`);
  }
  return node;
}

export function edgeById(id: string): MockEdge {
  const edge = edges.find((e) => e.id === id);
  if (!edge) {
    throw new Error(`unknown mock edge ${id}`);
  }
  return edge;
}
