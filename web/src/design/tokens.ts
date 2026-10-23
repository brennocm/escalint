// Design tokens: the single source of every color, size and duration in the UI.
// Components never use literal colors; they read the CSS custom properties that
// applyTheme() derives from these objects. Rationale and validation rules are
// in docs/design.md; palette.test.ts enforces contrast and perceptual distance.

export type ThemeName = 'light' | 'dark';

export const nodeKinds = [
  'user',
  'role',
  'group',
  'service',
  'external_account',
  'federated',
  'any_principal',
  'tier0_sink',
] as const;
export type NodeKind = (typeof nodeKinds)[number];

/** Edge kinds that encode an escalation technique (categorical palette). */
export const escalationEdgeKinds = [
  'assume',
  'trust',
  'credential',
  'modify_permissions',
  'modify_trust',
  'passrole_compute',
  'update_code',
] as const;
export type EscalationEdgeKind = (typeof escalationEdgeKinds)[number];

/** Structural edges are drawn in a neutral color. */
export const structuralEdgeKinds = ['member_of', 'admin'] as const;
export type StructuralEdgeKind = (typeof structuralEdgeKinds)[number];
export type EdgeKind = EscalationEdgeKind | StructuralEdgeKind;

export const tiers = [0, 1, 2, 3] as const;
export type Tier = (typeof tiers)[number];

export const severities = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof severities)[number];

/** Capability classes of the Exposure matrix, from weakest to strongest. */
export const capabilityLevels = ['list', 'read', 'write', 'permission_management'] as const;
export type CapabilityLevel = (typeof capabilityLevels)[number];

/** CloudTrail visibility of one exploitation step (ADR 0022). */
export const detectionStates = ['visible', 'partial', 'blind'] as const;
export type DetectionState = (typeof detectionStates)[number];

export interface ColorTokens {
  bg: string;
  surface: string;
  surfaceRaised: string;
  border: string;
  text: string;
  textMuted: string;
  accent: string;
  focus: string;
  nodeFill: string;
  nodeStroke: string;
  edgeStructural: string;
}

export interface Theme {
  colors: ColorTokens;
  /** Tier ring colors: sequential, monotonic in lightness (also under CVD). */
  tier: Record<Tier, string>;
  /** Edge colors: categorical, CIEDE2000 >= 15 pairwise (also under CVD). */
  edge: Record<EscalationEdgeKind, string>;
  /** Severity text/badge colors: WCAG AA (4.5:1) on bg and surface. */
  severity: Record<Severity, string>;
  /** Exposure matrix cells: single hue, monotonic lightness. */
  intensity: Record<CapabilityLevel, string>;
  /** Detection indicator colors (shape carries the meaning; color repeats it). */
  detection: Record<DetectionState, string>;
}

export const themes: Record<ThemeName, Theme> = {
  light: {
    colors: {
      bg: '#f7f7f8',
      surface: '#ffffff',
      surfaceRaised: '#ffffff',
      border: '#d9dbe1',
      text: '#17181c',
      textMuted: '#555864',
      accent: '#3346d3',
      focus: '#3346d3',
      nodeFill: '#ffffff',
      nodeStroke: '#3f434d',
      edgeStructural: '#7c818d',
    },
    tier: { 0: '#8e0132', 1: '#a13c02', 2: '#a3802d', 3: '#7d92a0' },
    edge: {
      assume: '#0b508c',
      trust: '#029e8f',
      credential: '#d37818',
      modify_permissions: '#f73277',
      modify_trust: '#977ed8',
      passrole_compute: '#2a7b54',
      update_code: '#724e02',
    },
    severity: {
      critical: '#8e0132',
      high: '#a13c02',
      medium: '#7a5a00',
      low: '#2d5a8c',
      info: '#555864',
    },
    intensity: {
      list: '#d5dafa',
      read: '#9aa6ee',
      write: '#5a6ddf',
      permission_management: '#2a39b0',
    },
    detection: { visible: '#3f434d', partial: '#7a5a00', blind: '#a13c02' },
  },
  dark: {
    colors: {
      bg: '#101114',
      surface: '#181a1f',
      surfaceRaised: '#20232a',
      border: '#2c2f37',
      text: '#eceef2',
      textMuted: '#a3a7b3',
      accent: '#9aa8ff',
      focus: '#9aa8ff',
      nodeFill: '#20232a',
      nodeStroke: '#c9ccd4',
      edgeStructural: '#7b8190',
    },
    tier: { 0: '#fd9bb7', 1: '#f19f64', 2: '#9c7222', 3: '#626e77' },
    edge: {
      assume: '#99a9fe',
      trust: '#55eee4',
      credential: '#d08b02',
      modify_permissions: '#d57279',
      modify_trust: '#bf75a9',
      passrole_compute: '#bae7aa',
      update_code: '#fddb24',
    },
    severity: {
      critical: '#fd9bb7',
      high: '#f19f64',
      medium: '#e2c266',
      low: '#8fb6ff',
      info: '#a3a7b3',
    },
    intensity: {
      list: '#2b3263',
      read: '#46559f',
      write: '#7385e3',
      permission_management: '#b3bdff',
    },
    detection: { visible: '#c9ccd4', partial: '#e2c266', blind: '#f19f64' },
  },
};

/** Stroke patterns, so edge kind never depends on color alone. */
export const edgeDash: Record<EdgeKind, string> = {
  assume: 'none',
  trust: '8 4',
  credential: '2 3',
  modify_permissions: 'none',
  modify_trust: '8 4',
  passrole_compute: '2 3',
  update_code: '10 3 2 3',
  member_of: '1 4',
  admin: 'none',
};

/** Unevaluated conditions: long gaps that read as "intermittent". */
export const conditionalDash = '6 6';

export const edgeLabels: Record<EdgeKind, string> = {
  assume: 'Assume role',
  trust: 'Trusted from outside',
  credential: 'Create credentials',
  modify_permissions: 'Modify permissions',
  modify_trust: 'Rewrite trust policy',
  passrole_compute: 'Pass role to compute',
  update_code: 'Update running code',
  member_of: 'Member of group',
  admin: 'Effective admin',
};

export const capabilityLabels: Record<CapabilityLevel, string> = {
  list: 'List',
  read: 'Read',
  write: 'Write',
  permission_management: 'Permission management',
};

export const detectionLabels: Record<DetectionState, string> = {
  visible: 'Visible in CloudTrail',
  partial: 'Partially visible',
  blind: 'Blind spot',
};

export const nodeLabels: Record<NodeKind, string> = {
  user: 'User',
  role: 'Role',
  group: 'Group',
  service: 'AWS service',
  external_account: 'External account',
  federated: 'Federated provider',
  any_principal: 'Any principal (*)',
  tier0_sink: 'Effective admin',
};

export const typography = {
  fontSans: 'Inter, system-ui, sans-serif',
  fontMono: '"JetBrains Mono", ui-monospace, monospace',
  sizes: { xs: 11, sm: 12, md: 14, lg: 16, xl: 20, xxl: 28 },
} as const;

export const space = { 1: 4, 2: 8, 3: 12, 4: 16, 5: 24, 6: 32, 7: 48 } as const;

export const radius = { sm: 4, md: 8, lg: 12 } as const;

export const motion = {
  fast: 200,
  camera: 300,
  slow: 350,
  easing: 'cubic-bezier(0.2, 0, 0, 1)',
  flowSpeed: 24, // px per second for the dash animation along paths
} as const;

/** Node radius from blast radius: square-root scale clamped to [4, 18] px. */
export const nodeSize = { min: 4, max: 18 } as const;

export function nodeRadius(reachablePrincipals: number, maxReachable: number): number {
  if (maxReachable <= 0 || reachablePrincipals <= 0) {
    return nodeSize.min;
  }
  const t = Math.sqrt(Math.min(reachablePrincipals, maxReachable) / maxReachable);
  return nodeSize.min + t * (nodeSize.max - nodeSize.min);
}

/** Tier ring width; Tier 0 is thicker so it reads without color. */
export function tierRingWidth(tier: Tier): number {
  return tier === 0 ? 3 : 1.5;
}

/** Opacity used for context (non-focused) elements in focus + context mode. */
export const dimmedOpacity = 0.1;
export const staleOpacity = 0.55;

/** Converts a camelCase token name into its CSS custom property name. */
export function cssVarName(token: string): string {
  return `--color-${token.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)}`;
}

/** Returns every CSS custom property of a theme, sorted for determinism. */
export function cssVariables(theme: ThemeName): [string, string][] {
  const t = themes[theme];
  const vars: [string, string][] = [];
  for (const name of Object.keys(t.colors) as (keyof ColorTokens)[]) {
    vars.push([cssVarName(name), t.colors[name]]);
  }
  for (const tier of tiers) {
    vars.push([`--tier-${String(tier)}`, t.tier[tier]]);
  }
  for (const kind of escalationEdgeKinds) {
    vars.push([`--edge-${kind.replace(/_/g, '-')}`, t.edge[kind]]);
  }
  for (const severity of severities) {
    vars.push([`--severity-${severity}`, t.severity[severity]]);
  }
  for (const level of capabilityLevels) {
    vars.push([`--intensity-${level.replace(/_/g, '-')}`, t.intensity[level]]);
  }
  for (const state of detectionStates) {
    vars.push([`--detection-${state}`, t.detection[state]]);
  }
  return vars.sort(([a], [b]) => a.localeCompare(b));
}

/** Writes the theme onto an element (normally <html>) via the CSSOM, which the
 * strict CSP allows, unlike inline style attributes in markup. */
export function applyTheme(root: HTMLElement, theme: ThemeName): void {
  for (const [name, value] of cssVariables(theme)) {
    root.style.setProperty(name, value);
  }
  root.style.setProperty('--font-sans', typography.fontSans);
  root.style.setProperty('--font-mono', typography.fontMono);
  root.style.setProperty('--edge-structural', themes[theme].colors.edgeStructural);
  root.style.setProperty('--motion-fast', `${String(motion.fast)}ms`);
  root.style.setProperty('--motion-slow', `${String(motion.slow)}ms`);
  root.style.setProperty('--motion-easing', motion.easing);
  root.dataset.theme = theme;
}

/** Picks the theme from an explicit choice or the OS preference. */
export function resolveTheme(choice: ThemeName | 'system', prefersDark: boolean): ThemeName {
  if (choice === 'system') {
    return prefersDark ? 'dark' : 'light';
  }
  return choice;
}
