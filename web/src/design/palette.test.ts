// Palette validation rules from docs/design.md. If you change a color in
// tokens.ts, these tests tell you whether it is still accessible.
import { describe, expect, it } from 'vitest';
import { contrastRatio, perceivedDistance, perceivedLightness, type Vision } from './color';
import {
  capabilityLevels,
  detectionStates,
  escalationEdgeKinds,
  severities,
  themes,
  tiers,
  type ColorTokens,
  type ThemeName,
} from './tokens';

const themeNames: ThemeName[] = ['light', 'dark'];
const visions: Vision[] = ['normal', 'protanopia', 'deuteranopia'];
const backgrounds = (t: ThemeName) => [themes[t].colors.bg, themes[t].colors.surface];

const AA_TEXT = 4.5;
const AA_GRAPHICS = 3;
const MIN_CATEGORICAL_DE = 15;
const MIN_SEQUENTIAL_STEP_DE = 10;

describe.each(themeNames)('%s theme', (theme) => {
  const t = themes[theme];

  it.each<keyof ColorTokens>(['text', 'textMuted', 'accent'])(
    'text token %s meets WCAG AA on bg and surface',
    (token) => {
      for (const bg of backgrounds(theme)) {
        expect(contrastRatio(t.colors[token], bg)).toBeGreaterThanOrEqual(AA_TEXT);
      }
    },
  );

  it.each(severities)('severity %s meets WCAG AA as text', (severity) => {
    for (const bg of backgrounds(theme)) {
      expect(contrastRatio(t.severity[severity], bg)).toBeGreaterThanOrEqual(AA_TEXT);
    }
  });

  it.each<keyof ColorTokens>(['focus', 'nodeStroke', 'edgeStructural'])(
    'graphic token %s meets 3:1 (WCAG 1.4.11)',
    (token) => {
      for (const bg of backgrounds(theme)) {
        expect(contrastRatio(t.colors[token], bg)).toBeGreaterThanOrEqual(AA_GRAPHICS);
      }
    },
  );

  it('edge and tier colors meet 3:1 against the background', () => {
    const colors = [...escalationEdgeKinds.map((k) => t.edge[k]), ...tiers.map((x) => t.tier[x])];
    for (const color of colors) {
      for (const bg of backgrounds(theme)) {
        expect(contrastRatio(color, bg), `${color} on ${bg}`).toBeGreaterThanOrEqual(AA_GRAPHICS);
      }
    }
  });

  it.each(visions)('edge colors are >= 15 CIEDE2000 apart under %s vision', (vision) => {
    for (const [i, a] of escalationEdgeKinds.entries()) {
      for (const b of escalationEdgeKinds.slice(i + 1)) {
        const d = perceivedDistance(t.edge[a], t.edge[b], vision);
        expect(d, `${a} vs ${b}`).toBeGreaterThanOrEqual(MIN_CATEGORICAL_DE);
      }
    }
  });

  it.each(visions)('tier ramp is monotonic and distinguishable under %s vision', (vision) => {
    // Light theme: more critical = darker. Dark theme: more critical = brighter.
    const direction = theme === 'light' ? -1 : 1;
    const ramp = [3, 2, 1, 0] as const;
    for (let i = 0; i < ramp.length - 1; i++) {
      const lower = t.tier[ramp[i] ?? 3];
      const higher = t.tier[ramp[i + 1] ?? 0];
      const step = perceivedLightness(higher, vision) - perceivedLightness(lower, vision);
      expect(direction * step, `lightness step ${lower} -> ${higher}`).toBeGreaterThan(0);
      expect(perceivedDistance(lower, higher, vision)).toBeGreaterThanOrEqual(
        MIN_SEQUENTIAL_STEP_DE,
      );
    }
  });

  it.each(visions)('exposure intensity ramp is monotonic under %s vision', (vision) => {
    const direction = theme === 'light' ? -1 : 1;
    for (let i = 0; i < capabilityLevels.length - 1; i++) {
      const weaker = t.intensity[capabilityLevels[i] ?? 'list'];
      const stronger = t.intensity[capabilityLevels[i + 1] ?? 'permission_management'];
      const step = perceivedLightness(stronger, vision) - perceivedLightness(weaker, vision);
      expect(direction * step).toBeGreaterThan(0);
      expect(perceivedDistance(weaker, stronger, vision)).toBeGreaterThanOrEqual(
        MIN_SEQUENTIAL_STEP_DE,
      );
    }
  });

  it.each(detectionStates)('detection color %s meets WCAG AA as text', (state) => {
    for (const bg of backgrounds(theme)) {
      expect(contrastRatio(t.detection[state], bg)).toBeGreaterThanOrEqual(AA_TEXT);
    }
  });
});
