import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { AttackBadge } from './AttackBadge';
import { DesignPage } from './DesignPage';
import { DetectionIndicator } from './DetectionIndicator';
import { EdgeStroke } from './EdgeStroke';
import { Glyph } from './Glyph';
import { ThemeProvider } from './theme';
import { dimmedOpacity, themes } from './tokens';

function inSvg(node: React.ReactNode, theme: 'light' | 'dark' = 'light') {
  return render(
    <ThemeProvider name={theme}>
      <svg>{node}</svg>
    </ThemeProvider>,
  );
}

describe('Glyph', () => {
  it('has an accessible name and a tier-colored ring', () => {
    const { container } = inSvg(<Glyph kind="role" tier={0} radius={10} label="OrgAdmin" />);
    expect(container.querySelector('title')?.textContent).toBe('OrgAdmin');
    const ring = container.querySelector('circle');
    expect(ring?.getAttribute('stroke')).toBe(themes.light.tier[0]);
    expect(ring?.getAttribute('stroke-width')).toBe('3');
  });

  it('dims context nodes and draws a halo when selected', () => {
    const dimmed = inSvg(<Glyph kind="user" tier={2} radius={8} state="dimmed" />);
    expect(dimmed.container.querySelector('g')?.getAttribute('opacity')).toBe(
      String(dimmedOpacity),
    );
    const selected = inSvg(<Glyph kind="user" tier={2} radius={8} state="selected" />, 'dark');
    expect(selected.container.querySelector('circle')?.getAttribute('stroke')).toBe(
      themes.dark.colors.focus,
    );
  });

  it('marks stale nodes with a dotted ring', () => {
    const { container } = inSvg(<Glyph kind="role" tier={3} radius={8} stale />);
    expect(container.querySelector('circle')?.getAttribute('stroke-dasharray')).toBe('1 3');
  });

  it('draws the tier0 sink as two rings without a tier ring', () => {
    const { container } = inSvg(<Glyph kind="tier0_sink" tier={0} radius={10} />);
    expect(container.querySelectorAll('circle')).toHaveLength(1);
    expect(container.querySelectorAll('path')).toHaveLength(1);
  });
});

describe('EdgeStroke', () => {
  it('uses the kind color, dash pattern and a unique arrow marker', () => {
    const { container } = inSvg(
      <>
        <EdgeStroke kind="credential" d="M0 0 L10 0" />
        <EdgeStroke kind="assume" d="M0 0 L10 0" conditional />
      </>,
    );
    const strokes = container.querySelectorAll('path[marker-end]');
    expect(strokes[0]?.getAttribute('stroke')).toBe(themes.light.edge.credential);
    expect(strokes[0]?.getAttribute('stroke-dasharray')).toBe('2 3');
    expect(strokes[1]?.getAttribute('stroke-dasharray')).toBe('6 6');
    const markers = [...container.querySelectorAll('marker')].map((m) => m.id);
    expect(new Set(markers).size).toBe(2);
  });
});

describe('DetectionIndicator', () => {
  it.each([
    ['visible', 0],
    ['partial', 0],
    ['blind', 1],
  ] as const)('%s state has its own shape', (state, lines) => {
    const { container } = inSvg(<DetectionIndicator state={state} />);
    expect(container.querySelectorAll('line')).toHaveLength(lines);
    expect(container.querySelector('title')?.textContent).toMatch(/CloudTrail|visible|Blind/);
  });
});

describe('AttackBadge', () => {
  it('links out safely with visible text', () => {
    render(
      <AttackBadge
        techniqueId="T1098.003"
        name="Additional Cloud Roles"
        tactics={['Persistence']}
      />,
    );
    const link = screen.getByRole('link');
    expect(link.getAttribute('href')).toBe('https://attack.mitre.org/techniques/T1098/003/');
    expect(link.getAttribute('rel')).toBe('noopener noreferrer');
    expect(link.getAttribute('target')).toBe('_blank');
    expect(link.textContent).toContain('Additional Cloud Roles');
  });
});

describe('DesignPage', () => {
  it.each(['light', 'dark'] as const)(
    'renders every section in %s without inline styles',
    (theme) => {
      const { container } = render(
        <ThemeProvider name={theme}>
          <DesignPage themeChoice={theme} onThemeChoice={() => undefined} />
        </ThemeProvider>,
      );
      for (const heading of [
        'Node glyphs',
        'Edges',
        'Color tokens',
        'Mockup · Trace',
        'Mockup · Exposure',
      ]) {
        expect(screen.getByRole('heading', { name: heading })).toBeDefined();
      }
      // The strict CSP (style-src 'self') blocks style attributes in markup.
      expect(container.querySelectorAll('[style]')).toHaveLength(0);
    },
  );
});
