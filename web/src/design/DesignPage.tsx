import { AttackBadge } from './AttackBadge';
import { contrastRatio } from './color';
import { DetectionIndicator } from './DetectionIndicator';
import { EdgeStroke } from './EdgeStroke';
import { Glyph, type GlyphState } from './Glyph';
import { ExposureMockup } from './mockups/ExposureMockup';
import { OverviewMockup } from './mockups/OverviewMockup';
import { ReachMockup } from './mockups/ReachMockup';
import { TraceMockup } from './mockups/TraceMockup';
import { useTheme } from './theme';
import {
  capabilityLabels,
  capabilityLevels,
  detectionLabels,
  detectionStates,
  edgeLabels,
  escalationEdgeKinds,
  nodeKinds,
  nodeLabels,
  severities,
  structuralEdgeKinds,
  tiers,
  type ThemeName,
} from './tokens';

interface Variant {
  label: string;
  state: GlyphState;
  stale?: boolean;
  conditional?: boolean;
}
const variants: Variant[] = [
  { label: 'normal', state: 'normal' },
  { label: 'hover', state: 'hover' },
  { label: 'selected', state: 'selected' },
  { label: 'dimmed', state: 'dimmed' },
  { label: 'stale', state: 'normal', stale: true },
  { label: 'conditional', state: 'normal', conditional: true },
];

function Swatch({ name, color, on }: { name: string; color: string; on: string }) {
  return (
    <figure className="swatch">
      <svg width={40} height={40} aria-hidden="true">
        <rect width={40} height={40} rx={8} fill={color} />
      </svg>
      <figcaption>
        <span className="swatch__name">{name}</span>
        <code>{color}</code>
        <span className="swatch__contrast">{contrastRatio(color, on).toFixed(1)}:1</span>
      </figcaption>
    </figure>
  );
}

function GlyphMatrix() {
  return (
    <table className="glyph-table">
      <caption className="visually-hidden">Node glyphs in every state</caption>
      <thead>
        <tr>
          <th scope="col">Kind</th>
          {variants.map((v) => (
            <th key={v.label} scope="col">
              {v.label}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {nodeKinds.map((kind) => (
          <tr key={kind}>
            <th scope="row">{nodeLabels[kind]}</th>
            {variants.map((v) => (
              <td key={v.label}>
                <svg width={52} height={52} viewBox="-26 -26 52 52" aria-hidden="true">
                  <Glyph
                    kind={kind}
                    tier={kind === 'tier0_sink' ? 0 : 1}
                    radius={11}
                    state={v.state}
                    stale={v.stale ?? false}
                    conditional={v.conditional ?? false}
                  />
                </svg>
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function EdgeSamples() {
  const all = [...escalationEdgeKinds, ...structuralEdgeKinds];
  return (
    <ul className="edge-samples">
      {all.map((kind) => (
        <li key={kind}>
          <svg width={150} height={20} aria-hidden="true">
            <EdgeStroke kind={kind} d="M4 10 L142 10" />
          </svg>
          <span>{edgeLabels[kind]}</span>
          <code>{kind}</code>
        </li>
      ))}
      <li>
        <svg width={150} height={20} aria-hidden="true">
          <EdgeStroke kind="assume" d="M4 10 L142 10" conditional />
        </svg>
        <span>Conditional (unevaluated condition)</span>
        <code>status: conditional</code>
      </li>
      <li>
        <svg width={150} height={20} aria-hidden="true">
          <EdgeStroke kind="passrole_compute" d="M4 10 L142 10" width={5.2} />
        </svg>
        <span>Choke point (width = log₂(1 + paths cut))</span>
        <code>paths_cut: 3</code>
      </li>
      <li>
        <svg width={150} height={20} aria-hidden="true">
          <EdgeStroke kind="modify_permissions" d="M4 10 L142 10" flow />
        </svg>
        <span>Flow animation on escalation paths</span>
        <code>off with reduced motion</code>
      </li>
    </ul>
  );
}

export function DesignPage({
  themeChoice,
  onThemeChoice,
}: {
  themeChoice: ThemeName | 'system';
  onThemeChoice: (choice: ThemeName | 'system') => void;
}) {
  const theme = useTheme();
  const on = theme.colors.surface;
  return (
    <main className="design">
      <header className="design__header">
        <div>
          <h1>escalint · visual language</h1>
          <p className="muted">
            Phase 1D prototype. Static mockups use a hand-drawn sample of the vulnerable example
            account; identifiers are fake.
          </p>
        </div>
        <fieldset className="theme-switch">
          <legend>Theme</legend>
          {(['system', 'light', 'dark'] as const).map((choice) => (
            <label key={choice}>
              <input
                type="radio"
                name="theme"
                value={choice}
                checked={themeChoice === choice}
                onChange={() => {
                  onThemeChoice(choice);
                }}
              />
              {choice}
            </label>
          ))}
        </fieldset>
      </header>

      <section aria-labelledby="sec-glyphs">
        <h2 id="sec-glyphs">Node glyphs</h2>
        <p className="muted">
          Shape encodes the kind, the outer ring encodes the tier (thicker for Tier 0), size encodes
          blast radius. Stale nodes fade and get a dotted ring; conditional tiers get a dashed ring.
        </p>
        <GlyphMatrix />
        <div className="tier-row">
          {tiers.map((t) => (
            <figure key={t}>
              <svg width={52} height={52} viewBox="-26 -26 52 52" aria-hidden="true">
                <Glyph kind="role" tier={t} radius={11} />
              </svg>
              <figcaption>Tier {t}</figcaption>
            </figure>
          ))}
          {[4, 8, 13, 18].map((r) => (
            <figure key={r}>
              <svg width={52} height={52} viewBox="-26 -26 52 52" aria-hidden="true">
                <Glyph kind="user" tier={2} radius={r} />
              </svg>
              <figcaption>r = {r}px</figcaption>
            </figure>
          ))}
        </div>
      </section>

      <section aria-labelledby="sec-edges">
        <h2 id="sec-edges">Edges</h2>
        <p className="muted">
          Seven categorical colors (CIEDE2000 ≥ 15 apart, also under protanopia and deuteranopia)
          and a stroke pattern per kind, so color is never the only channel.
        </p>
        <EdgeSamples />
      </section>

      <section aria-labelledby="sec-detection">
        <h2 id="sec-detection">Detection and ATT&amp;CK</h2>
        <ul className="detection-samples">
          {detectionStates.map((state) => (
            <li key={state}>
              <svg width={20} height={20} viewBox="-10 -10 20 20" aria-hidden="true">
                <DetectionIndicator state={state} size={12} />
              </svg>
              <span>{detectionLabels[state]}</span>
            </li>
          ))}
        </ul>
        <div className="badges">
          <AttackBadge
            techniqueId="T1098.003"
            name="Additional Cloud Roles"
            tactics={['Persistence', 'Privilege Escalation']}
          />
        </div>
        <p className="muted">
          Technique shown as a style sample; mappings are verified in Phase 1E.
        </p>
      </section>

      <section aria-labelledby="sec-color">
        <h2 id="sec-color">Color tokens</h2>
        <h3>Tiers (sequential)</h3>
        <div className="swatches">
          {tiers.map((t) => (
            <Swatch key={t} name={`Tier ${String(t)}`} color={theme.tier[t]} on={on} />
          ))}
        </div>
        <h3>Edges (categorical)</h3>
        <div className="swatches">
          {escalationEdgeKinds.map((k) => (
            <Swatch key={k} name={k} color={theme.edge[k]} on={on} />
          ))}
        </div>
        <h3>Severity (text, AA)</h3>
        <div className="swatches">
          {severities.map((s) => (
            <Swatch key={s} name={s} color={theme.severity[s]} on={on} />
          ))}
        </div>
        <h3>Exposure intensity</h3>
        <div className="swatches">
          {capabilityLevels.map((l) => (
            <Swatch key={l} name={capabilityLabels[l]} color={theme.intensity[l]} on={on} />
          ))}
        </div>
      </section>

      <section aria-labelledby="sec-type">
        <h2 id="sec-type">Typography</h2>
        <p className="type-sample type-sample--sans">
          Inter — Who can reach what in your AWS IAM. 0123456789
        </p>
        <p className="type-sample type-sample--mono">
          JetBrains Mono — arn:aws:iam::111111111111:role/LambdaExecAdmin
        </p>
      </section>

      <section aria-labelledby="sec-overview">
        <h2 id="sec-overview">Mockup · Overview</h2>
        <OverviewMockup />
      </section>
      <section aria-labelledby="sec-trace">
        <h2 id="sec-trace">Mockup · Trace</h2>
        <TraceMockup />
      </section>
      <div className="mockup-pair">
        <section aria-labelledby="sec-reach">
          <h2 id="sec-reach">Mockup · Reach</h2>
          <ReachMockup />
        </section>
        <section aria-labelledby="sec-exposure">
          <h2 id="sec-exposure">Mockup · Exposure</h2>
          <ExposureMockup />
        </section>
      </div>
    </main>
  );
}
