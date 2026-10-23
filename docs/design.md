# Visual language

The UI exists to answer one question fast: *who can reach what, and how?*
Every visual decision below serves legibility of that answer for people who
read graphs for a living, including people with color vision deficiencies.

Sources of truth: `web/src/design/tokens.ts` (values), `web/src/design/glyphs.ts`
(geometry), `web/src/design/palette.test.ts` (rules). The `#/design` route
(dev server and demo build only) shows everything on one page.

## Principles

1. **Clarity over ornament.** Decoration that does not encode data is removed.
2. **Shape and position before color.** Kind is a shape, tier is a ring,
   blast radius is size, edge kind is a stroke pattern; color repeats the
   information, it never carries it alone.
3. **Controlled density.** Focus + context: what matters is full strength,
   everything else drops to 10 % opacity.
4. **Every color means something.** There are no decorative colors; a color
   always maps to a tier, an edge kind, a severity, a capability level or a
   detection state.
5. **Hostile data is text.** Names, tags and policies are rendered as text
   nodes only (no HTML injection sinks; lint-enforced).

## Tokens

Components never use literal colors. SVG components read resolved token values
through `useTheme()` and pass them as presentation attributes, so exported SVG
files are self-contained; DOM components use the CSS custom properties that
`applyTheme()` writes through the CSSOM (allowed by the strict CSP, unlike
`style` attributes in markup).

| Group | Tokens |
| --- | --- |
| Surfaces | `bg`, `surface`, `surfaceRaised`, `border` |
| Text | `text`, `textMuted`, `accent`, `focus` |
| Graph | `nodeFill`, `nodeStroke`, `edgeStructural` |
| Palettes | `tier[0..3]`, `edge[kind]`, `severity[level]`, `intensity[level]`, `detection[state]` |
| Type | Inter (UI), JetBrains Mono (ARNs, actions, IDs); sizes 11–28 px |
| Space / radius | 4-px scale; radius 4 / 8 / 12 |
| Motion | 200 ms (fast), 300 ms (camera), 350 ms (slow); easing `cubic-bezier(0.2, 0, 0, 1)` |

Light and dark themes follow `prefers-color-scheme` by default and can be
forced from the UI.

## Palettes and their validation

Rules are unit tests (`palette.test.ts`); a palette edit that breaks one fails CI.

| Palette | Rule |
| --- | --- |
| Text tokens and severities | WCAG AA, ≥ 4.5:1 on `bg` and `surface` |
| Focus, node stroke, edges, tiers | ≥ 3:1 against the background (WCAG 1.4.11) |
| Edge kinds (7, categorical) | CIEDE2000 ≥ 15 between every pair, under normal vision, protanopia and deuteranopia |
| Tiers (4, sequential) | lightness strictly monotonic from Tier 3 to Tier 0 (darker in light theme, brighter in dark theme) under all three visions; adjacent steps ≥ 10 CIEDE2000 |
| Exposure intensity (4, sequential) | same rule as tiers |
| Detection states | ≥ 4.5:1 (they also appear as text) |

Color science lives in `web/src/design/color.ts`: WCAG relative luminance,
CIELAB (D65), CIEDE2000 tested against the reference pairs of Sharma, Wu and
Dalal (2005), and CVD simulation with the severity-1.0 matrices of Machado,
Oliveira and Fernandes (2009) applied in linear RGB.

The categorical palette was found by constrained search (hue kept within ±18°
of a semantic target per edge kind, minimum chroma, contrast ≥ 3:1) maximizing
the minimum pairwise CIEDE2000 across the three visions: the result is 15.7
(light) and 15.9 (dark). The margin is small by design — seven saturated,
semantically chosen hues that survive deuteranopia leave little room — which is
why every edge kind also has a stroke pattern.

**Known exception:** the two weakest Exposure levels (`list`, `read`) are below
3:1 against the background. Matrix cells always have a border, the selected
cell shows its level as text, and the matrix has an equivalent accessible table.

## Glyphs (shape = node kind)

| Kind | Shape |
| --- | --- |
| user | circle |
| role | hexagon |
| group | rounded square |
| service | diamond |
| external_account | circle with dashed outline |
| federated | pentagon |
| any_principal | 8-point star |
| tier0_sink | double ring |

Polygons are scaled (`glyphScale`) to match the visual area of the circle.
The Atlas implements the same shapes as signed distance functions in fragment
shaders (Phase 12); their TypeScript ports are tested against `glyphs.ts`.

**Encodings on a glyph**

- **Tier** → color of an outer ring; Tier 0 ring is 3 px, others 1.5 px.
- **Blast radius** → radius, square-root scale clamped to 4–18 px.
- **Stale** (unused for 90 days, when `last_used` exists) → 55 % opacity and a dotted ring.
- **Conditional tier** → dashed ring.
- **States** → hover: soft focus halo; selected: solid focus halo; dimmed: 10 % opacity.

## Edges

| Kind | Pattern |
| --- | --- |
| assume | solid |
| trust | dashed `8 4` |
| credential | dotted `2 3` |
| modify_permissions | solid |
| modify_trust | dashed `8 4` |
| passrole_compute | dotted `2 3` |
| update_code | dash-dot `10 3 2 3` |
| member_of (structural) | sparse dots, neutral color |
| admin (structural) | solid, neutral color |

- **Conditional** edges use long gaps `6 6` and the label says which condition
  keys were not evaluated.
- **Choke points**: width = 1.75 + 1.5 · log₂(1 + paths cut).
- **Arrowheads** are sized in user space (7 px + width) so thick edges stay legible.
- **Flow animation** (a moving dash) marks escalation paths; it is removed under
  `prefers-reduced-motion`.

## Detection and ATT&CK (addendum)

Each exploitation step shows its CloudTrail visibility with a shape:

| State | Shape |
| --- | --- |
| visible | filled disc |
| partial | half-filled disc |
| blind spot | ring with a diagonal slash |

ATT&CK techniques are text badges (`ID`, name, tactics), never icon-only. They
link to `attack.mitre.org` as user-initiated navigation with
`rel="noopener noreferrer"`; the app never fetches anything external.

## Typography

Inter (variable) for UI text with tabular numerals for counts; JetBrains Mono
(variable) for ARNs, actions, rule and path IDs. Both are OFL, self-hosted as
latin subsets in `web/src/assets/fonts/` (66 KB and 38 KB woff2) with their
licenses; neither declares a Reserved Font Name, so subsets keep the original
names. Fonts live under `src/assets` (not `public/`) so Vite bundles them and
the same build works under `serve`, a Pages sub-path and `file://`.

## Motion

Camera transitions 200–350 ms with the shared easing; no motion conveys
information on its own; everything animated stops under
`prefers-reduced-motion`.

## States

Every view designs empty (no paths: say so and show what was analyzed),
loading (skeleton, no spinners on data that arrives in < 300 ms) and error
(what failed, how to fix it, never a stack trace). Detailed in Phase 11.

## Mockups (Phase 1D)

The `#/design` page renders static mockups of Overview, Trace, Reach and
Exposure from a hand-drawn sample of `examples/vulnerable-account`
(`web/src/design/mock/vulnerableAccount.ts`). They fix the visual language, not
the layouts: in the shipped views Trace uses a layered layout by hop count,
Reach the custom radial layout and Exposure a Canvas matrix (ADR 0014).

Regenerate the checkpoint screenshots with `pnpm design:screenshots`
(`SCREENSHOT_DIR` sets the output folder).

## Final views

Captured from the production build on `examples/vulnerable-account` by
`make demo-video` (1280×800, reduced motion); the README shows all of them.

| View | Light | Dark |
| --- | --- | --- |
| Overview | ![Overview view, light theme](media/views/overview-light.png) | ![Overview view, dark theme](media/views/overview-dark.png) |
| Atlas | ![Atlas view, light theme](media/views/atlas-light.png) | ![Atlas view, dark theme](media/views/atlas-dark.png) |
| Trace | ![Trace view, light theme](media/views/trace-light.png) | ![Trace view, dark theme](media/views/trace-dark.png) |
| Reach | ![Reach view, light theme](media/views/reach-light.png) | ![Reach view, dark theme](media/views/reach-dark.png) |
| Exposure | ![Exposure view, light theme](media/views/exposure-light.png) | ![Exposure view, dark theme](media/views/exposure-dark.png) |
| Findings | ![Findings view, light theme](media/views/findings-light.png) | ![Findings view, dark theme](media/views/findings-dark.png) |
| Fix plan | ![Fix view, light theme](media/views/fix-light.png) | ![Fix view, dark theme](media/views/fix-dark.png) |
| Detect | ![Detect view, light theme](media/views/detect-light.png) | ![Detect view, dark theme](media/views/detect-dark.png) |
| Diff | ![Diff view, light theme](media/views/diff-light.png) | ![Diff view, dark theme](media/views/diff-dark.png) |
