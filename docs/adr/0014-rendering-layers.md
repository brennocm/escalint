# 0014 — Layered rendering: WebGL, Canvas 2D, SVG and DOM

Status: Accepted

## Context

The UI must draw 10,000 nodes and 40,000 edges smoothly (Atlas), small
graphs that are fully accessible (Trace, Reach), a dense matrix
(Exposure), and tables everywhere, under a strict CSP and a small
dependency budget (ADR 0013).

## Decision

| Layer | Technology | Where |
| --- | --- | --- |
| Large graph | own WebGL2 renderer: instanced quads; node glyphs drawn with signed distance functions in the fragment shader; edges with the kind's dash pattern in screen pixels | Atlas |
| Group areas, labels with halo and collision, meta-nodes, minimap | Canvas 2D overlay | Atlas |
| Small interactive graphs | SVG React components (focusable, keyboard navigation) | Trace, Reach, Diff |
| Dense matrix | Canvas 2D, only visible rows drawn | Exposure |
| Panels, tables, search | DOM | all |

- **No sigma.js / graphology / ELK.** The Atlas needs custom programs for
  the eight glyphs anyway; a 300-line renderer with no dependency is easier
  to audit than a framework plus plugins. A Trace path is a chain, so a
  layered layout reduces to columns by hop count (`views/trace/layout.ts`);
  ELK (EPL-2.0, ~1 MB) is not needed.
- SDF functions live in `views/atlas/sdf.ts` (tested at known points) and
  are mirrored in GLSL in `renderer.ts`.
- Force layout (Barnes–Hut repulsion, linear attraction, gravity to each
  account's anchor) runs in a Web Worker (`workers/layout.worker.ts`), with
  a main-thread fallback where workers are unavailable (single-file
  report under `file://`).
- Every graphical view has an equivalent table, and canvases are
  `aria-hidden`.
- Without WebGL2 the Atlas shows a notice and the table.

## Consequences

- Initial JavaScript is about 80 KB gzip; views load on demand.
- Visual fidelity of WebGL depends on the GPU; visual baselines mask the
  WebGL canvas (ADR 0019).
