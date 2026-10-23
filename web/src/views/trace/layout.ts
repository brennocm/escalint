import type { Path } from '../../contract/analysis';
import type { Indexes } from '../../data/indexes';

// Layered layout of a path and its alternatives (the other enumerated paths
// from the same source): one row per path, one column per step, so the
// same position always means the same hop count. Deterministic: rows are
// the chosen path first, then alternatives by length and ID.

export const card = { width: 196, height: 64, gapX: 150, gapY: 40, pad: 16 } as const;

export interface CardBox {
  readonly id: string; // node ID
  readonly x: number;
  readonly y: number;
  readonly row: number;
  readonly col: number;
}

export interface EdgeLine {
  readonly id: string;
  readonly row: number;
  readonly x1: number;
  readonly y1: number;
  readonly x2: number;
  readonly y2: number;
}

export interface TraceLayout {
  readonly rows: readonly Path[];
  readonly cards: readonly CardBox[];
  readonly edges: readonly EdgeLine[];
  readonly width: number;
  readonly height: number;
}

export function alternatives(ix: Indexes, path: Path): Path[] {
  return (ix.pathsByNode.get(path.source) ?? [])
    .filter((p) => p.source === path.source && p.id !== path.id)
    .sort((a, b) => a.length - b.length || (a.id < b.id ? -1 : 1));
}

export function traceLayout(ix: Indexes, path: Path, maxRows = 3): TraceLayout {
  const rows = [path, ...alternatives(ix, path)].slice(0, maxRows);
  const cards: CardBox[] = [];
  const edges: EdgeLine[] = [];
  let cols = 0;
  rows.forEach((p, row) => {
    const y = card.pad + row * (card.height + card.gapY);
    p.nodes.forEach((id, col) => {
      cards.push({ id, x: card.pad + col * (card.width + card.gapX), y, row, col });
    });
    p.edges.forEach((id, col) => {
      const x1 = card.pad + col * (card.width + card.gapX) + card.width;
      edges.push({
        id,
        row,
        x1,
        y1: y + card.height / 2,
        x2: x1 + card.gapX,
        y2: y + card.height / 2,
      });
    });
    cols = Math.max(cols, p.nodes.length);
  });
  return {
    rows,
    cards,
    edges,
    width: card.pad * 2 + cols * card.width + Math.max(0, cols - 1) * card.gapX,
    height: card.pad * 2 + rows.length * card.height + Math.max(0, rows.length - 1) * card.gapY,
  };
}

/** Stroke width of an edge from the number of paths through it (log). */
export function chokeWidth(pathsCut: number): number {
  return 1.75 + Math.min(4, Math.log2(Math.max(1, pathsCut)));
}

/** Next card for keyboard navigation (arrows). */
export function neighbor(l: TraceLayout, from: CardBox, key: string): CardBox | undefined {
  const at = (row: number, col: number): CardBox | undefined =>
    l.cards.find((c) => c.row === row && c.col === col);
  switch (key) {
    case 'ArrowRight':
      return at(from.row, from.col + 1);
    case 'ArrowLeft':
      return at(from.row, from.col - 1);
    case 'ArrowDown':
      return at(from.row + 1, Math.min(from.col, (l.rows[from.row + 1]?.nodes.length ?? 1) - 1));
    case 'ArrowUp':
      return at(from.row - 1, Math.min(from.col, (l.rows[from.row - 1]?.nodes.length ?? 1) - 1));
    default:
      return undefined;
  }
}
