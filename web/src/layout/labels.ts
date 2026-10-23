// Label placement for the Atlas: candidates sorted by priority (tier, then
// blast radius, then degree) claim cells of a screen-space grid; a label
// that overlaps an already placed label or a focused node is skipped.

export interface LabelCandidate {
  readonly id: string;
  readonly x: number; // screen position of the node
  readonly y: number;
  readonly r: number; // node radius on screen
  readonly width: number; // text width in px
  readonly tier: number;
  readonly blast: number;
  readonly degree: number;
  readonly focused?: boolean;
}

export interface PlacedLabel {
  readonly id: string;
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
}

export function priority(a: LabelCandidate, b: LabelCandidate): number {
  return (
    Number(b.focused ?? false) - Number(a.focused ?? false) ||
    a.tier - b.tier ||
    b.blast - a.blast ||
    b.degree - a.degree ||
    (a.id < b.id ? -1 : 1)
  );
}

export function placeLabels(
  cands: readonly LabelCandidate[],
  view: { width: number; height: number },
  height = 14,
  cell = 32,
  max = 400,
): PlacedLabel[] {
  const sorted = [...cands].sort(priority);
  const grid = new Map<string, PlacedLabel[]>();
  const focused = cands.filter((c) => c.focused);
  const placed: PlacedLabel[] = [];
  const overlaps = (
    a: PlacedLabel,
    b: { x: number; y: number; width: number; height: number },
  ): boolean =>
    a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height && b.y < a.y + a.height;
  for (const c of sorted) {
    if (placed.length >= max) break;
    const box: PlacedLabel = {
      id: c.id,
      x: c.x - c.width / 2,
      y: c.y + c.r + 3,
      width: c.width,
      height,
    };
    if (
      box.x < 0 ||
      box.y < 0 ||
      box.x + box.width > view.width ||
      box.y + box.height > view.height
    )
      continue;
    const cells: string[] = [];
    for (let gx = Math.floor(box.x / cell); gx <= Math.floor((box.x + box.width) / cell); gx++) {
      for (let gy = Math.floor(box.y / cell); gy <= Math.floor((box.y + box.height) / cell); gy++)
        cells.push(`${String(gx)},${String(gy)}`);
    }
    if (cells.some((k) => (grid.get(k) ?? []).some((p) => overlaps(p, box)))) continue;
    // Never cover a focused node.
    if (
      !c.focused &&
      focused.some((f) =>
        overlaps(box, { x: f.x - f.r, y: f.y - f.r, width: 2 * f.r, height: 2 * f.r }),
      )
    )
      continue;
    placed.push(box);
    for (const k of cells) grid.set(k, [...(grid.get(k) ?? []), box]);
  }
  return placed;
}
