// Uniform grid over world positions for hit testing (hover, click).

export class SpatialGrid {
  private readonly cells = new Map<string, number[]>();

  constructor(
    private readonly xs: ArrayLike<number>,
    private readonly ys: ArrayLike<number>,
    private readonly cell = 40,
  ) {
    for (let i = 0; i < xs.length; i++) {
      const k = this.key(xs[i] ?? 0, ys[i] ?? 0);
      const list = this.cells.get(k);
      if (list) list.push(i);
      else this.cells.set(k, [i]);
    }
  }

  private key(x: number, y: number): string {
    return `${String(Math.floor(x / this.cell))},${String(Math.floor(y / this.cell))}`;
  }

  /** Index of the nearest point within maxDist, or -1. skip filters out
   * hidden points. */
  nearest(
    x: number,
    y: number,
    maxDist: number,
    skip: (i: number) => boolean = () => false,
  ): number {
    let best = -1;
    let bestD = maxDist;
    const r = Math.ceil(maxDist / this.cell);
    const cx = Math.floor(x / this.cell);
    const cy = Math.floor(y / this.cell);
    for (let gx = cx - r; gx <= cx + r; gx++) {
      for (let gy = cy - r; gy <= cy + r; gy++) {
        for (const i of this.cells.get(`${String(gx)},${String(gy)}`) ?? []) {
          if (skip(i)) continue;
          const d = Math.hypot((this.xs[i] ?? 0) - x, (this.ys[i] ?? 0) - y);
          if (d < bestD || (d === bestD && i < best)) {
            best = i;
            bestD = d;
          }
        }
      }
    }
    return best;
  }
}
