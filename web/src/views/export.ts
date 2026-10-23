// Exports a view as SVG or PNG without any dependency: the SVG is the
// view's own DOM serialized with computed colors inlined (CSS variables do
// not survive outside the page); PNG draws that SVG on a canvas.

const styled = [
  'fill',
  'stroke',
  'stroke-width',
  'stroke-dasharray',
  'opacity',
  'font-family',
  'font-size',
  'font-weight',
];

function inlineStyles(source: Element, target: Element): void {
  const cs = window.getComputedStyle(source);
  const decl: string[] = [];
  for (const p of styled) {
    const v = cs.getPropertyValue(p);
    if (v) decl.push(`${p}:${v}`);
  }
  if (decl.length && target instanceof SVGElement) target.setAttribute('style', decl.join(';'));
  for (let i = 0; i < source.children.length; i++) {
    const s = source.children[i];
    const t = target.children[i];
    if (s && t) inlineStyles(s, t);
  }
}

export function serializeSVG(svg: SVGSVGElement): string {
  const clone = svg.cloneNode(true) as SVGSVGElement;
  clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
  inlineStyles(svg, clone);
  // Interactive attributes mean nothing in a file.
  for (const el of clone.querySelectorAll('[tabindex]')) el.removeAttribute('tabindex');
  return new XMLSerializer().serializeToString(clone);
}

function save(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export function exportSVG(svg: SVGSVGElement, name: string): void {
  save(new Blob([serializeSVG(svg)], { type: 'image/svg+xml' }), name);
}

export async function exportPNG(svg: SVGSVGElement, name: string, scale = 2): Promise<void> {
  const url = URL.createObjectURL(new Blob([serializeSVG(svg)], { type: 'image/svg+xml' }));
  try {
    const img = new Image();
    img.src = url;
    await img.decode();
    const canvas = document.createElement('canvas');
    canvas.width = Math.ceil(svg.width.baseVal.value * scale);
    canvas.height = Math.ceil(svg.height.baseVal.value * scale);
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.fillStyle = window.getComputedStyle(document.body).backgroundColor;
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.scale(scale, scale);
    ctx.drawImage(img, 0, 0);
    const blob = await new Promise<Blob | null>((resolve) => {
      canvas.toBlob(resolve, 'image/png');
    });
    if (blob) save(blob, name);
  } finally {
    URL.revokeObjectURL(url);
  }
}

/** PNG of a canvas (Atlas, Exposure). */
export function exportCanvasPNG(canvas: HTMLCanvasElement, name: string): void {
  canvas.toBlob((blob) => {
    if (blob) save(blob, name);
  }, 'image/png');
}
