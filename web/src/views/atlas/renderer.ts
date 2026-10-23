import { hexToRgb } from '../../design/color';

// WebGL2 renderer of the Atlas (ADR 0014). Nodes are instanced quads whose
// fragment shader draws the kind's glyph with a signed distance function
// (crisp at any zoom; same functions as sdf.ts) plus the tier ring. Edges
// are instanced quads with the kind's dash pattern computed in screen
// pixels. All colors come from the theme tokens.

export interface NodeAttrs {
  readonly x: Float32Array;
  readonly y: Float32Array;
  readonly radius: Float32Array; // px at zoom 1
  readonly kind: Float32Array; // sdf.kindCodes
  readonly ring: readonly string[]; // tier color (hex)
  readonly flags: Uint8Array; // NodeFlag bits
}

export interface EdgeAttrs {
  readonly from: Uint32Array; // node index
  readonly to: Uint32Array;
  readonly color: readonly string[];
  readonly width: Float32Array; // px
  readonly dash: Float32Array; // 4 per edge: on, off, on, off (0 = solid)
  readonly flags: Uint8Array; // EdgeFlag bits
}

export const NodeFlag = {
  stale: 1,
  dimmed: 2,
  selected: 4,
  conditional: 8,
  hover: 16,
  hidden: 32,
  tier0: 64,
} as const;
export const EdgeFlag = { dimmed: 1, highlight: 2, hidden: 4 } as const;

export interface Palette {
  readonly fill: string;
  readonly stroke: string;
  readonly focus: string;
  readonly bg: string;
}

export interface Camera {
  readonly x: number;
  readonly y: number;
  readonly zoom: number;
}

const nodeVS = `#version 300 es
in vec2 a_corner;
in vec2 a_pos;
in float a_radius;
in float a_kind;
in vec3 a_ring;
in float a_flags;
uniform vec3 u_cam;
uniform vec2 u_view;
out vec2 v_uv;
out float v_kind;
out vec3 v_ring;
out float v_flags;
out float v_px;
const float EXTENT = 1.75;
void main() {
  float r = clamp(a_radius * sqrt(u_cam.z), 2.0, 48.0);
  vec2 s = (a_pos - u_cam.xy) * u_cam.z + u_view * 0.5 + a_corner * r * EXTENT;
  gl_Position = vec4(s / u_view * 2.0 - 1.0, 0.0, 1.0);
  gl_Position.y = -gl_Position.y;
  v_uv = a_corner * EXTENT;
  v_kind = a_kind;
  v_ring = a_ring;
  v_flags = a_flags;
  v_px = r;
}`;

const nodeFS = `#version 300 es
precision highp float;
in vec2 v_uv;
in float v_kind;
in vec3 v_ring;
in float v_flags;
in float v_px;
uniform vec3 u_fill;
uniform vec3 u_stroke;
uniform vec3 u_focus;
uniform float u_dim;
out vec4 color;
const float PI = 3.14159265;
float sdCircle(vec2 p, float r) { return length(p) - r; }
float sdPolygon(vec2 p, float r, float n) {
  float an = PI / n;
  float a = atan(p.x, p.y);
  a = mod(a, 2.0 * an) - an;
  return length(p) * cos(a) - r * cos(an);
}
float sdRoundedSquare(vec2 p, float h, float c) {
  vec2 q = abs(p) - h + c;
  return length(max(q, 0.0)) + min(max(q.x, q.y), 0.0) - c;
}
float sdDiamond(vec2 p, float r) { return (abs(p.x) + abs(p.y) - r) / sqrt(2.0); }
float sdStar(vec2 p, float r, float n, float k) {
  float an = PI / n;
  float a = mod(atan(p.x, p.y), 2.0 * an);
  if (a > an) a = 2.0 * an - a;
  vec2 q = length(p) * vec2(cos(a), sin(a));
  vec2 A = vec2(r, 0.0);
  vec2 B = r * k * vec2(cos(an), sin(an));
  float t = clamp(dot(q - A, B - A) / dot(B - A, B - A), 0.0, 1.0);
  float d = length(q - (A + t * (B - A)));
  float side = (B.x - A.x) * (q.y - A.y) - (B.y - A.y) * (q.x - A.x);
  return side > 0.0 ? -d : d;
}
float glyph(int kind, vec2 p) {
  if (kind == 1) return sdPolygon(p, 1.0, 6.0);
  if (kind == 2) return sdRoundedSquare(p, 0.85, 0.25);
  if (kind == 3) return sdDiamond(p, 1.1);
  if (kind == 5) return sdPolygon(p, 1.0, 5.0);
  if (kind == 6) return sdStar(p, 1.1, 8.0, 0.55);
  if (kind == 7) return min(abs(sdCircle(p, 0.95)) - 0.12, abs(sdCircle(p, 0.6)) - 0.12);
  return sdCircle(p, 1.0);
}
bool flag(float f, float bit) { return mod(floor(f / bit), 2.0) == 1.0; }
void main() {
  if (flag(v_flags, 32.0)) discard;
  int kind = int(v_kind + 0.5);
  float aa = 1.5 / v_px;
  float d = glyph(kind, v_uv);
  float ang = atan(v_uv.y, v_uv.x);
  vec4 c = vec4(0.0);
  // Fill and outline (dashed outline for external accounts).
  float fill = 1.0 - smoothstep(-aa, aa, d);
  float edge = 1.0 - smoothstep(0.0, aa * 1.5, abs(d) - 0.08);
  if (kind == 4 && mod(ang * 6.0 / PI, 1.0) > 0.55) edge = 0.0;
  if (kind == 7) {
    c = mix(c, vec4(v_ring, 1.0), fill);
  } else {
    c = mix(c, vec4(u_fill, 1.0), fill);
    c = mix(c, vec4(u_stroke, 1.0), edge);
    // Tier ring: thicker for Tier 0 (ring color is the tier's).
    float width = flag(v_flags, 64.0) ? 0.22 : 0.12;
    float ring = 1.0 - smoothstep(0.0, aa * 1.5, abs(length(v_uv) - 1.35) - width);
    if (flag(v_flags, 1.0) && mod(ang * 10.0 / PI, 1.0) > 0.4) ring = 0.0; // stale: dotted
    if (flag(v_flags, 8.0) && mod(ang * 5.0 / PI, 1.0) > 0.7) ring = 0.0;  // conditional: dashed
    c = mix(c, vec4(v_ring, 1.0), ring);
  }
  if (flag(v_flags, 4.0) || flag(v_flags, 16.0)) {
    float halo = 1.0 - smoothstep(0.0, aa * 1.5, abs(length(v_uv) - 1.62) - (flag(v_flags, 4.0) ? 0.09 : 0.05));
    c = mix(c, vec4(u_focus, 1.0), halo);
  }
  float alpha = flag(v_flags, 2.0) ? u_dim : (flag(v_flags, 1.0) ? 0.6 : 1.0);
  if (c.a * alpha < 0.01) discard;
  color = vec4(c.rgb, c.a * alpha);
}`;

const edgeVS = `#version 300 es
in vec2 a_corner; // x: 0..1 along, y: -1..1 across
in vec2 a_from;
in vec2 a_to;
in vec3 a_color;
in float a_width;
in vec4 a_dash;
in float a_flags;
uniform vec3 u_cam;
uniform vec2 u_view;
out vec3 v_color;
out float v_t;
out vec4 v_dash;
out float v_flags;
out float v_along;
void main() {
  vec2 a = (a_from - u_cam.xy) * u_cam.z + u_view * 0.5;
  vec2 b = (a_to - u_cam.xy) * u_cam.z + u_view * 0.5;
  vec2 dir = b - a;
  float len = max(length(dir), 0.001);
  vec2 n = vec2(-dir.y, dir.x) / len;
  vec2 s = a + dir * a_corner.x + n * a_corner.y * a_width * 0.5;
  gl_Position = vec4(s / u_view * 2.0 - 1.0, 0.0, 1.0);
  gl_Position.y = -gl_Position.y;
  v_color = a_color;
  v_t = a_corner.x * len;
  v_dash = a_dash;
  v_flags = a_flags;
  v_along = a_corner.x;
}`;

const edgeFS = `#version 300 es
precision highp float;
in vec3 v_color;
in float v_t;
in vec4 v_dash;
in float v_flags;
in float v_along;
uniform float u_dim;
out vec4 color;
bool flag(float f, float bit) { return mod(floor(f / bit), 2.0) == 1.0; }
void main() {
  if (flag(v_flags, 4.0)) discard;
  float period = v_dash.x + v_dash.y + v_dash.z + v_dash.w;
  if (period > 0.0) {
    float m = mod(v_t, period);
    bool on = m < v_dash.x || (m >= v_dash.x + v_dash.y && m < v_dash.x + v_dash.y + v_dash.z);
    if (!on) discard;
  }
  // Direction: edges brighten towards their target.
  float alpha = mix(0.45, 1.0, v_along);
  if (flag(v_flags, 1.0)) alpha *= u_dim;
  if (flag(v_flags, 2.0)) alpha = 1.0;
  color = vec4(v_color, alpha);
}`;

function compile(gl: WebGL2RenderingContext, vs: string, fs: string): WebGLProgram {
  const make = (type: number, src: string): WebGLShader => {
    const s = gl.createShader(type);
    if (!s) throw new Error('createShader failed');
    gl.shaderSource(s, src);
    gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS))
      throw new Error(gl.getShaderInfoLog(s) ?? 'shader error');
    return s;
  };
  const p = gl.createProgram();
  gl.attachShader(p, make(gl.VERTEX_SHADER, vs));
  gl.attachShader(p, make(gl.FRAGMENT_SHADER, fs));
  gl.linkProgram(p);
  if (!gl.getProgramParameter(p, gl.LINK_STATUS))
    throw new Error(gl.getProgramInfoLog(p) ?? 'link error');
  return p;
}

function rgb(hex: string): [number, number, number] {
  const c = hexToRgb(hex);
  return [c[0], c[1], c[2]];
}

/** Parses an SVG dash array ("8 4", "none") into 4 floats. */
export function dashArray(s: string): [number, number, number, number] {
  if (s === 'none' || s.trim() === '') return [0, 0, 0, 0];
  const n = s.split(/\s+/).map(Number);
  const [a = 0, b = 0, c = 0, d = 0] = n.length === 2 ? [n[0], n[1], 0, 0] : n;
  return [a, b, c, d];
}

export class AtlasRenderer {
  private readonly gl: WebGL2RenderingContext;
  private readonly nodeProgram: WebGLProgram;
  private readonly edgeProgram: WebGLProgram;
  private readonly nodeVAO: WebGLVertexArrayObject;
  private readonly edgeVAO: WebGLVertexArrayObject;
  private nodeCount = 0;
  private edgeCount = 0;
  private readonly buffers: WebGLBuffer[] = [];

  /** Throws when WebGL2 is unavailable; callers fall back to the table. */
  constructor(private readonly canvas: HTMLCanvasElement) {
    const gl = canvas.getContext('webgl2', { antialias: true, premultipliedAlpha: false });
    if (!gl) throw new Error('WebGL2 is not available');
    this.gl = gl;
    this.nodeProgram = compile(gl, nodeVS, nodeFS);
    this.edgeProgram = compile(gl, edgeVS, edgeFS);
    this.nodeVAO = gl.createVertexArray();
    this.edgeVAO = gl.createVertexArray();
  }

  private buffer(data: Float32Array): WebGLBuffer {
    const gl = this.gl;
    const b = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, b);
    gl.bufferData(gl.ARRAY_BUFFER, data, gl.STATIC_DRAW);
    this.buffers.push(b);
    return b;
  }

  private attr(
    program: WebGLProgram,
    name: string,
    data: Float32Array,
    size: number,
    divisor: number,
  ): void {
    const gl = this.gl;
    const loc = gl.getAttribLocation(program, name);
    if (loc < 0) return;
    this.buffer(data);
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, size, gl.FLOAT, false, 0, 0);
    gl.vertexAttribDivisor(loc, divisor);
  }

  setData(nodes: NodeAttrs, edges: EdgeAttrs): void {
    const gl = this.gl;
    for (const b of this.buffers.splice(0)) gl.deleteBuffer(b);
    const n = nodes.x.length;
    const pos = new Float32Array(n * 2);
    const ring = new Float32Array(n * 3);
    for (let i = 0; i < n; i++) {
      pos[i * 2] = nodes.x[i] ?? 0;
      pos[i * 2 + 1] = nodes.y[i] ?? 0;
      ring.set(rgb(nodes.ring[i] ?? '#888888'), i * 3);
    }
    gl.bindVertexArray(this.nodeVAO);
    this.attr(this.nodeProgram, 'a_corner', new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), 2, 0);
    this.attr(this.nodeProgram, 'a_pos', pos, 2, 1);
    this.attr(this.nodeProgram, 'a_radius', nodes.radius, 1, 1);
    this.attr(this.nodeProgram, 'a_kind', nodes.kind, 1, 1);
    this.attr(this.nodeProgram, 'a_ring', ring, 3, 1);
    this.attr(this.nodeProgram, 'a_flags', Float32Array.from(nodes.flags), 1, 1);
    this.nodeCount = n;

    const m = edges.from.length;
    const from = new Float32Array(m * 2);
    const to = new Float32Array(m * 2);
    const color = new Float32Array(m * 3);
    for (let i = 0; i < m; i++) {
      const a = edges.from[i] ?? 0;
      const b = edges.to[i] ?? 0;
      from[i * 2] = nodes.x[a] ?? 0;
      from[i * 2 + 1] = nodes.y[a] ?? 0;
      to[i * 2] = nodes.x[b] ?? 0;
      to[i * 2 + 1] = nodes.y[b] ?? 0;
      color.set(rgb(edges.color[i] ?? '#888888'), i * 3);
    }
    gl.bindVertexArray(this.edgeVAO);
    this.attr(this.edgeProgram, 'a_corner', new Float32Array([0, -1, 1, -1, 0, 1, 1, 1]), 2, 0);
    this.attr(this.edgeProgram, 'a_from', from, 2, 1);
    this.attr(this.edgeProgram, 'a_to', to, 2, 1);
    this.attr(this.edgeProgram, 'a_color', color, 3, 1);
    this.attr(this.edgeProgram, 'a_width', edges.width, 1, 1);
    this.attr(this.edgeProgram, 'a_dash', edges.dash, 4, 1);
    this.attr(this.edgeProgram, 'a_flags', Float32Array.from(edges.flags), 1, 1);
    this.edgeCount = m;
    gl.bindVertexArray(null);
  }

  /** Updates only node and edge flags (hover, selection, filters). */
  setFlags(nodeFlags: Uint8Array, edgeFlags: Uint8Array, nodes: NodeAttrs, edges: EdgeAttrs): void {
    this.setData({ ...nodes, flags: nodeFlags }, { ...edges, flags: edgeFlags });
  }

  draw(cam: Camera, palette: Palette, dim: number, showGraph: boolean): void {
    const gl = this.gl;
    const dpr = window.devicePixelRatio || 1;
    const w = this.canvas.clientWidth;
    const h = this.canvas.clientHeight;
    if (this.canvas.width !== Math.round(w * dpr) || this.canvas.height !== Math.round(h * dpr)) {
      this.canvas.width = Math.round(w * dpr);
      this.canvas.height = Math.round(h * dpr);
    }
    gl.viewport(0, 0, this.canvas.width, this.canvas.height);
    const [br, bg, bb] = rgb(palette.bg);
    gl.clearColor(br, bg, bb, 1);
    gl.clear(gl.COLOR_BUFFER_BIT);
    if (!showGraph) return;
    gl.enable(gl.BLEND);
    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
    const camU = [cam.x, cam.y, cam.zoom] as const;
    gl.useProgram(this.edgeProgram);
    gl.uniform3f(gl.getUniformLocation(this.edgeProgram, 'u_cam'), ...camU);
    gl.uniform2f(gl.getUniformLocation(this.edgeProgram, 'u_view'), w, h);
    gl.uniform1f(gl.getUniformLocation(this.edgeProgram, 'u_dim'), dim);
    gl.bindVertexArray(this.edgeVAO);
    gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, 4, this.edgeCount);
    gl.useProgram(this.nodeProgram);
    gl.uniform3f(gl.getUniformLocation(this.nodeProgram, 'u_cam'), ...camU);
    gl.uniform2f(gl.getUniformLocation(this.nodeProgram, 'u_view'), w, h);
    gl.uniform3f(gl.getUniformLocation(this.nodeProgram, 'u_fill'), ...rgb(palette.fill));
    gl.uniform3f(gl.getUniformLocation(this.nodeProgram, 'u_stroke'), ...rgb(palette.stroke));
    gl.uniform3f(gl.getUniformLocation(this.nodeProgram, 'u_focus'), ...rgb(palette.focus));
    gl.uniform1f(gl.getUniformLocation(this.nodeProgram, 'u_dim'), dim);
    gl.bindVertexArray(this.nodeVAO);
    gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, 4, this.nodeCount);
    gl.bindVertexArray(null);
  }

  destroy(): void {
    const gl = this.gl;
    for (const b of this.buffers.splice(0)) gl.deleteBuffer(b);
    gl.deleteProgram(this.nodeProgram);
    gl.deleteProgram(this.edgeProgram);
  }
}
