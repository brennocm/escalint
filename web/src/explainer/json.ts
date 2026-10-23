// A small JSON tokenizer and pretty-printer for the policy explainer. It
// never evaluates or injects markup: tokens become text nodes. Lines know
// which Statement element they belong to, so the deciding statements can
// be highlighted.

export type TokenKind =
  'brace' | 'bracket' | 'colon' | 'comma' | 'key' | 'string' | 'number' | 'literal';

export interface Token {
  readonly kind: TokenKind;
  readonly text: string;
}

export class JSONSyntaxError extends Error {
  override readonly name = 'JSONSyntaxError';
}

const literal = /^(true|false|null)/;
const number = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/;

/** Splits JSON text into tokens; object keys are told apart from values. */
export function tokenize(text: string): Token[] {
  const out: Token[] = [];
  const stack: ('{' | '[')[] = [];
  let expectKey = false;
  let i = 0;
  while (i < text.length) {
    const c = text.charAt(i);
    if (c === ' ' || c === '\n' || c === '\r' || c === '\t') {
      i++;
      continue;
    }
    if (c === '{' || c === '[') {
      out.push({ kind: c === '{' ? 'brace' : 'bracket', text: c });
      stack.push(c);
      expectKey = c === '{';
      i++;
      continue;
    }
    if (c === '}' || c === ']') {
      const open = stack.pop();
      if ((c === '}' && open !== '{') || (c === ']' && open !== '['))
        throw new JSONSyntaxError(`unexpected ${c} at ${String(i)}`);
      out.push({ kind: c === '}' ? 'brace' : 'bracket', text: c });
      expectKey = false;
      i++;
      continue;
    }
    if (c === ':') {
      out.push({ kind: 'colon', text: ':' });
      expectKey = false;
      i++;
      continue;
    }
    if (c === ',') {
      out.push({ kind: 'comma', text: ',' });
      expectKey = stack[stack.length - 1] === '{';
      i++;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text.charAt(j) !== '"') j += text.charAt(j) === '\\' ? 2 : 1;
      if (j >= text.length) throw new JSONSyntaxError(`unterminated string at ${String(i)}`);
      out.push({ kind: expectKey ? 'key' : 'string', text: text.slice(i, j + 1) });
      i = j + 1;
      continue;
    }
    const rest = text.slice(i);
    const m = number.exec(rest) ?? literal.exec(rest);
    if (!m) throw new JSONSyntaxError(`unexpected character at ${String(i)}`);
    out.push({ kind: /^[tfn]/.test(m[0]) ? 'literal' : 'number', text: m[0] });
    i += m[0].length;
  }
  if (stack.length) throw new JSONSyntaxError('unexpected end of input');
  return out;
}

export interface Line {
  readonly indent: number;
  readonly tokens: readonly Token[];
  /** Index in the top-level Statement array, or -1. */
  readonly statement: number;
}

/** Pretty-prints tokens, one value per line, tagging Statement elements. */
export function pretty(tokens: readonly Token[]): Line[] {
  const lines: Line[] = [];
  let current: Token[] = [];
  let indent = 0;
  let lineIndent = 0;
  let lineStatement = -1;
  // Context: for each open container, its key in the parent and element index.
  const stack: { key: string | null; index: number; kind: '{' | '[' }[] = [];
  let pendingKey: string | null = null;
  const statementIndex = (): number => {
    // Inside the top-level object's "Statement" array: stack[1] is that array.
    const top = stack[1];
    return stack.length >= 2 &&
      stack[0]?.kind === '{' &&
      top?.kind === '[' &&
      top.key === '"Statement"'
      ? top.index
      : -1;
  };
  const flush = (): void => {
    if (current.length)
      lines.push({ indent: lineIndent, tokens: current, statement: lineStatement });
    current = [];
  };
  const start = (): void => {
    if (current.length === 0) {
      lineIndent = indent;
      lineStatement = statementIndex();
    }
  };
  for (const t of tokens) {
    if (t.text === '{' || t.text === '[') {
      start();
      current.push(t);
      stack.push({ key: pendingKey, index: 0, kind: t.text });
      pendingKey = null;
      flush();
      indent++;
    } else if (t.text === '}' || t.text === ']') {
      flush();
      indent--;
      stack.pop();
      start();
      current.push(t);
    } else if (t.kind === 'comma') {
      current.push(t);
      flush();
      const top = stack[stack.length - 1];
      if (top?.kind === '[') top.index++;
    } else {
      start();
      if (t.kind === 'key') pendingKey = t.text;
      current.push(t);
    }
  }
  flush();
  // Closing lines of a statement belong to it; the "Statement" array's own
  // brackets do not.
  return lines;
}
