import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { buildIndexes } from '../data/indexes';
import { vulnerable } from '../data/fixtures';
import { explain } from './explain';
import { JSONSyntaxError, pretty, tokenize } from './json';
import { PolicyExplainer } from './PolicyExplainer';

const ix = buildIndexes(vulnerable);

describe('tokenize', () => {
  it('tells keys from values', () => {
    const t = tokenize('{"a": [1, -2.5e3, "x\\"y", true, null], "b": {}}');
    expect(t.map((x) => x.kind)).toEqual([
      'brace',
      'key',
      'colon',
      'bracket',
      'number',
      'comma',
      'number',
      'comma',
      'string',
      'comma',
      'literal',
      'comma',
      'literal',
      'bracket',
      'comma',
      'key',
      'colon',
      'brace',
      'brace',
      'brace',
    ]);
  });
  it.each(['{"a":}x', '{"a":"unterminated}', '[1}', '{', 'nope'])('rejects %s', (s) => {
    expect(() => tokenize(s)).toThrow(JSONSyntaxError);
  });
});

describe('pretty', () => {
  it('tags statement lines', () => {
    const lines = pretty(
      tokenize(
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["a","b"]},{"Effect":"Deny"}]}',
      ),
    );
    const text = lines
      .map((l) => '  '.repeat(l.indent) + l.tokens.map((t) => t.text).join(''))
      .join('\n');
    expect(text).toContain('  "Statement":[');
    const s1 = lines
      .filter((l) => l.statement === 1)
      .map((l) => l.tokens.map((t) => t.text).join(''));
    expect(s1).toEqual(['{', '"Effect":"Deny"', '}']);
    expect(lines.filter((l) => l.statement === 0).length).toBeGreaterThan(3);
    expect(lines[0]?.statement).toBe(-1);
  });
});

describe('explain', () => {
  it('states which statement allows each action', () => {
    const e = vulnerable.edges.find((x) => x.rule_ids.includes('EL-PE-022'));
    if (!e) throw new Error('fixture');
    const lines = explain(ix, e);
    expect(lines[0]).toMatch(/^iam:PassRole: identity policy: allowed by statement #\d+ of /);
    expect(lines.join(' ')).toContain('No organization data');
  });
  it('renders the deciding statement highlighted', () => {
    const e = vulnerable.edges.find((x) => x.evidence.length > 0 && x.rule_ids.length > 0);
    if (!e) throw new Error('fixture');
    const { container } = render(<PolicyExplainer ix={ix} edge={e} pseudonyms={false} />);
    expect(screen.getAllByLabelText('Policy document').length).toBeGreaterThan(0);
    expect(container.querySelectorAll('.json__line--hit').length).toBeGreaterThan(0);
  });
  it('hides details with pseudonyms', () => {
    const e = vulnerable.edges[0];
    if (!e) throw new Error('fixture');
    render(<PolicyExplainer ix={ix} edge={e} pseudonyms={true} />);
    expect(screen.getByText(/hidden while pseudonyms/)).toBeTruthy();
  });
});
