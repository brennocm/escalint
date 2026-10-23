import { useMemo } from 'react';
import type { Edge } from '../contract/analysis';
import type { Indexes } from '../data/indexes';
import { explain } from './explain';
import { pretty, tokenize, type Line } from './json';

function JsonView({
  text,
  highlight,
}: {
  readonly text: string;
  readonly highlight: ReadonlySet<number>;
}) {
  const lines: Line[] = useMemo(() => {
    try {
      return pretty(tokenize(text));
    } catch {
      return [{ indent: 0, tokens: [{ kind: 'string', text }], statement: -1 }];
    }
  }, [text]);
  return (
    // A scrollable region must be keyboard-focusable (WCAG 2.1.1).
    // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
    <pre className="json" tabIndex={0} aria-label="Policy document">
      {lines.map((l, i) => (
        <span
          key={i}
          className={highlight.has(l.statement) ? 'json__line json__line--hit' : 'json__line'}
        >
          {'  '.repeat(l.indent)}
          {l.tokens.map((t, j) => (
            <span key={j} className={`json__${t.kind}`}>
              {t.text}
              {t.kind === 'colon' ? ' ' : ''}
            </span>
          ))}
          {'\n'}
        </span>
      ))}
    </pre>
  );
}

/** Why an edge exists: the trace in words and the deciding statements. */
export function PolicyExplainer({
  ix,
  edge,
  pseudonyms,
}: {
  readonly ix: Indexes;
  readonly edge: Edge;
  readonly pseudonyms: boolean;
}) {
  const docs = useMemo(() => new Map(ix.analysis.policies.map((p) => [p.source, p])), [ix]);
  const sources = [...new Set(edge.evidence.map((e) => e.policy))];
  return (
    <section className="explainer" aria-label="Policy explainer">
      <h2 className="section__title">Why this edge exists</h2>
      {pseudonyms ? (
        <p className="muted">Policy details are hidden while pseudonyms are on.</p>
      ) : (
        <>
          <ul className="explainer__trace">
            {explain(ix, edge).map((l, i) => (
              <li key={i}>{l}</li>
            ))}
          </ul>
          {sources.map((src) => {
            const doc = docs.get(src);
            const hits = new Set(
              edge.evidence.filter((e) => e.policy === src).map((e) => e.statement_index),
            );
            return (
              <div key={src} className="explainer__policy">
                <h3 className="mono">{doc ? `${doc.name} · ${doc.type}` : src}</h3>
                {doc ? (
                  <JsonView text={JSON.stringify(doc.document)} highlight={hits} />
                ) : (
                  <p className="muted">
                    {ix.analysis.snapshot.redacted
                      ? 'Documents are omitted from redacted analyses.'
                      : 'Document not available (synthetic or not collected).'}
                  </p>
                )}
              </div>
            );
          })}
        </>
      )}
    </section>
  );
}
