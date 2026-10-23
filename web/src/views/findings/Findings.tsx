import { useMemo, useState, type UIEvent } from 'react';
import { severities } from '../../design/tokens';
import { displayName } from '../../shell/names';
import { formatHash, to, type Filters } from '../../state/route';
import { Severity } from '../common';
import type { ViewProps } from '../registry';
import { filterFindings, subjectName, toCSV, windowRange, type SortKey } from './model';

const rowHeight = 56;

function download(name: string, text: string, type: string): void {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export function Findings({ ix, route, pseudonyms, update }: ViewProps) {
  const [sort, setSort] = useState<SortKey>('severity');
  const [scroll, setScroll] = useState(0);
  const [viewport, setViewport] = useState(640);
  const f = route.filters;
  const rows = useMemo(() => filterFindings(ix, f, sort), [ix, f, sort]);
  const [first, last] = windowRange(scroll, viewport, rowHeight, rows.length);
  const setFilters = (patch: Partial<Filters>): void => {
    update((r) => ({ ...r, filters: { ...r.filters, ...patch } }));
  };
  const toggle = (list: readonly string[], v: string): string[] =>
    list.includes(v) ? list.filter((x) => x !== v) : [...list, v];
  const ruleIds = useMemo(
    () => [...new Set(ix.analysis.findings.map((x) => x.rule_id))].sort(),
    [ix],
  );
  const header = (key: SortKey, label: string) => (
    <th scope="col" aria-sort={sort === key ? 'ascending' : 'none'}>
      <button
        type="button"
        className="th-button"
        onClick={() => {
          setSort(key);
        }}
      >
        {label}
      </button>
    </th>
  );
  const subject = (id: string | null, fallback: string): string => {
    const n = id ? ix.nodes.get(id) : undefined;
    return n ? displayName(n, pseudonyms) : pseudonyms ? '—' : fallback;
  };
  return (
    <div className="findings">
      <h1 className="view__title">Findings</h1>
      <form
        className="filters"
        aria-label="Filters"
        onSubmit={(e) => {
          e.preventDefault();
        }}
      >
        <fieldset className="filters__group">
          <legend>Severity</legend>
          {severities.map((s) => (
            <label key={s}>
              <input
                type="checkbox"
                checked={f.severities.includes(s)}
                onChange={() => {
                  setFilters({ severities: toggle(f.severities, s) });
                }}
              />{' '}
              {s}
            </label>
          ))}
        </fieldset>
        <label className="filters__field">
          Rule{' '}
          <select
            value={f.rules[0] ?? ''}
            onChange={(e) => {
              setFilters({ rules: e.target.value ? [e.target.value] : [] });
            }}
          >
            <option value="">All rules</option>
            {ruleIds.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </label>
        <label className="filters__field">
          Text{' '}
          <input
            type="search"
            value={f.text}
            maxLength={200}
            onChange={(e) => {
              setFilters({ text: e.target.value });
            }}
          />
        </label>
        <label className="filters__field">
          <input
            type="checkbox"
            checked={f.suppressed}
            onChange={() => {
              setFilters({ suppressed: !f.suppressed });
            }}
          />{' '}
          Suppressed only
        </label>
        <button
          type="button"
          className="button"
          disabled={pseudonyms}
          title={pseudonyms ? 'Turn pseudonyms off to export' : undefined}
          onClick={() => {
            download('escalint-findings.csv', toCSV(ix, rows), 'text/csv');
          }}
        >
          Export CSV
        </button>
      </form>
      <p className="muted" aria-live="polite">
        {rows.length} finding(s)
      </p>
      <div
        className="vtable"
        role="region"
        aria-label="Findings table"
        // Scrollable regions must be keyboard-focusable (WCAG 2.1.1).
        // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
        tabIndex={0}
        onScroll={(e: UIEvent<HTMLDivElement>) => {
          setScroll(e.currentTarget.scrollTop);
          setViewport(e.currentTarget.clientHeight);
        }}
      >
        <table className="table" aria-rowcount={rows.length + 1}>
          <thead>
            <tr aria-rowindex={1}>
              {header('severity', 'Severity')}
              {header('rule', 'Rule')}
              {header('subject', 'Subject')}
              <th scope="col">Finding</th>
              <th scope="col">Path</th>
            </tr>
          </thead>
          <tbody>
            {first > 0 && (
              <tr aria-hidden="true">
                <td colSpan={5} style={{ height: first * rowHeight }} />
              </tr>
            )}
            {rows.slice(first, last).map((x, i) => (
              <tr
                key={x.id}
                aria-rowindex={first + i + 2}
                aria-selected={route.sel === x.id}
                className={route.sel === x.id ? 'row row--selected' : 'row'}
                onClick={() => {
                  update((r) => ({ ...r, sel: x.id }));
                }}
              >
                <td>
                  <Severity value={x.severity} />
                  {x.suppressed && <span className="badge">suppressed</span>}
                  {x.latent && <span className="badge">latent</span>}
                </td>
                <td className="mono">{x.rule_id}</td>
                <td className="cell-wrap">{subject(x.node_id, subjectName(ix, x))}</td>
                <td className="cell-wrap">
                  <button
                    type="button"
                    className="link-button"
                    onClick={() => {
                      update((r) => ({ ...r, sel: x.id }));
                    }}
                  >
                    {x.title}
                  </button>
                </td>
                <td>
                  {x.path_id ? (
                    <a href={formatHash(to('path', x.path_id))}>trace</a>
                  ) : (
                    <span className="muted">—</span>
                  )}
                </td>
              </tr>
            ))}
            {last < rows.length && (
              <tr aria-hidden="true">
                <td colSpan={5} style={{ height: (rows.length - last) * rowHeight }} />
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
