import { demoDatasets } from '../data/load';

/** Shown only in the public demo build: the data is synthetic. */
export function DemoBanner() {
  const current = new URLSearchParams(window.location.search).get('dataset') ?? demoDatasets[0].id;
  return (
    <div className="notice notice--demo" role="note">
      <strong>Demo with synthetic data.</strong> No real account is shown; account IDs are fake.
      <label className="filters__field">
        Dataset{' '}
        <select
          value={current}
          onChange={(e) => {
            const url = new URL(window.location.href);
            url.searchParams.set('dataset', e.target.value);
            url.hash = '#/';
            window.location.assign(url.toString());
          }}
        >
          {demoDatasets.map((d) => (
            <option key={d.id} value={d.id}>
              {d.label}
            </option>
          ))}
        </select>
      </label>
    </div>
  );
}
