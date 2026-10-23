import type { ReactNode } from 'react';

export function Loading({ what = 'analysis' }: { readonly what?: string }) {
  return (
    <div className="state state--loading" role="status" aria-live="polite">
      <div className="skeleton skeleton--title" />
      <div className="skeleton" />
      <div className="skeleton" />
      <span className="visually-hidden">Loading {what}…</span>
    </div>
  );
}

export function ErrorState({ message }: { readonly message: string }) {
  return (
    <div className="state state--error" role="alert">
      <h2>Could not open the analysis</h2>
      <p>{message}</p>
      <p className="muted">
        Produce one with <code>escalint analyze snapshot.json -o analysis.json</code>, or open it
        with <code>escalint serve</code>.
      </p>
    </div>
  );
}

export function Empty({
  title,
  children,
}: {
  readonly title: string;
  readonly children?: ReactNode;
}) {
  return (
    <div className="state state--empty">
      <h2>{title}</h2>
      {children}
    </div>
  );
}
