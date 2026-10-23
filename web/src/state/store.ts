import { useSyncExternalStore } from 'react';

// A minimal external store (ADR 0016): state is a plain immutable object,
// updates replace it, React reads it through useSyncExternalStore.

export interface Store<S> {
  readonly get: () => S;
  readonly set: (update: (s: S) => S) => void;
  readonly subscribe: (listener: () => void) => () => void;
}

export function createStore<S>(initial: S): Store<S> {
  let state = initial;
  const listeners = new Set<() => void>();
  return {
    get: () => state,
    set: (update) => {
      const next = update(state);
      if (Object.is(next, state)) return;
      state = next;
      for (const l of [...listeners]) l();
    },
    subscribe: (listener) => {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
  };
}

/** Subscribes a component to a slice of the store. The selector must
 * return a stable value for unchanged input (use memo for derived data). */
export function useStore<S, T>(store: Store<S>, selector: (s: S) => T): T {
  return useSyncExternalStore(
    store.subscribe,
    () => selector(store.get()),
    () => selector(store.get()),
  );
}

/** Memoizes a function of one argument by reference (the last input only),
 * which is what selectors over an immutable store need. */
export function memo<A, R>(fn: (a: A) => R): (a: A) => R {
  let last: { a: A; r: R } | null = null;
  return (a: A) => {
    if (last && Object.is(last.a, a)) return last.r;
    const r = fn(a);
    last = { a, r };
    return r;
  };
}

/** Memoizes a function of two arguments by reference. */
export function memo2<A, B, R>(fn: (a: A, b: B) => R): (a: A, b: B) => R {
  let last: { a: A; b: B; r: R } | null = null;
  return (a: A, b: B) => {
    if (last && Object.is(last.a, a) && Object.is(last.b, b)) return last.r;
    const r = fn(a, b);
    last = { a, b, r };
    return r;
  };
}
